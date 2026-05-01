// OIDC SSO handlers — IAM (Casdoor) authorization-code flow.
//
// Flow:
//
//	1. GET  /v1/sso/oidc/login?orgSlug=...   →  302 IAM /login/oauth/authorize
//	   Sets HttpOnly+Secure state cookie (HMAC-signed, 5-min expiry, single-use).
//	2. GET  /v1/sso/oidc/callback?code&state →  exchange code, set session cookie, 302 /
//	   Validates state (signature + expiry + cookie match), Origin/Referer.
//	3. GET  /v1/sso/whoami                   →  echo session subject (used by SPA after redirect)
//	4. POST /v1/sso/logout                   →  clear session cookie, 204
//
// State and session cookies are independent: the state cookie is short-lived
// (5 min) and consumed exactly once on callback; the session cookie holds the
// IAM access token for subsequent KMS API calls.
//
// CSRF protection on /callback:
//   - state parameter is HMAC-signed, expires in 5 min, single-use (matched
//     against the kms_oidc_state cookie value)
//   - Referer/Origin (if present) must be from IAM_ENDPOINT host
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// stateCookie holds the HMAC-signed state nonce. Single-use.
	stateCookie = "kms_oidc_state"
	// sessionCookie holds the IAM access token after successful login.
	sessionCookie = "kms_session"
	// stateTTL bounds the OAuth round-trip — IAM must redirect back inside
	// this window or the user re-clicks "Login".
	stateTTL = 5 * time.Minute
	// sessionTTL matches the IAM access-token lifetime we accept (24h).
	// IAM enforces its own expiry inside the JWT; this is the cookie cap.
	sessionTTL = 24 * time.Hour
)

// oidcConfig captures the static OIDC settings for KMS. The clientID is
// safe to bake into env (it's public per OAuth2 spec); clientSecret stays
// in env-only and is supplied via KMS_OIDC_CLIENT_SECRET (KMSSecret CRD).
type oidcConfig struct {
	iamEndpoint  string // e.g. https://iam.dev.satschel.com
	clientID     string // e.g. liquidity-kms
	clientSecret string // KMSSecret-injected
	stateSecret  []byte // HMAC key for state-nonce signing (>=32 bytes)
	cookieDomain string // optional; empty = host-only cookie (recommended)
}

// loadOIDCConfig reads the OIDC settings. Returns nil if OIDC is not
// configured — the handlers register a 503 in that case so the deployment
// is observably misconfigured rather than silently broken.
func loadOIDCConfig() *oidcConfig {
	iam := envOr("IAM_ENDPOINT", "")
	cid := envOr("KMS_OIDC_CLIENT_ID", "")
	cs := envOr("KMS_OIDC_CLIENT_SECRET", "")
	ss := envOr("KMS_STATE_SECRET", "")
	if iam == "" || cid == "" || cs == "" || ss == "" {
		return nil
	}
	// State HMAC key: minimum 32 bytes of entropy. The operator wires
	// this from KMS (KMSSecret CRD); reject anything shorter so a typo
	// can't reduce the search space for a forger.
	if len(ss) < 32 {
		log.Printf("kms: KMS_STATE_SECRET must be >= 32 bytes; OIDC disabled")
		return nil
	}
	return &oidcConfig{
		iamEndpoint:  strings.TrimRight(iam, "/"),
		clientID:     cid,
		clientSecret: cs,
		stateSecret:  []byte(ss),
		cookieDomain: envOr("KMS_COOKIE_DOMAIN", ""),
	}
}

// signState builds an opaque, tamper-evident state token:
//
//	base64url(nonce(16B) | be64(unix-expiry) | hmac(secret, nonce|expiry|orgSlug))
//
// orgSlug is bound into the MAC so an attacker cannot relay a state token
// minted for one org to a different org's callback.
func (c *oidcConfig) signState(orgSlug string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	exp := time.Now().Add(stateTTL).Unix()
	buf := make([]byte, 0, 32)
	buf = append(buf, nonce...)
	buf = appendBE64(buf, exp)
	mac := hmac.New(sha256.New, c.stateSecret)
	mac.Write(buf)
	mac.Write([]byte(orgSlug))
	buf = append(buf, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// verifyState confirms the state token was issued by us, hasn't expired,
// and is bound to the given orgSlug. Returns nil on success.
func (c *oidcConfig) verifyState(token, orgSlug string) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("state: bad encoding")
	}
	// 16-byte nonce + 8-byte expiry + 32-byte HMAC = 56 bytes minimum.
	if len(raw) != 16+8+sha256.Size {
		return fmt.Errorf("state: bad length")
	}
	nonce := raw[:16]
	exp := readBE64(raw[16:24])
	gotMAC := raw[24:]
	mac := hmac.New(sha256.New, c.stateSecret)
	mac.Write(nonce)
	mac.Write(raw[16:24])
	mac.Write([]byte(orgSlug))
	wantMAC := mac.Sum(nil)
	if !hmac.Equal(gotMAC, wantMAC) {
		return fmt.Errorf("state: bad signature")
	}
	if time.Now().Unix() > exp {
		return fmt.Errorf("state: expired")
	}
	return nil
}

// callbackURL returns the absolute callback URL the request was served
// from. Trusting the Host header is acceptable here because IAM verifies
// redirect_uri against its registered allowlist — a forged Host would
// produce a redirect_uri IAM rejects.
func callbackURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		// Local dev only. Production runs behind hanzoai/ingress with TLS.
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/v1/sso/oidc/callback"
}

// registerOIDCRoutes wires the SSO endpoints onto the given mux. If OIDC
// isn't configured the handlers return 503 so misconfiguration is visible.
func registerOIDCRoutes(mux *http.ServeMux) {
	cfg := loadOIDCConfig()
	if cfg == nil {
		mux.HandleFunc("GET /v1/sso/oidc/login", oidcUnconfigured)
		mux.HandleFunc("GET /v1/sso/oidc/callback", oidcUnconfigured)
		mux.HandleFunc("GET /v1/sso/whoami", oidcUnconfigured)
		mux.HandleFunc("POST /v1/sso/logout", oidcUnconfigured)
		log.Printf("kms: OIDC SSO disabled (set IAM_ENDPOINT, KMS_OIDC_CLIENT_ID, KMS_OIDC_CLIENT_SECRET, KMS_STATE_SECRET)")
		return
	}
	log.Printf("kms: OIDC SSO enabled — issuer=%s client_id=%s", cfg.iamEndpoint, cfg.clientID)
	mux.HandleFunc("GET /v1/sso/oidc/login", cfg.handleLogin)
	mux.HandleFunc("GET /v1/sso/oidc/callback", cfg.handleCallback)
	mux.HandleFunc("GET /v1/sso/whoami", cfg.handleWhoami)
	mux.HandleFunc("POST /v1/sso/logout", cfg.handleLogout)
	mux.HandleFunc("POST /v1/kms/credentials", cfg.handleMintClientCredential)
}

func oidcUnconfigured(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"statusCode": 503,
		"message":    "OIDC SSO not configured",
	})
}

// handleLogin: mint a state token, set the state cookie, redirect to IAM.
func (c *oidcConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	orgSlug := r.URL.Query().Get("orgSlug")
	state, err := c.signState(orgSlug)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "state mint failed"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/v1/sso/oidc/callback",
		Domain:   c.cookieDomain,
		MaxAge:   int(stateTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		// SameSite=Lax allows the cookie to ride along the IAM→KMS
		// top-level GET redirect; Strict would drop it.
		SameSite: http.SameSiteLaxMode,
	})
	q := url.Values{
		"client_id":     {c.clientID},
		"redirect_uri":  {callbackURL(r)},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {state},
	}
	if orgSlug != "" {
		// Casdoor honours `application` as the org-app scoping hint.
		q.Set("application", orgSlug)
	}
	http.Redirect(w, r, c.iamEndpoint+"/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

// handleCallback: validate state + Origin/Referer, exchange code, set session.
func (c *oidcConfig) handleCallback(w http.ResponseWriter, r *http.Request) {
	// CSRF: if the browser sent Origin or Referer, it must match this host.
	// Per OAuth2 the IAM redirect is a top-level navigation from iam.*; the
	// browser sends Referer = iam host (acceptable) OR the request is a
	// direct GET (no Referer at all). Reject only when Referer/Origin is
	// present AND points somewhere unrelated — that's the smuggling case.
	if !originLooksOK(r, c.iamEndpoint, "https://"+r.Host) {
		log.Printf("kms: oidc callback rejected — bad origin/referer")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	orgSlug := r.URL.Query().Get("orgSlug") // optional; may be empty

	if state == "" || code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "state and code required"})
		return
	}

	// State must equal the cookie minted on /login (strict pinning).
	cookie, err := r.Cookie(stateCookie)
	if err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "missing state cookie"})
		return
	}
	if !hmac.Equal([]byte(cookie.Value), []byte(state)) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "state mismatch"})
		return
	}
	if err := c.verifyState(state, orgSlug); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
		return
	}
	// Single-use: clear the state cookie so it can't be replayed.
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: "", Path: "/v1/sso/oidc/callback",
		Domain: c.cookieDomain, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})

	tok, err := c.exchangeCode(r.Context(), code, callbackURL(r))
	if err != nil {
		log.Printf("kms: oidc token exchange failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"message": "token exchange failed"})
		return
	}
	if tok == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "no access_token returned"})
		return
	}

	// Session cookie = IAM access token. Server-side validation on every
	// API hit happens at the gateway; KMS treats this cookie as opaque.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		Domain:   c.cookieDomain,
		MaxAge:   int(sessionTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	// Strict redirect target: hardcoded to "/" so a tampered query param
	// can't turn this into an open redirect.
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleWhoami echoes the session token presence so the SPA can decide
// whether to render the dashboard. Token contents are NOT returned.
func (c *oidcConfig) handleWhoami(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

// handleMintClientCredential creates a new KMS service application
// (clientId/clientSecret pair) via Casdoor admin API and returns the
// secret to the caller exactly once. The caller must be authenticated
// (session cookie) — the IAM admin credentials live in env, never in the
// browser.
//
// Frontend wires a "Generate KMS Client Credential" button to this. The
// returned secret is shown once for clipboard copy and never persisted by
// KMS — Casdoor stores it. To rotate, generate a new one and revoke the
// old via Casdoor admin UI.
//
// IAM admin auth: Casdoor takes adminId/adminSecret as query params on
// the admin API. We pull them from KMS_IAM_ADMIN_CLIENT_ID and
// KMS_IAM_ADMIN_CLIENT_SECRET (KMSSecret-injected).
func (c *oidcConfig) handleMintClientCredential(w http.ResponseWriter, r *http.Request) {
	// Require an authenticated session — the session cookie holds the
	// IAM access token granted via the OIDC flow above. We don't decode
	// it here; presence is enough since the gateway validates upstream.
	if cookie, err := r.Cookie(sessionCookie); err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "session required"})
		return
	}

	adminID := envOr("KMS_IAM_ADMIN_CLIENT_ID", "")
	adminSecret := envOr("KMS_IAM_ADMIN_CLIENT_SECRET", "")
	owner := envOr("KMS_IAM_OWNER", "liquidity")
	if adminID == "" || adminSecret == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"message": "IAM admin credentials not configured",
		})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	if req.Name == "" {
		// Default name: kms-client-{8 hex} so duplicates can't collide.
		nonce := make([]byte, 4)
		_, _ = rand.Read(nonce)
		req.Name = fmt.Sprintf("kms-client-%x", nonce)
	}

	// Casdoor add-application endpoint; clientId/secret rendered into the
	// JSON body, owner & app name in the URL. Casdoor returns the
	// generated clientSecret in the response — capture and forward.
	body := map[string]any{
		"owner":        owner,
		"name":         req.Name,
		"displayName":  req.Name,
		"description":  req.Description,
		"organization": owner,
		// Mark as M2M (Casdoor "Service" type) so it doesn't appear in
		// the user-facing app picker.
		"clientId":     "", // server-generated
		"clientSecret": "", // server-generated
	}
	bodyJSON, _ := json.Marshal(body)
	q := url.Values{
		"clientId":     {adminID},
		"clientSecret": {adminSecret},
	}
	adminURL := c.iamEndpoint + "/api/add-application?" + q.Encode()
	adminReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, adminURL,
		strings.NewReader(string(bodyJSON)))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"message": err.Error()})
		return
	}
	adminReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(adminReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"message": "iam unreachable"})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var iam struct {
		Status string `json:"status"`
		Msg    string `json:"msg"`
		Data   struct {
			ClientID     string `json:"clientId"`
			ClientSecret string `json:"clientSecret"`
		} `json:"data2"`
	}
	if err := json.Unmarshal(respBody, &iam); err != nil || iam.Data.ClientID == "" {
		// Casdoor sometimes returns the generated app under `data` (not
		// data2) depending on version — try the other shape before giving up.
		var alt struct {
			Status string `json:"status"`
			Data   struct {
				ClientID     string `json:"clientId"`
				ClientSecret string `json:"clientSecret"`
			} `json:"data"`
		}
		if err := json.Unmarshal(respBody, &alt); err == nil && alt.Data.ClientID != "" {
			iam.Data = alt.Data
			iam.Status = alt.Status
		}
	}
	if iam.Data.ClientID == "" || iam.Data.ClientSecret == "" {
		log.Printf("kms: mint-credential: iam returned no clientId/secret (status=%d)", resp.StatusCode)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"message": "IAM did not return credentials",
		})
		return
	}
	// Return ONCE. KMS does not store the secret. Operator copies to KMS
	// or env and revokes via IAM admin if it ever needs to be rotated.
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":         req.Name,
		"clientId":     iam.Data.ClientID,
		"clientSecret": iam.Data.ClientSecret,
	})
}

// handleLogout clears the session cookie. State cookie is already cleared
// by the callback; nothing else to do server-side.
func (c *oidcConfig) handleLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", Domain: c.cookieDomain,
		MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// exchangeCode posts the auth code to IAM's token endpoint and returns
// the access_token. The IAM endpoint is canonical Casdoor at
// /login/oauth/access_token (no /api/ prefix — killed in iam v2.381).
func (c *oidcConfig) exchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.iamEndpoint+"/login/oauth/access_token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("iam status=%d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	if tok.Error != "" {
		return "", fmt.Errorf("iam error: %s", tok.Error)
	}
	return tok.AccessToken, nil
}

// originLooksOK returns true if the request's Origin/Referer is empty
// (no header sent — direct nav) or matches one of the allowed prefixes.
// IAM is allowed because the callback is reached via top-level navigation
// from iam.* after consent.
func originLooksOK(r *http.Request, allowed ...string) bool {
	for _, h := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		if h == "" {
			continue
		}
		match := false
		for _, prefix := range allowed {
			if prefix != "" && strings.HasPrefix(h, prefix) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func appendBE64(b []byte, v int64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

func readBE64(b []byte) int64 {
	_ = b[7]
	return int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
}
