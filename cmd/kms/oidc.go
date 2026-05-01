// OIDC SSO handlers — IAM (Casdoor) authorization-code flow.
//
// Flow:
//
//	1. GET  /v1/sso/oidc/login?orgSlug=...   →  302 IAM /login/oauth/authorize
//	   Sets HttpOnly+Secure state cookie (HMAC-signed, 5-min expiry, single-use).
//	2. GET  /v1/sso/oidc/callback?code&state →  exchange code, set session cookie, 302 /
//	   Validates state (signature + expiry + cookie match + server-side nonce
//	   blacklist), Origin/Referer (parsed-Host equality, no prefix extension).
//	3. GET  /v1/sso/whoami                   →  echo session subject (used by SPA after redirect)
//	4. POST /v1/sso/logout                   →  clear session cookie, 204
//	5. POST /v1/kms/credentials              →  mint M2M client (kms-admin role + JWKS-validated session required)
//
// State and session cookies are independent: the state cookie is short-lived
// (5 min) and consumed exactly once on callback; the session cookie holds the
// IAM access token for subsequent KMS API calls.
//
// CSRF protection on /callback:
//   - state parameter is HMAC-signed, expires in 5 min, single-use (matched
//     against the kms_oidc_state cookie value AND a server-side nonce LRU
//     so a replica fleet can't double-redeem)
//   - Referer/Origin (if present) must be from IAM_ENDPOINT or this Host —
//     compared by parsed URL.Host equality, not prefix.
//
// Mint authorization (POST /v1/kms/credentials):
//   - Session JWT validated against IAM JWKS (sig, iss, aud, exp, owner)
//   - Caller must have `kms-admin` or `superadmin` in `roles` claim
//   - Per-subject rate limit: 5 mints / hour
//   - Audited: subject + name + outcome
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

	// mintRateLimit caps mint-credential requests per subject per window.
	mintRateLimit  = 5
	mintRateWindow = time.Hour

	// Roles permitted to mint M2M client credentials.
	roleKMSAdmin   = "kms-admin"
	roleSuperadmin = "superadmin"
)

// oidcConfig captures the static OIDC settings for KMS. The clientID is
// safe to bake into env (it's public per OAuth2 spec); clientSecret stays
// in env-only and is supplied via KMS_OIDC_CLIENT_SECRET (KMSSecret CRD).
type oidcConfig struct {
	iamEndpoint  string // e.g. https://iam.dev.satschel.com
	iamHost      string // parsed Host of iamEndpoint (for origin comparisons)
	clientID     string // e.g. liquidity-kms
	clientSecret string // KMSSecret-injected
	stateSecret  []byte // HMAC key for state-nonce signing (>=32 bytes)
	owner        string // KMS_IAM_OWNER — required JWT `owner` claim value
	cookieDomain string // optional; empty = host-only cookie (recommended)

	// Server-side single-use nonce blacklist. Replicated boxes share state
	// only via cookie+HMAC; this LRU prevents intra-replica replay before
	// the cookie clear lands on the client.
	nonces *nonceLRU

	// Per-subject mint rate limiter.
	mintLimiter *rateLimiter

	// JWT validator for session tokens (mint-credential gate).
	jwtValidator *sessionJWTValidator
}

// loadOIDCConfig reads the OIDC settings. Returns nil if OIDC is not
// configured — the handlers register a 503 in that case so the deployment
// is observably misconfigured rather than silently broken.
func loadOIDCConfig() *oidcConfig {
	iam := envOr("IAM_ENDPOINT", "")
	cid := envOr("KMS_OIDC_CLIENT_ID", "")
	cs := envOr("KMS_OIDC_CLIENT_SECRET", "")
	ss := envOr("KMS_STATE_SECRET", "")
	owner := envOr("KMS_IAM_OWNER", "liquidity")
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
	cookieDomain := envOr("KMS_COOKIE_DOMAIN", "")
	// Reject leading-dot wildcard cookie domains. Setting Domain=.foo.com
	// makes the session cookie visible to every subdomain — leakage we don't
	// want. Operator must use host-only (the empty default) or an exact host.
	if strings.HasPrefix(cookieDomain, ".") {
		log.Printf("kms: KMS_COOKIE_DOMAIN=%q starts with '.' (wildcard); OIDC disabled — set host-only or exact host", cookieDomain)
		return nil
	}
	iamURL, err := url.Parse(strings.TrimRight(iam, "/"))
	if err != nil || iamURL.Host == "" {
		log.Printf("kms: IAM_ENDPOINT %q failed to parse; OIDC disabled", iam)
		return nil
	}
	return &oidcConfig{
		iamEndpoint:  strings.TrimRight(iam, "/"),
		iamHost:      iamURL.Host,
		clientID:     cid,
		clientSecret: cs,
		stateSecret:  []byte(ss),
		owner:        owner,
		cookieDomain: cookieDomain,
		nonces:       newNonceLRU(10000, stateTTL),
		mintLimiter:  newRateLimiter(mintRateLimit, mintRateWindow),
		jwtValidator: newSessionJWTValidator(strings.TrimRight(iam, "/"), cid, owner),
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
// and is bound to the given orgSlug. Returns the 16-byte nonce on success
// for caller-side single-use enforcement.
func (c *oidcConfig) verifyState(token, orgSlug string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("state: bad encoding")
	}
	// 16-byte nonce + 8-byte expiry + 32-byte HMAC = 56 bytes minimum.
	if len(raw) != 16+8+sha256.Size {
		return nil, fmt.Errorf("state: bad length")
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
		return nil, fmt.Errorf("state: bad signature")
	}
	if time.Now().Unix() > exp {
		return nil, fmt.Errorf("state: expired")
	}
	return nonce, nil
}

// callbackURL returns the absolute callback URL. KMS runs behind
// hanzoai/ingress with TLS termination; the scheme is always https in
// production. Hardcoded to avoid X-Forwarded-Proto misconfig regressions
// silently producing http:// redirect_uri values that IAM rejects.
func callbackURL(r *http.Request) string {
	return "https://" + r.Host + "/v1/sso/oidc/callback"
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
		mux.HandleFunc("POST /v1/kms/credentials", oidcUnconfigured)
		log.Printf("kms: OIDC SSO disabled (set IAM_ENDPOINT, KMS_OIDC_CLIENT_ID, KMS_OIDC_CLIENT_SECRET, KMS_STATE_SECRET)")
		return
	}
	log.Printf("kms: OIDC SSO enabled — issuer=%s client_id=%s owner=%s", cfg.iamEndpoint, cfg.clientID, cfg.owner)
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
	// CSRF: if the browser sent Origin or Referer, it must match this host
	// or IAM. Comparison is parsed-URL.Host equality (case-insensitive),
	// not prefix — `iam.dev.satschel.com.evil.com` does not match
	// `iam.dev.satschel.com`.
	if !originLooksOK(r, c.iamHost, r.Host) {
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
	nonce, err := c.verifyState(state, orgSlug)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
		return
	}
	// Single-use: cookie clear (race-prone across replicas) + server-side
	// nonce blacklist (authoritative). If the same nonce arrives a second
	// time on this replica it's rejected here.
	if !c.nonces.consume(nonce) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "state: already used"})
		return
	}
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

	// Session cookie = IAM access token. We validate it ourselves on the
	// mint-credential gate; SPA-only routes treat it as an opaque presence
	// signal.
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
// secret to the caller exactly once.
//
// Authz chain (every check fail-closed):
//  1. session cookie present
//  2. session JWT verified against IAM JWKS (sig, iss, aud, exp)
//  3. JWT `owner` claim equals KMS_IAM_OWNER
//  4. JWT `roles` claim contains kms-admin or superadmin
//  5. per-subject rate limit (5 / hour)
//
// On success the IAM admin credential (env-only) is used to create the
// app; the generated secret is forwarded to the caller exactly once.
func (c *oidcConfig) handleMintClientCredential(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "session required"})
		return
	}

	claims, err := c.jwtValidator.validate(r.Context(), cookie.Value)
	if err != nil {
		log.Printf("kms: audit: mint-credential rejected — jwt: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "invalid session"})
		return
	}

	if !hasRole(claims.Roles, roleKMSAdmin) && !hasRole(claims.Roles, roleSuperadmin) {
		log.Printf("kms: audit: mint-credential subject=%s ok=false reason=role", claims.Subject)
		writeJSON(w, http.StatusForbidden, map[string]any{"message": "kms-admin role required"})
		return
	}

	if !c.mintLimiter.allow(claims.Subject) {
		log.Printf("kms: audit: mint-credential subject=%s ok=false reason=rate", claims.Subject)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"message": "rate limited"})
		return
	}

	adminID := envOr("KMS_IAM_ADMIN_CLIENT_ID", "")
	adminSecret := envOr("KMS_IAM_ADMIN_CLIENT_SECRET", "")
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
		nb := make([]byte, 4)
		_, _ = rand.Read(nb)
		req.Name = fmt.Sprintf("kms-client-%x", nb)
	}

	clientID, clientSecret, err := c.callIAMAddApplication(r.Context(), adminID, adminSecret, req.Name, req.Description)
	if err != nil {
		log.Printf("kms: audit: mint-credential subject=%s name=%s ok=false reason=iam: %v", claims.Subject, req.Name, err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"message": err.Error()})
		return
	}
	log.Printf("kms: audit: mint-credential subject=%s name=%s ok=true", claims.Subject, req.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":         req.Name,
		"clientId":     clientID,
		"clientSecret": clientSecret,
	})
}

// callIAMAddApplication posts the create request to Casdoor and parses
// the response. Validates HTTP status AND the IAM envelope `status` so a
// 200-with-error body is treated as the failure it is.
func (c *oidcConfig) callIAMAddApplication(ctx context.Context, adminID, adminSecret, name, description string) (string, string, error) {
	body := map[string]any{
		"owner":        c.owner,
		"name":         name,
		"displayName":  name,
		"description":  description,
		"organization": c.owner,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, adminURL, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("iam unreachable: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("iam status=%d", resp.StatusCode)
	}

	// Casdoor returns the generated app under either `data` or `data2`
	// depending on version — try both shapes.
	var iam struct {
		Status string          `json:"status"`
		Msg    string          `json:"msg"`
		Data   json.RawMessage `json:"data"`
		Data2  json.RawMessage `json:"data2"`
	}
	if err := json.Unmarshal(respBody, &iam); err != nil {
		return "", "", fmt.Errorf("iam: bad json: %w", err)
	}
	if iam.Status != "" && iam.Status != "ok" {
		return "", "", fmt.Errorf("iam: %s", iam.Msg)
	}

	type appShape struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	var app appShape
	for _, raw := range []json.RawMessage{iam.Data2, iam.Data} {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var a appShape
		if err := json.Unmarshal(raw, &a); err == nil && a.ClientID != "" {
			app = a
			break
		}
	}
	if app.ClientID == "" || app.ClientSecret == "" {
		return "", "", errors.New("iam returned no credentials")
	}
	return app.ClientID, app.ClientSecret, nil
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
// (no header sent — direct nav) or its parsed Host equals one of the
// allowed hosts (case-insensitive). Hosts only — no prefix matching — so
// `iam.dev.satschel.com.evil.com` cannot impersonate `iam.dev.satschel.com`.
// Schemes other than https are rejected.
func originLooksOK(r *http.Request, allowedHosts ...string) bool {
	for _, h := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		if h == "" {
			continue
		}
		u, err := url.Parse(h)
		if err != nil || u.Host == "" {
			return false
		}
		if u.Scheme != "https" {
			return false
		}
		matched := false
		for _, host := range allowedHosts {
			if host == "" {
				continue
			}
			if strings.EqualFold(u.Host, host) {
				matched = true
				break
			}
		}
		if !matched {
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

// hasRole returns true if any element of roles equals want (case-sensitive,
// matches Casdoor convention).
func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// JWKS-validated session JWTs.
// ---------------------------------------------------------------------------

// sessionClaims is the subset of IAM/Casdoor claims we authorize on.
// `owner` scopes to the org slug; `roles` carries the role list the
// kms-admin gate consumes.
type sessionClaims struct {
	jwt.Claims
	Owner string   `json:"owner"`
	Roles []string `json:"roles"`
}

// sessionJWTValidator verifies session JWTs against the IAM JWKS. TTL
// cache for keys (5 min); fail-stale on refresh error so brief IAM blips
// don't break the mint-credential gate.
type sessionJWTValidator struct {
	jwksURL  string
	issuer   string
	audience string
	owner    string
	cache    *jwksCache
}

func newSessionJWTValidator(iamEndpoint, audience, owner string) *sessionJWTValidator {
	return &sessionJWTValidator{
		jwksURL:  iamEndpoint + "/.well-known/jwks",
		issuer:   iamEndpoint,
		audience: audience,
		owner:    owner,
		cache: &jwksCache{
			url:    iamEndpoint + "/.well-known/jwks",
			ttl:    5 * time.Minute,
			client: &http.Client{Timeout: 10 * time.Second},
		},
	}
}

func (v *sessionJWTValidator) validate(ctx context.Context, raw string) (*sessionClaims, error) {
	if raw == "" {
		return nil, errors.New("empty token")
	}
	tok, err := jwt.ParseSigned(raw, []gojose.SignatureAlgorithm{
		gojose.RS256, gojose.RS384, gojose.RS512,
		gojose.ES256, gojose.ES384, gojose.ES512,
	})
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	keys, err := v.cache.get(ctx)
	if err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	var claims sessionClaims
	verified := false
	var lastErr error
	for _, k := range keys.Keys {
		if err := tok.Claims(k.Key, &claims); err == nil {
			verified = true
			break
		} else {
			lastErr = err
		}
	}
	if !verified {
		if lastErr == nil {
			lastErr = errors.New("no key matched")
		}
		return nil, fmt.Errorf("verify: %w", lastErr)
	}
	exp := jwt.Expected{
		Time:        time.Now(),
		Issuer:      v.issuer,
		AnyAudience: jwt.Audience{v.audience},
	}
	if err := claims.Claims.Validate(exp); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	if claims.Owner != v.owner {
		return nil, fmt.Errorf("owner: got %q want %q", claims.Owner, v.owner)
	}
	return &claims, nil
}

// jwksCache holds a TTL-bounded copy of IAM's JWKS. fail-stale: if any
// keys have been fetched and a refresh fails, the stale set is returned.
type jwksCache struct {
	mu        sync.RWMutex
	keys      *gojose.JSONWebKeySet
	fetchedAt time.Time
	ttl       time.Duration
	url       string
	client    *http.Client
}

func (c *jwksCache) get(ctx context.Context) (*gojose.JSONWebKeySet, error) {
	c.mu.RLock()
	if c.keys != nil && time.Since(c.fetchedAt) < c.ttl {
		k := c.keys
		c.mu.RUnlock()
		return k, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys != nil && time.Since(c.fetchedAt) < c.ttl {
		return c.keys, nil
	}
	keys, err := c.fetch(ctx)
	if err != nil {
		if c.keys != nil {
			return c.keys, nil
		}
		return nil, err
	}
	c.keys = keys
	c.fetchedAt = time.Now()
	return keys, nil
}

func (c *jwksCache) fetch(ctx context.Context) (*gojose.JSONWebKeySet, error) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var ks gojose.JSONWebKeySet
	if err := json.Unmarshal(body, &ks); err != nil {
		return nil, err
	}
	return &ks, nil
}

// ---------------------------------------------------------------------------
// Server-side single-use nonce blacklist.
// ---------------------------------------------------------------------------

// nonceLRU is a fixed-size hash set with TTL eviction. Keys = 16-byte
// state nonces. Provides at-most-once redemption inside the process; with
// >1 replica behind ingress the request must hit the same replica twice
// for the LRU to fire — sticky sessions or shared-state would fully close
// the multi-replica gap, but for KMS (StatefulSet replicas=1 in prod) this
// is sufficient and zero-dep.
type nonceLRU struct {
	mu      sync.Mutex
	cap     int
	ttl     time.Duration
	entries map[[16]byte]time.Time
}

func newNonceLRU(cap int, ttl time.Duration) *nonceLRU {
	if cap < 1 {
		cap = 1
	}
	return &nonceLRU{
		cap:     cap,
		ttl:     ttl,
		entries: make(map[[16]byte]time.Time, cap),
	}
}

// consume returns true if nonce is unseen (and records it) or false if
// already used. Expired entries are evicted on access.
func (l *nonceLRU) consume(nonce []byte) bool {
	if len(nonce) != 16 {
		return false
	}
	var k [16]byte
	copy(k[:], nonce)

	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if t, ok := l.entries[k]; ok {
		if now.Sub(t) < l.ttl {
			return false
		}
	}
	// Evict if at capacity (drop expired first; if none, drop oldest).
	if len(l.entries) >= l.cap {
		var oldestKey [16]byte
		var oldestT time.Time
		first := true
		for ek, et := range l.entries {
			if now.Sub(et) >= l.ttl {
				delete(l.entries, ek)
				continue
			}
			if first || et.Before(oldestT) {
				oldestKey = ek
				oldestT = et
				first = false
			}
		}
		if len(l.entries) >= l.cap && !first {
			delete(l.entries, oldestKey)
		}
	}
	l.entries[k] = now
	return true
}

// ---------------------------------------------------------------------------
// Per-subject rate limiter (in-memory window count).
// ---------------------------------------------------------------------------

type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string][]time.Time),
	}
}

// allow returns true if the subject is under its window quota and
// records the hit; false otherwise.
func (rl *rateLimiter) allow(subject string) bool {
	if subject == "" {
		return false
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	hits := rl.buckets[subject]
	// Drop expired hits.
	keep := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= rl.limit {
		rl.buckets[subject] = keep
		return false
	}
	rl.buckets[subject] = append(keep, now)
	return true
}
