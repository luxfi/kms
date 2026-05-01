package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestCfg(t *testing.T, iamEndpoint string) *oidcConfig {
	t.Helper()
	// Deterministic 32-byte secret so signature checks are reproducible.
	return &oidcConfig{
		iamEndpoint:  strings.TrimRight(iamEndpoint, "/"),
		clientID:     "liquidity-kms",
		clientSecret: "test-secret",
		stateSecret:  []byte("test-secret-test-secret-test-32!"),
	}
}

// TestSsoOidcLogin_redirectsToIAM asserts the login handler 302s to the
// IAM authorize URL with all required OAuth2 params.
func TestSsoOidcLogin_redirectsToIAM(t *testing.T) {
	cfg := newTestCfg(t, "https://iam.dev.satschel.com")
	req := httptest.NewRequest(http.MethodGet, "/v1/sso/oidc/login?orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{} // mark as TLS so callbackURL emits https://
	rec := httptest.NewRecorder()
	cfg.handleLogin(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://iam.dev.satschel.com/login/oauth/authorize?") {
		t.Fatalf("Location: %q does not target IAM authorize", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := u.Query()
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "scope", "state"} {
		if q.Get(k) == "" {
			t.Errorf("missing query param %q", k)
		}
	}
	if q.Get("client_id") != "liquidity-kms" {
		t.Errorf("client_id: got %q want liquidity-kms", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type: got %q want code", q.Get("response_type"))
	}
	if q.Get("redirect_uri") != "https://kms.dev.satschel.com/v1/sso/oidc/callback" {
		t.Errorf("redirect_uri: got %q", q.Get("redirect_uri"))
	}
	if q.Get("application") != "liquidity" {
		t.Errorf("application: got %q want liquidity", q.Get("application"))
	}
}

// TestSsoOidcLogin_includesStateNonce asserts a state cookie is set,
// HttpOnly+Secure, and the value verifies under our HMAC.
func TestSsoOidcLogin_includesStateNonce(t *testing.T) {
	cfg := newTestCfg(t, "https://iam.dev.satschel.com")
	req := httptest.NewRequest(http.MethodGet, "/v1/sso/oidc/login?orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	cfg.handleLogin(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	var stateVal string
	for _, c := range resp.Cookies() {
		if c.Name != stateCookie {
			continue
		}
		stateVal = c.Value
		if !c.HttpOnly {
			t.Error("state cookie not HttpOnly")
		}
		if !c.Secure {
			t.Error("state cookie not Secure")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Error("state cookie not SameSite=Lax")
		}
		if c.MaxAge != int(stateTTL/time.Second) {
			t.Errorf("state cookie MaxAge=%d want %d", c.MaxAge, int(stateTTL/time.Second))
		}
	}
	if stateVal == "" {
		t.Fatal("no state cookie set")
	}
	// Cookie value must equal the state= query param the redirect carries.
	u, _ := url.Parse(resp.Header.Get("Location"))
	if u.Query().Get("state") != stateVal {
		t.Error("state cookie value does not match state query param")
	}
	// And it must verify under our HMAC for orgSlug=liquidity.
	if err := cfg.verifyState(stateVal, "liquidity"); err != nil {
		t.Errorf("state verify: %v", err)
	}
	// Forged orgSlug must NOT verify (state is bound to org).
	if err := cfg.verifyState(stateVal, "evil"); err == nil {
		t.Error("state verify accepted wrong orgSlug — binding broken")
	}
}

// TestSsoOidcCallback_validatesState covers three cases:
//  1. missing state cookie → 400
//  2. mismatch between cookie and ?state= → 400
//  3. expired state → 400
//  4. good state → token exchange + 302 /
func TestSsoOidcCallback_validatesState(t *testing.T) {
	// Stand up a fake IAM that 200s the token exchange.
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/oauth/access_token" {
			t.Errorf("unexpected IAM path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type: got %q", form.Get("grant_type"))
		}
		if form.Get("code") != "good-code" {
			t.Errorf("code: got %q", form.Get("code"))
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "iam-jwt-token"})
	}))
	defer iam.Close()

	cfg := newTestCfg(t, iam.URL)

	// Mint a valid state for orgSlug=liquidity.
	good, err := cfg.signState("liquidity")
	if err != nil {
		t.Fatalf("signState: %v", err)
	}

	// 1) No state cookie at all.
	req := httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+good+"&code=good-code&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing-cookie: got %d want 400", rec.Code)
	}

	// 2) Cookie present but does not match the ?state= param.
	req = httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+good+"&code=good-code&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: "different-value"})
	rec = httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("mismatched-cookie: got %d want 400", rec.Code)
	}

	// 3) Expired state — mint with a stale expiry by hand.
	stale := mintState(t, cfg.stateSecret, "liquidity", time.Now().Add(-1*time.Minute).Unix())
	req = httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+stale+"&code=good-code&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: stale})
	rec = httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expired: got %d want 400", rec.Code)
	}

	// 4) Happy path: state matches, exchange returns access_token.
	req = httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+good+"&code=good-code&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: good})
	rec = httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("happy: got %d want 302; body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("happy: Location=%q want /", loc)
	}
	// Session cookie must be set with the IAM token.
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil {
		t.Fatal("session cookie not set on happy path")
	}
	if session.Value != "iam-jwt-token" {
		t.Errorf("session value: got %q want iam-jwt-token", session.Value)
	}
	if !session.HttpOnly || !session.Secure {
		t.Error("session cookie missing HttpOnly/Secure")
	}
}

// TestSsoOidcCallback_csrfProtection asserts a callback whose
// Origin/Referer points elsewhere is rejected with 403.
func TestSsoOidcCallback_csrfProtection(t *testing.T) {
	cfg := newTestCfg(t, "https://iam.dev.satschel.com")
	good, _ := cfg.signState("liquidity")

	req := httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+good+"&code=c&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: good})
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("evil origin: got %d want 403", rec.Code)
	}
}

// TestSsoOidcLogout clears the session cookie.
func TestSsoOidcLogout(t *testing.T) {
	cfg := newTestCfg(t, "https://iam.dev.satschel.com")
	req := httptest.NewRequest(http.MethodPost, "/v1/sso/logout", nil)
	rec := httptest.NewRecorder()
	cfg.handleLogout(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("status: got %d want 204", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("session cookie not cleared")
	}
}

// TestMintClientCredential_requiresSession asserts the endpoint refuses
// unauthenticated callers — the IAM admin credential must NEVER be used
// on behalf of an anonymous browser.
func TestMintClientCredential_requiresSession(t *testing.T) {
	cfg := newTestCfg(t, "https://iam.dev.satschel.com")
	req := httptest.NewRequest(http.MethodPost, "/v1/kms/credentials", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	cfg.handleMintClientCredential(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-session: got %d want 401", rec.Code)
	}
}

// TestSsoOidcUnconfigured returns 503 when env vars are missing — the
// deployment-misconfig signal the operator should see.
func TestSsoOidcUnconfigured(t *testing.T) {
	rec := httptest.NewRecorder()
	oidcUnconfigured(rec, httptest.NewRequest(http.MethodGet, "/v1/sso/oidc/login", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unconfigured: got %d want 503", rec.Code)
	}
}

// mintState fabricates a state token with an arbitrary expiry — used to
// build an expired token for the negative test in TestSsoOidcCallback_validatesState.
func mintState(t *testing.T, secret []byte, orgSlug string, exp int64) string {
	t.Helper()
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	buf := append([]byte(nil), nonce...)
	buf = appendBE64(buf, exp)
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf)
	mac.Write([]byte(orgSlug))
	buf = append(buf, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(buf)
}
