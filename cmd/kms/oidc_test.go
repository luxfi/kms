package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func newTestCfg(t *testing.T, iamEndpoint string) *oidcConfig {
	t.Helper()
	u, _ := url.Parse(strings.TrimRight(iamEndpoint, "/"))
	return &oidcConfig{
		iamEndpoint:  strings.TrimRight(iamEndpoint, "/"),
		iamHost:      u.Host,
		clientID:     "liquidity-kms",
		clientSecret: "test-secret",
		stateSecret:  []byte("test-secret-test-secret-test-32!"),
		owner:        "liquidity",
		nonces:       newNonceLRU(1024, stateTTL),
		mintLimiter:  newRateLimiter(mintRateLimit, mintRateWindow),
	}
}

// TestSsoOidcLogin_redirectsToIAM asserts the login handler 302s to the
// IAM authorize URL with all required OAuth2 params.
func TestSsoOidcLogin_redirectsToIAM(t *testing.T) {
	cfg := newTestCfg(t, "https://iam.dev.satschel.com")
	req := httptest.NewRequest(http.MethodGet, "/v1/sso/oidc/login?orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
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
	u, _ := url.Parse(resp.Header.Get("Location"))
	if u.Query().Get("state") != stateVal {
		t.Error("state cookie value does not match state query param")
	}
	if _, err := cfg.verifyState(stateVal, "liquidity"); err != nil {
		t.Errorf("state verify: %v", err)
	}
	if _, err := cfg.verifyState(stateVal, "evil"); err == nil {
		t.Error("state verify accepted wrong orgSlug — binding broken")
	}
}

// TestSsoOidcCallback_validatesState covers four cases:
//  1. missing state cookie → 400
//  2. mismatch between cookie and ?state= → 400
//  3. expired state → 400
//  4. good state → token exchange + 302 /
func TestSsoOidcCallback_validatesState(t *testing.T) {
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

	good, err := cfg.signState("liquidity")
	if err != nil {
		t.Fatalf("signState: %v", err)
	}

	// 1) No state cookie.
	req := httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+good+"&code=good-code&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing-cookie: got %d want 400", rec.Code)
	}

	// 2) Cookie mismatch.
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

	// 3) Expired.
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

	// 4) Happy path.
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

// TestOriginGuard_rejectsPrefixExtension confirms the parsed-Host
// equality check rejects suffix-based smuggling like
// `iam.dev.satschel.com.evil.com` — the previous prefix-match accepted it.
func TestOriginGuard_rejectsPrefixExtension(t *testing.T) {
	cfg := newTestCfg(t, "https://iam.dev.satschel.com")
	good, _ := cfg.signState("liquidity")

	req := httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+good+"&code=c&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: good})
	// Smuggled host: `iam.dev.satschel.com` is the prefix but the actual
	// host is attacker-controlled.
	req.Header.Set("Origin", "https://iam.dev.satschel.com.evil.com")
	rec := httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("prefix-extension: got %d want 403", rec.Code)
	}
}

// TestOriginGuard_rejectsHTTP confirms http:// origins are rejected even
// if the host matches.
func TestOriginGuard_rejectsHTTP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "http://iam.dev.satschel.com")
	if originLooksOK(r, "iam.dev.satschel.com", "kms.dev.satschel.com") {
		t.Error("http:// origin accepted; want rejected")
	}
}

// TestStateNonce_singleUseAcrossReplicas mints a state, redeems it once,
// then attempts to replay it (cookie still attached, e.g. before the
// Set-Cookie clear lands). The second redemption must be rejected.
func TestStateNonce_singleUseAcrossReplicas(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": "iam-jwt-token"})
	}))
	defer iam.Close()
	cfg := newTestCfg(t, iam.URL)

	good, _ := cfg.signState("liquidity")

	// First redemption — should succeed (302 /).
	req := httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+good+"&code=c&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: good})
	rec := httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("first redeem: got %d want 302", rec.Code)
	}

	// Replay — same state, same cookie still attached. LRU must reject.
	req = httptest.NewRequest(http.MethodGet,
		"/v1/sso/oidc/callback?state="+good+"&code=c&orgSlug=liquidity", nil)
	req.Host = "kms.dev.satschel.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: good})
	rec = httptest.NewRecorder()
	cfg.handleCallback(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replay: got %d want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "already used") {
		t.Errorf("replay body: got %q want contains 'already used'", rec.Body.String())
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
// unauthenticated callers.
func TestMintClientCredential_requiresSession(t *testing.T) {
	cfg := newTestCfg(t, "https://iam.dev.satschel.com")
	req := httptest.NewRequest(http.MethodPost, "/v1/kms/credentials", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	cfg.handleMintClientCredential(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-session: got %d want 401", rec.Code)
	}
}

// TestMintClientCredential_validatesJWT covers four invalid-JWT cases —
// each must result in 401:
//  1. unsigned/garbage
//  2. signature key mismatch
//  3. expired
//  4. wrong audience
func TestMintClientCredential_validatesJWT(t *testing.T) {
	signer, jwks := newTestSigner(t)
	wrongSigner, _ := newTestSigner(t)

	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/jwks") {
			json.NewEncoder(w).Encode(jwks)
			return
		}
		http.NotFound(w, r)
	}))
	defer iam.Close()

	cfg := newTestCfg(t, iam.URL)
	cfg.jwtValidator = newSessionJWTValidator(iam.URL, cfg.clientID, cfg.owner)

	cases := []struct {
		name  string
		token string
	}{
		{
			name:  "garbage",
			token: "not-a-jwt",
		},
		{
			name:  "wrong-signer",
			token: signClaims(t, wrongSigner, sessionClaims{
				Claims: jwt.Claims{
					Issuer:   iam.URL,
					Subject:  "u1",
					Audience: jwt.Audience{cfg.clientID},
					Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
				Owner: cfg.owner,
				Roles: []string{roleKMSAdmin},
			}),
		},
		{
			name: "expired",
			token: signClaims(t, signer, sessionClaims{
				Claims: jwt.Claims{
					Issuer:   iam.URL,
					Subject:  "u1",
					Audience: jwt.Audience{cfg.clientID},
					Expiry:   jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
				},
				Owner: cfg.owner,
				Roles: []string{roleKMSAdmin},
			}),
		},
		{
			name: "wrong-aud",
			token: signClaims(t, signer, sessionClaims{
				Claims: jwt.Claims{
					Issuer:   iam.URL,
					Subject:  "u1",
					Audience: jwt.Audience{"some-other-app"},
					Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
				Owner: cfg.owner,
				Roles: []string{roleKMSAdmin},
			}),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/kms/credentials", strings.NewReader(`{}`))
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.token})
			rec := httptest.NewRecorder()
			cfg.handleMintClientCredential(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("got %d want 401; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestMintClientCredential_requiresKmsAdminRole — a JWT with a non-admin
// role list must produce 403.
func TestMintClientCredential_requiresKmsAdminRole(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/jwks") {
			json.NewEncoder(w).Encode(jwks)
			return
		}
		http.NotFound(w, r)
	}))
	defer iam.Close()

	cfg := newTestCfg(t, iam.URL)
	cfg.jwtValidator = newSessionJWTValidator(iam.URL, cfg.clientID, cfg.owner)

	tok := signClaims(t, signer, sessionClaims{
		Claims: jwt.Claims{
			Issuer:   iam.URL,
			Subject:  "u-no-roles",
			Audience: jwt.Audience{cfg.clientID},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: cfg.owner,
		Roles: []string{"viewer"}, // not admin
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/kms/credentials", strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	rec := httptest.NewRecorder()
	cfg.handleMintClientCredential(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestMintClientCredential_rateLimits — 6th mint within 1h from the same
// subject must produce 429.
func TestMintClientCredential_rateLimits(t *testing.T) {
	signer, jwks := newTestSigner(t)

	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/jwks") {
			json.NewEncoder(w).Encode(jwks)
			return
		}
		// add-application: return generated app under data2 envelope.
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"data2": map[string]any{
				"clientId":     "generated-client-id",
				"clientSecret": "generated-client-secret",
			},
		})
	}))
	defer iam.Close()

	cfg := newTestCfg(t, iam.URL)
	cfg.jwtValidator = newSessionJWTValidator(iam.URL, cfg.clientID, cfg.owner)

	t.Setenv("KMS_IAM_ADMIN_CLIENT_ID", "admin-id")
	t.Setenv("KMS_IAM_ADMIN_CLIENT_SECRET", "admin-secret")

	tok := signClaims(t, signer, sessionClaims{
		Claims: jwt.Claims{
			Issuer:   iam.URL,
			Subject:  "u-burst",
			Audience: jwt.Audience{cfg.clientID},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: cfg.owner,
		Roles: []string{roleKMSAdmin},
	})

	// First 5 must succeed.
	for i := 0; i < mintRateLimit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/credentials", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
		rec := httptest.NewRecorder()
		cfg.handleMintClientCredential(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("mint #%d: got %d want 201; body=%s", i+1, rec.Code, rec.Body.String())
		}
	}
	// 6th must be 429.
	req := httptest.NewRequest(http.MethodPost, "/v1/kms/credentials", strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	rec := httptest.NewRecorder()
	cfg.handleMintClientCredential(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("mint #6: got %d want 429", rec.Code)
	}
}

// TestMintClientCredential_auditLogs captures log output and asserts the
// audit line carries subject and name.
func TestMintClientCredential_auditLogs(t *testing.T) {
	signer, jwks := newTestSigner(t)

	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/jwks") {
			json.NewEncoder(w).Encode(jwks)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"data2": map[string]any{
				"clientId":     "generated-client-id",
				"clientSecret": "generated-client-secret",
			},
		})
	}))
	defer iam.Close()

	cfg := newTestCfg(t, iam.URL)
	cfg.jwtValidator = newSessionJWTValidator(iam.URL, cfg.clientID, cfg.owner)
	t.Setenv("KMS_IAM_ADMIN_CLIENT_ID", "admin-id")
	t.Setenv("KMS_IAM_ADMIN_CLIENT_SECRET", "admin-secret")

	tok := signClaims(t, signer, sessionClaims{
		Claims: jwt.Claims{
			Issuer:   iam.URL,
			Subject:  "u-audit",
			Audience: jwt.Audience{cfg.clientID},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: cfg.owner,
		Roles: []string{roleKMSAdmin},
	})

	var buf bytes.Buffer
	prevW := log.Writer()
	prevF := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevW)
		log.SetFlags(prevF)
	})

	body := strings.NewReader(`{"name":"my-test-app"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/kms/credentials", body)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	rec := httptest.NewRecorder()
	cfg.handleMintClientCredential(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}

	logs := buf.String()
	if !strings.Contains(logs, "subject=u-audit") {
		t.Errorf("audit log missing subject; got: %s", logs)
	}
	if !strings.Contains(logs, "name=my-test-app") {
		t.Errorf("audit log missing name; got: %s", logs)
	}
	if !strings.Contains(logs, "ok=true") {
		t.Errorf("audit log missing ok=true; got: %s", logs)
	}
}

// TestCookieDomain_rejectsLeadingDot asserts loadOIDCConfig refuses to
// boot when KMS_COOKIE_DOMAIN is a wildcard subdomain (leading dot).
func TestCookieDomain_rejectsLeadingDot(t *testing.T) {
	t.Setenv("IAM_ENDPOINT", "https://iam.dev.satschel.com")
	t.Setenv("KMS_OIDC_CLIENT_ID", "liquidity-kms")
	t.Setenv("KMS_OIDC_CLIENT_SECRET", "test-secret")
	t.Setenv("KMS_STATE_SECRET", "test-secret-test-secret-test-32!")
	t.Setenv("KMS_COOKIE_DOMAIN", ".satschel.com")

	if cfg := loadOIDCConfig(); cfg != nil {
		t.Fatal("loadOIDCConfig accepted leading-dot KMS_COOKIE_DOMAIN; want nil")
	}

	// Sanity: removing the dot succeeds.
	t.Setenv("KMS_COOKIE_DOMAIN", "kms.dev.satschel.com")
	if cfg := loadOIDCConfig(); cfg == nil {
		t.Error("loadOIDCConfig rejected exact host KMS_COOKIE_DOMAIN; want accepted")
	}
}

// TestCasdoorErrorEnvelope_returnsError — IAM returns 200 + status:error
// envelope. callIAMAddApplication must convert to error with Msg.
func TestCasdoorErrorEnvelope_returnsError(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"msg":    "duplicate name",
		})
	}))
	defer iam.Close()

	cfg := newTestCfg(t, iam.URL)
	_, _, err := cfg.callIAMAddApplication(context.Background(), "admin", "secret", "dup", "")
	if err == nil {
		t.Fatal("expected error from status:error envelope; got nil")
	}
	if !strings.Contains(err.Error(), "duplicate name") {
		t.Errorf("error: got %q want to contain 'duplicate name'", err.Error())
	}
}

// TestCasdoorErrorEnvelope_non2xxFails — non-2xx HTTP must fail without
// trying to parse the body envelope.
func TestCasdoorErrorEnvelope_non2xxFails(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer iam.Close()

	cfg := newTestCfg(t, iam.URL)
	_, _, err := cfg.callIAMAddApplication(context.Background(), "admin", "secret", "n", "")
	if err == nil {
		t.Fatal("expected error from 503; got nil")
	}
	if !strings.Contains(err.Error(), "status=503") {
		t.Errorf("error: got %q want to contain 'status=503'", err.Error())
	}
}

// TestCallbackURL_alwaysHTTPS asserts the callback URL is https:// even
// when the request lacks TLS metadata. Production runs behind ingress;
// http:// would produce a redirect_uri IAM rejects.
func TestCallbackURL_alwaysHTTPS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/sso/oidc/login", nil)
	r.Host = "kms.dev.satschel.com"
	if got := callbackURL(r); got != "https://kms.dev.satschel.com/v1/sso/oidc/callback" {
		t.Errorf("callbackURL = %q; want https://...", got)
	}
}

// TestSsoOidcUnconfigured returns 503 when env vars are missing.
func TestSsoOidcUnconfigured(t *testing.T) {
	rec := httptest.NewRecorder()
	oidcUnconfigured(rec, httptest.NewRequest(http.MethodGet, "/v1/sso/oidc/login", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unconfigured: got %d want 503", rec.Code)
	}
}

// mintState fabricates a state token with an arbitrary expiry — used to
// build an expired token for the negative test.
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

// newTestSigner returns an RSA signer + JWKS containing the public key.
func newTestSigner(t *testing.T) (gojose.Signer, *gojose.JSONWebKeySet) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	jwks := &gojose.JSONWebKeySet{
		Keys: []gojose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     "test-key",
			Algorithm: string(gojose.RS256),
			Use:       "sig",
		}},
	}
	return signer, jwks
}

// signClaims returns a serialized JWT for the given claims under signer.
func signClaims(t *testing.T, signer gojose.Signer, claims sessionClaims) string {
	t.Helper()
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("jwt.Signed.Serialize: %v", err)
	}
	return out
}
