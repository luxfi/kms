// Tests for the org-scoped JWT middleware on the secrets surface.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// signOrgClaims returns a serialized JWT for the given orgClaims under signer.
func signOrgClaims(t *testing.T, signer gojose.Signer, claims orgClaims) string {
	t.Helper()
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("jwt.Signed.Serialize: %v", err)
	}
	return out
}

// jwksHandler returns a stub IAM that serves the given JWKS.
func jwksHandler(jwks *gojose.JSONWebKeySet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/jwks") {
			json.NewEncoder(w).Encode(jwks)
			return
		}
		http.NotFound(w, r)
	})
}

func TestRequireOrgJWT_missingBearer(t *testing.T) {
	auth := newOrgJWTAuth("https://iam.example.com")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_invalidBearerShape(t *testing.T) {
	auth := newOrgJWTAuth("https://iam.example.com")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Token abc")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_validTokenForCorrectOrg(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "user-z",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "liquidity", // user-token case: owner IS the org
	})

	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !called {
		t.Error("inner handler not called")
	}
}

func TestRequireOrgJWT_crossOrgRejected(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	// Token for org=mlc, request for org=liquidity → 403.
	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "mlc-app",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "mlc",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must NOT be called for cross-org token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_kmsAdminCrossesOrgs(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	// kms-admin role lets the holder reach across orgs.
	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "ops",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "operator-org",
		Roles: []string{"kms-admin"},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d want 200 (kms-admin); body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_expiredRejected(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "old",
			Expiry:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
		Owner: "liquidity",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must reject expired token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d want 401 (expired); body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_wrongIssuerRejected(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	// Issuer mismatch — claim says some-other-iam, validator expects iam.URL.
	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  "https://other-iam.example.com",
			Subject: "u",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "liquidity",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must reject wrong issuer")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d want 401 (wrong issuer); body=%s", rec.Code, rec.Body.String())
	}
}

// Casdoor-style client_credentials JWT — owner="admin" (record parent),
// type="application", name="<org>-<service>". The org is derived from
// the name prefix per the documented IAM naming convention.
func TestRequireOrgJWT_applicationToken_orgFromName(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "admin/liquidity-kms",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "admin",
		Name:  "liquidity-kms",
		Type:  "application",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d want 200 (app token, org from name); body=%s", rec.Code, rec.Body.String())
	}
}

// An application named "liquidity-kms" must NOT be able to read mlc's
// secrets — the name prefix is the only org binding, no fall-through
// to other orgs.
func TestRequireOrgJWT_applicationToken_crossOrgRejected(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "admin/liquidity-kms",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "admin",
		Name:  "liquidity-kms",
		Type:  "application",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must reject app token reaching across orgs")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/mlc/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d want 403 (cross-org app token); body=%s", rec.Code, rec.Body.String())
	}
}

// Operator-set Tag overrides org derivation — used for cross-cutting
// service apps that don't follow <org>-<service>.
func TestRequireOrgJWT_tagPicksOrg(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "admin/some-app",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "admin",
		Name:  "some-app",
		Type:  "application",
		Tag:   "liquidity",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d want 200 (Tag override); body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_missingOwnerClaimRejected(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL)

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "u",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		// Owner deliberately empty AND no Tag/Name/Type — orgs() yields
		// nothing, so the token is rejected.
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must reject token with no resolvable org")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/liquidity/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d want 401 (missing owner); body=%s", rec.Code, rec.Body.String())
	}
}

func TestBearerToken_extracts(t *testing.T) {
	cases := []struct {
		header, want string
	}{
		{"", ""},
		{"Bearer ", ""},
		{"Bearer abc", "abc"},
		{"Bearer  spaced  ", "spaced"},
		{"bearer abc", ""}, // case-sensitive prefix per RFC 6750
		{"Token abc", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		got := bearerToken(req)
		if got != c.want {
			t.Errorf("header=%q got=%q want=%q", c.header, got, c.want)
		}
	}
}
