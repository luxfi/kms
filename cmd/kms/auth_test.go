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
	auth := newOrgJWTAuth("https://iam.example.com", "")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_invalidBearerShape(t *testing.T) {
	auth := newOrgJWTAuth("https://iam.example.com", "")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
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

	auth := newOrgJWTAuth(iam.URL, "")

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "user-z",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "org1", // user-token case: owner IS the org
	})

	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
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

	auth := newOrgJWTAuth(iam.URL, "")

	// Token for org=org2, request for org=org1 → 403.
	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "org2-app",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "org2",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must NOT be called for cross-org token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_subScopeAuthorized(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL, "")

	// Token for parent org "lux"; request for the project sub-scope
	// "lux-infra" (the lux-operator's projectSlug) → 200. A token for
	// the parent org reaches every hyphen-delimited project under it.
	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "lux-kms",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "lux",
	})

	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/lux-infra/secrets/lux/devnet/staking", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d want 200 (lux authorizes lux-infra); body=%s", rec.Code, rec.Body.String())
	}
	if !called {
		t.Error("inner handler not called for authorized sub-scope")
	}
}

func TestRequireOrgJWT_subScopeBoundaryRejected(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL, "")

	// Token for org "lux"; request for "luxx-infra" → 403. The '-'
	// boundary in the prefix rule prevents a token for "lux" from
	// leaking into an unrelated org whose slug merely shares a prefix.
	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "lux-kms",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "lux",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must NOT be called: lux must not authorize luxx-infra")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/luxx-infra/secrets/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d want 403 (boundary); body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireOrgJWT_kmsAdminCrossesOrgs(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL, "")

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

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
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

	auth := newOrgJWTAuth(iam.URL, "")

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "old",
			Expiry:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
		Owner: "org1",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must reject expired token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
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

	auth := newOrgJWTAuth(iam.URL, "")

	// Issuer mismatch — claim says some-other-iam, validator expects iam.URL.
	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  "https://other-iam.example.com",
			Subject: "u",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "org1",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must reject wrong issuer")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d want 401 (wrong issuer); body=%s", rec.Code, rec.Body.String())
	}
}

// IAM client_credentials JWT — owner="admin" (record parent),
// type="application", name="<org>-<service>". The org is derived from
// the name prefix per the documented IAM naming convention.
func TestRequireOrgJWT_applicationToken_orgFromName(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL, "")

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "admin/org1-kms",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "admin",
		Name:  "org1-kms",
		Type:  "application",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d want 200 (app token, org from name); body=%s", rec.Code, rec.Body.String())
	}
}

// An application named "org1-kms" must NOT be able to read org2's
// secrets — the name prefix is the only org binding, no fall-through
// to other orgs.
func TestRequireOrgJWT_applicationToken_crossOrgRejected(t *testing.T) {
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	defer iam.Close()

	auth := newOrgJWTAuth(iam.URL, "")

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "admin/org1-kms",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "admin",
		Name:  "org1-kms",
		Type:  "application",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must reject app token reaching across orgs")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org2/secrets/iam/X", nil)
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

	auth := newOrgJWTAuth(iam.URL, "")

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  iam.URL,
			Subject: "admin/some-app",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "admin",
		Name:  "some-app",
		Type:  "application",
		Tag:   "org1",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
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

	auth := newOrgJWTAuth(iam.URL, "")

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

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d want 401 (missing owner); body=%s", rec.Code, rec.Body.String())
	}
}

// In production KMS fetches JWKS from the in-cluster IAM URL but the
// JWT `iss` claim was minted with the public hostname. The validator
// must accept tokens whose `iss` matches the configured expectedIssuer
// even when that string differs from the JWKS host.
func TestRequireOrgJWT_splitJwksAndIssuer(t *testing.T) {
	signer, jwks := newTestSigner(t)
	jwksHost := httptest.NewServer(jwksHandler(jwks))
	defer jwksHost.Close()

	publicIssuer := "https://iam.dev.example.com"
	auth := newOrgJWTAuth(jwksHost.URL, publicIssuer)

	tok := signOrgClaims(t, signer, orgClaims{
		Claims: jwt.Claims{
			Issuer:  publicIssuer, // minted with public host
			Subject: "admin/org1-kms",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Owner: "admin",
		Name:  "org1-kms",
		Type:  "application",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/org1/secrets/iam/X", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d want 200 (split jwksURL vs issuer); body=%s", rec.Code, rec.Body.String())
	}
}

// White-label: one KMS may accept several brand issuers via a
// comma-separated KMS_EXPECTED_ISSUER. A token minted by ANY listed
// issuer must validate; one minted by an unlisted issuer must 401. This
// is the fix that lets the Lux-brand KMS accept lux.id tokens while still
// honoring hanzo.id (both brands share IAM signing keys).
func TestRequireOrgJWT_multiIssuerWhiteLabel(t *testing.T) {
	signer, jwks := newTestSigner(t)
	jwksHost := httptest.NewServer(jwksHandler(jwks))
	defer jwksHost.Close()

	// Note the whitespace + trailing slash — parseIssuers must normalize both.
	auth := newOrgJWTAuth(jwksHost.URL, "https://hanzo.id, https://lux.id/")

	mkTok := func(iss string) string {
		return signOrgClaims(t, signer, orgClaims{
			Claims: jwt.Claims{
				Issuer:  iss,
				Subject: "admin/sdm-kms",
				Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Owner: "admin",
			Name:  "sdm-kms",
			Type:  "application",
		})
	}

	cases := []struct {
		name string
		iss  string
		want int
	}{
		{"hanzo.id accepted", "https://hanzo.id", http.StatusOK},
		{"lux.id accepted", "https://lux.id", http.StatusOK},
		{"trailing slash tolerated", "https://lux.id/", http.StatusOK},
		{"unlisted issuer rejected", "https://evil.example.com", http.StatusUnauthorized},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/kms/orgs/sdm/secrets/staking/staker.crt", nil)
			req.Header.Set("Authorization", "Bearer "+mkTok(c.iss))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("iss=%s: got %d want %d; body=%s", c.iss, rec.Code, c.want, rec.Body.String())
			}
		})
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
