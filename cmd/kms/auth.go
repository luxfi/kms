// JWT-backed authorization for the secrets surface.
//
// Every /v1/kms/orgs/{org}/secrets/* request must carry an
// `Authorization: Bearer <jwt>` header. The JWT is validated against
// IAM's JWKS (signature, issuer, expiry) and the `owner` claim must
// equal the {org} path param. Service tokens minted by IAM via
// client_credentials carry the application's owner — that's the org
// boundary we enforce.
//
// kms-admin role override: a token whose `roles` includes "kms-admin"
// can read/write any org. The role is granted in IAM, not configured
// here.
//
// Public endpoints (no Bearer required) are wired in main.go and stay
// public: /healthz, /health, /v1/kms/health{,z}, /v1/admin/config,
// /v1/kms/auth/login, the OIDC routes, and the embedded SPA. The
// middleware below only wraps the secrets handlers.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// orgClaims is the minimal JWT shape we authorize secrets reads/writes
// against. `owner` scopes to the org slug; `roles` carries the IAM
// role list (kms-admin override).
type orgClaims struct {
	jwt.Claims
	Owner string   `json:"owner"`
	Roles []string `json:"roles"`
}

// orgJWTAuth verifies tokens against the IAM JWKS. Issuer is checked
// (must equal iamEndpoint). Audience is NOT enforced because IAM
// client_credentials grants don't pin an audience to the resource
// server today — we rely on issuer + signature + owner-equals-org.
type orgJWTAuth struct {
	jwksURL string
	issuer  string
	cache   *jwksCache
}

func newOrgJWTAuth(iamEndpoint string) *orgJWTAuth {
	iam := strings.TrimRight(iamEndpoint, "/")
	return &orgJWTAuth{
		jwksURL: iam + "/.well-known/jwks",
		issuer:  iam,
		cache: &jwksCache{
			url:    iam + "/.well-known/jwks",
			ttl:    5 * time.Minute,
			client: &http.Client{Timeout: 10 * time.Second},
		},
	}
}

func (a *orgJWTAuth) validate(ctx context.Context, raw string) (*orgClaims, error) {
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
	keys, err := a.cache.get(ctx)
	if err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	var claims orgClaims
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
		Time:   time.Now(),
		Issuer: a.issuer,
	}
	if err := claims.Claims.Validate(exp); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	if claims.Owner == "" {
		return nil, errors.New("missing owner claim")
	}
	return &claims, nil
}

// requireOrgJWT wraps a handler, ensuring the request carries a valid
// IAM-signed JWT whose `owner` matches the {org} path param (or whose
// `roles` includes "kms-admin"). On failure the request is rejected
// with 401 (missing/malformed) or 403 (token belongs to another org).
//
// nil receiver short-circuits to 503 — operators who haven't wired
// IAM_ENDPOINT can see the misconfiguration in their logs and probes
// instead of a wide-open store.
func (a *orgJWTAuth) requireOrgJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"statusCode": 503, "message": "auth not configured",
			})
			return
		}
		raw := bearerToken(r)
		if raw == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"statusCode": 401, "message": "missing bearer token",
			})
			return
		}
		claims, err := a.validate(r.Context(), raw)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"statusCode": 401, "message": "invalid token",
			})
			return
		}
		org := r.PathValue("org")
		if org == "" {
			// Should never happen — the route pattern requires {org}.
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"statusCode": 400, "message": "org required",
			})
			return
		}
		if claims.Owner != org && !hasRole(claims.Roles, "kms-admin") {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"statusCode": 403, "message": "token owner does not match org",
			})
			return
		}
		next(w, r)
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

