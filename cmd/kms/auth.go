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
	"log"
	"net/http"
	"strings"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// orgClaims is the minimal JWT shape we authorize secrets reads/writes
// against. The org binding follows two flavors of IAM JWT:
//
//  1. User tokens (Google OAuth, password) — `owner` IS the org slug.
//     Example: a user signs in to organization=org1, the JWT
//     carries owner="org1", name="<username>".
//  2. Application tokens (client_credentials) — `owner`="admin"
//     (the parent record), and the application's `name` carries the
//     org as a prefix per the documented `<org>-<service>` naming
//     convention. Example: kms-app for org1 is name="org1-kms",
//     owner="admin", type="application".
//
// `roles` carries the IAM role list (kms-admin override).
type orgClaims struct {
	jwt.Claims
	Owner string   `json:"owner"`
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Tag   string   `json:"tag"`
	Roles []string `json:"roles"`
}

// orgs returns the set of org slugs this token is allowed to act for.
// Empty result = unauthenticated principal.
//
// Resolution order, first non-empty wins:
//   - Tag (operators set this on cross-cutting service apps when they
//     don't follow the <org>-<service> convention).
//   - For application tokens: prefix of Name up to the first '-'.
//   - Owner (the user-token case).
func (c *orgClaims) orgs() []string {
	out := []string{}
	if c.Tag != "" {
		out = append(out, c.Tag)
	}
	if c.Type == "application" && c.Name != "" {
		if i := strings.Index(c.Name, "-"); i > 0 {
			out = append(out, c.Name[:i])
		}
	}
	if c.Owner != "" && c.Owner != "admin" && c.Owner != "built-in" {
		out = append(out, c.Owner)
	}
	return out
}

// orgAuthorizes reports whether a token org slug authorizes access to a
// requested path org. The IAM `owner`/`name` claim carries the parent
// org (e.g. "lux"), but operators address project-scoped vaults under
// that org via a longer slug (e.g. the lux-operator queries KMS with
// org="lux-infra", its legacy projectSlug). A token for org "lux"
// must reach "lux-infra", "lux-mainnet", … — every project under it —
// without minting per-project tokens.
//
// Match rule (boundary-safe): the requested org is authorized when it
// equals the token org, OR the requested org is a sub-scope, i.e. it
// begins with `tokenOrg + "-"`. The '-' separator prevents a token for
// "lux" from leaking into an unrelated org like "luxx" — only true
// hyphen-delimited sub-scopes match.
func orgAuthorizes(tokenOrg, requested string) bool {
	return requested == tokenOrg ||
		strings.HasPrefix(requested, tokenOrg+"-")
}

// orgJWTAuth verifies tokens against the IAM JWKS. Issuer is checked
// (must equal expectedIssuer). Audience is NOT enforced because IAM
// client_credentials grants don't pin an audience to the resource
// server today — we rely on issuer + signature + owner-equals-org.
//
// jwksURL and expectedIssuer often differ in production: jwksURL is
// the in-cluster IAM URL (e.g. `http://iam.<namespace>.svc:8000/...`)
// for cheap fetches, expectedIssuer is the public host the JWT `iss`
// claim was minted with (e.g. `https://iam.<env>.<tenant>.example.com`).
// Splitting them is what keeps validation working when KMS sits behind
// a gateway that rewrites Host.
type orgJWTAuth struct {
	jwksURL string
	issuers []string // accepted `iss` values; a white-label KMS trusts every brand IAM that shares its signing keys
	cache   *jwksCache
}

// newOrgJWTAuth wires the validator from env. iamEndpoint is the URL
// KMS will fetch JWKS from (in-cluster); expectedIssuer is the
// `iss` claim value to enforce. If expectedIssuer is empty the
// iamEndpoint is used (matches the simple single-URL deployment).
func newOrgJWTAuth(iamEndpoint, expectedIssuer string) *orgJWTAuth {
	iam := strings.TrimRight(iamEndpoint, "/")
	issuers := parseIssuers(expectedIssuer)
	if len(issuers) == 0 {
		issuers = []string{iam}
	}
	jwksURL := iam + "/.well-known/jwks"
	return &orgJWTAuth{
		jwksURL: jwksURL,
		issuers: issuers,
		cache: &jwksCache{
			url:    jwksURL,
			ttl:    5 * time.Minute,
			client: &http.Client{Timeout: 10 * time.Second},
		},
	}
}

// parseIssuers normalizes KMS_EXPECTED_ISSUER into the set of accepted
// `iss` values. A comma-separated list lets one KMS serve multiple
// white-label brands that share IAM signing keys — e.g. a Lux-brand KMS
// trusting both `https://hanzo.id` and `https://lux.id`. Order-preserving,
// de-duplicated, trailing slashes trimmed.
func parseIssuers(s string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		v := strings.TrimRight(strings.TrimSpace(part), "/")
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// issuerAllowed reports whether a token's `iss` claim is one of the
// configured accepted issuers (trailing-slash insensitive).
func issuerAllowed(allowed []string, iss string) bool {
	iss = strings.TrimRight(iss, "/")
	for _, a := range allowed {
		if iss == a {
			return true
		}
	}
	return false
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
	// DEBUG: log JWKS state + token kid for diagnosis
	tokKid := ""
	if len(tok.Headers) > 0 {
		tokKid = tok.Headers[0].KeyID
	}
	kidList := make([]string, 0, len(keys.Keys))
	for _, k := range keys.Keys {
		kidList = append(kidList, k.KeyID)
	}
	log.Printf("kms: validate: tok kid=%s jwks kids=%v", tokKid, kidList)
	var claims orgClaims
	verified := false
	var lastErr error
	for _, k := range keys.Keys {
		if err := tok.Claims(k.Key, &claims); err == nil {
			verified = true
			break
		} else {
			log.Printf("kms: validate: kid=%s err=%v", k.KeyID, err)
			lastErr = err
		}
	}
	if !verified {
		if lastErr == nil {
			lastErr = errors.New("no key matched")
		}
		return nil, fmt.Errorf("verify: %w", lastErr)
	}
	// Time/expiry via go-jose; issuer is checked separately so we can accept
	// a set of white-label brand issuers (go-jose's Expected pins exactly one).
	if err := claims.Claims.Validate(jwt.Expected{Time: time.Now()}); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	if !issuerAllowed(a.issuers, claims.Issuer) {
		return nil, fmt.Errorf("validate: issuer %q not accepted", claims.Issuer)
	}
	if len(claims.orgs()) == 0 {
		return nil, errors.New("token has no resolvable org")
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
			// Log the actual reason so operators can see *why* a token
			// was rejected (signature mismatch vs issuer mismatch vs
			// expiry vs etc.). Body stays opaque to clients.
			log.Printf("kms: auth reject: %v (path=%s)", err, r.URL.Path)
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
		allowed := false
		for _, o := range claims.orgs() {
			if orgAuthorizes(o, org) {
				allowed = true
				break
			}
		}
		if !allowed && !hasRole(claims.Roles, "kms-admin") {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"statusCode": 403, "message": "token does not authorize this org",
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
