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
// public: /healthz, /health, /v1/kms/health{,z}, /v1/kms/auth/login
// and the OIDC routes. The
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

// authorizesHome reports whether these claims may touch THIS deployment's
// secret store.
//
// The store is one flat keyspace — kms/secrets/{path}/{env}/{name}, no org
// component (see registerSecretRoutes). So the {org} in the URL scopes NOTHING:
// it is caller-chosen, and requireOrgJWT only ever lets a caller name an org its
// own token already authorizes. A caller naming its OWN org and then asking for
// another tenant's PATH therefore passed every check and read the record — the
// URL org check is not a tenant boundary, it only proves the caller didn't lie
// about itself.
//
// The boundary is this: one IAM signs tokens for every brand and ~90
// applications, so "validly signed" says nothing about which store you may
// reach. KMS_HOME_ORG names the org(s) that own THIS deployment's store, and a
// caller is admitted only when its own org authorizes one of them — by the same
// boundary-safe rule the URL org uses, so a parent org reaches the store it owns
// while a sub-scope or a foreign brand does not.
//
// kms-admin / superadmin is the cross-cutting override for platform audit and
// rotation. It is granted in IAM, so it is not something a tenant can assert
// about itself.
//
// A nil/empty homeOrgs set means "unconfigured", and the gate goes inert. That
// state is unreachable in a real deployment: main refuses to boot the secret
// surface without it (requireHomeOrgConfig).
func (a *orgJWTAuth) authorizesHome(c *orgClaims) bool {
	if hasRole(c.Roles, roleKMSAdmin) || hasRole(c.Roles, roleSuperadmin) {
		return true
	}
	for _, home := range a.homeOrgs {
		for _, o := range c.orgs() {
			if orgAuthorizes(o, home) {
				return true
			}
		}
	}
	return false
}

// requireHomeOrgConfig returns an error when the secret surface would run with
// no home org configured. main calls it after wiring auth and refuses to boot on
// error: an unconfigured gate authorizes any valid IAM token from any org, which
// is precisely the state this fix exists to end. Failing to boot leaves the
// prior pod serving — a stalled rollout, never an open store.
func requireHomeOrgConfig(homeOrgs []string) error {
	if len(homeOrgs) == 0 {
		return errors.New("KMS_HOME_ORG is required: the secret store belongs to the org that owns this deployment (e.g. KMS_HOME_ORG=hanzo). Without it the secret surface would authorize any valid IAM token from any org")
	}
	return nil
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

	// homeOrgs is the set of orgs this deployment's secret store belongs to
	// (KMS_HOME_ORG). It is the tenant boundary — see authorizesHome for why the
	// URL org is not one. Set at the composition root; main refuses to boot with
	// it empty.
	homeOrgs []string
}

// newOrgJWTAuth wires the validator from env. iamEndpoint is the URL
// KMS will fetch JWKS from (in-cluster); expectedIssuer is the
// `iss` claim value to enforce. If expectedIssuer is empty the
// iamEndpoint is used (matches the simple single-URL deployment).
// iamJWKSURL builds the IAM JWKS endpoint.
//
// The path is NOT "/.well-known/jwks". IAM serves a 200 text/html SPA catch-all for
// any unregistered path, so a wrong path here is never a 404 — it is HTML that fails
// to unmarshal, so no key is ever loaded, every token check fails, and the only
// symptom reaching an operator is `login HTTP 401 invalid credentials` on a
// KMSSecret, which points at credentials rather than at this. lux-k8s sat that way
// from 2026-03-17 to 2026-08-01 with 50 of 53 secrets unsynced.
//
// /v1/iam/... is the canonical host-relative prefix (HIP-0111) and is already what
// IAM_TOKEN_PATH defaults to; JWKS was simply left behind on the legacy root path.
// Overridable for the same reason the token path is.
func iamJWKSURL(iamEndpoint string) string {
	return strings.TrimRight(iamEndpoint, "/") + envOr("IAM_JWKS_PATH", "/v1/iam/.well-known/jwks")
}

func newOrgJWTAuth(iamEndpoint, expectedIssuer string) *orgJWTAuth {
	iam := strings.TrimRight(iamEndpoint, "/")
	issuers := parseIssuers(expectedIssuer)
	if len(issuers) == 0 {
		issuers = []string{iam}
	}
	jwksURL := iamJWKSURL(iam)
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

// normalizeSet splits a comma-separated env value into an order-preserving,
// de-duplicated set, applying norm to each entry BEFORE the empty/dup check so
// two spellings that normalize to the same value collapse to one. One helper
// backs both the issuer list and the home-org list — exactly one way to parse a
// CSV env into a set.
func normalizeSet(s string, norm func(string) string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		v := norm(strings.TrimSpace(part))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// parseHomeOrgs normalizes KMS_HOME_ORG into the set of orgs this deployment's
// secret store belongs to. Comma-separated for the rare shared-store case; a
// single value ("hanzo") is the norm. Trailing slashes are meaningless to an org
// slug, so unlike issuers they are NOT trimmed — an org is a bare slug, and
// silently accepting "hanzo/" would let a typo name a different tenant.
func parseHomeOrgs(s string) []string {
	return normalizeSet(s, func(v string) string { return v })
}

// parseIssuers normalizes KMS_EXPECTED_ISSUER into the set of accepted
// `iss` values. A comma-separated list lets one KMS serve multiple
// white-label brands that share IAM signing keys — e.g. a Lux-brand KMS
// trusting both `https://hanzo.id` and `https://lux.id`. Order-preserving,
// de-duplicated, trailing slashes trimmed.
func parseIssuers(s string) []string {
	return normalizeSet(s, func(v string) string { return strings.TrimRight(v, "/") })
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
	tokKid := ""
	if len(tok.Headers) > 0 {
		tokKid = tok.Headers[0].KeyID
	}
	var claims orgClaims
	verified := false
	var lastErr error
	// Try the key the token names first (kid header) — the common case is one
	// exact match, so verification is a single signature check instead of
	// brute-forcing every brand cert. A miss on a non-matching key is expected,
	// not an event: no per-attempt logging (it produced one line per brand cert
	// per request — millions/day); the returned error carries the diagnosis.
	for _, k := range keys.Keys {
		if tokKid != "" && k.KeyID != tokKid {
			continue
		}
		if err := tok.Claims(k.Key, &claims); err == nil {
			verified = true
			break
		} else {
			lastErr = err
		}
	}
	if !verified && tokKid != "" {
		// kid named but didn't verify (rotation skew) — legacy fallback across
		// the remaining keys before failing.
		for _, k := range keys.Keys {
			if k.KeyID == tokKid {
				continue
			}
			if err := tok.Claims(k.Key, &claims); err == nil {
				verified = true
				break
			} else {
				lastErr = err
			}
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
		// The check above only proves the caller did not lie about WHO it is —
		// the org it named is one its own token already authorizes. The store is
		// org-flat, so that says nothing about WHICH store it may read: naming
		// your own org and then another tenant's path reached the record. This
		// is the tenant boundary. Inert when unconfigured (main boot-guards it).
		if len(a.homeOrgs) > 0 && !a.authorizesHome(claims) {
			log.Printf("kms: home-org reject: orgs=%v (path=%s)", claims.orgs(), r.URL.Path)
			writeJSON(w, http.StatusForbidden, map[string]any{
				"statusCode": 403, "message": "token does not authorize this KMS",
			})
			return
		}
		next(w, r)
	}
}

// requireJWT gates the org-less secret surface (/v1/kms/secrets*). There is no
// URL org to reconcile, so the tenant boundary here is the only one that ever
// mattered: the TOKEN's org against this deployment's home org. The store
// partition is the deployment (one KMS per plane), so a caller is admitted only
// when its own org authorizes a home org — otherwise the shared IAM's token for
// any of ~90 apps across every brand would read the whole store through this
// door. Inert only when homeOrgs is unconfigured, which main refuses to boot.
func (a *orgJWTAuth) requireJWT(next http.HandlerFunc) http.HandlerFunc {
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
			log.Printf("kms: auth reject: %v (path=%s)", err, r.URL.Path)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"statusCode": 401, "message": "invalid token",
			})
			return
		}
		if len(a.homeOrgs) > 0 && !a.authorizesHome(claims) {
			log.Printf("kms: home-org reject: orgs=%v (path=%s)", claims.orgs(), r.URL.Path)
			writeJSON(w, http.StatusForbidden, map[string]any{
				"statusCode": 403, "message": "token does not authorize this KMS",
			})
			return
		}
		next(w, r)
	}
}

// requireKeyAuth wraps a validator-key-management handler (keygen, sign,
// rotate, and the key-metadata reads) with app-layer IAM JWT verification.
//
// Unlike requireOrgJWT there is no {org} path param to bind to: validator
// key custody is a cluster-admin operation, not an org-scoped secret. It is
// gated on the kms-admin role (superadmin is the break-glass override),
// granted in IAM — the same authority the zapserver /v1/sdk sign op and the
// mpc KMS handlers enforce for their write path.
//
// Fail closed at every step:
//   - nil receiver (IAM not wired)     => 503, never open
//   - missing / malformed bearer       => 401
//   - bad signature / issuer / expiry  => 401
//   - authenticated but missing role   => 403
//
// The JWT signature is verified HERE against IAM's JWKS. We deliberately do
// NOT trust a gateway-injected role header (e.g. X-IAM-Roles): a caller that
// reaches :8080 directly — NetworkPolicy gap, port-forward, pod compromise,
// SSRF — could forge such a header but cannot forge an IAM signature. This
// is the defense-in-depth layer that stands even if the NetworkPolicy fails,
// not a replacement for it.
func (a *orgJWTAuth) requireKeyAuth(next http.HandlerFunc) http.HandlerFunc {
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
			log.Printf("kms: key-auth reject: %v (path=%s)", err, r.URL.Path)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"statusCode": 401, "message": "invalid token",
			})
			return
		}
		if !hasRole(claims.Roles, roleKMSAdmin) && !hasRole(claims.Roles, roleSuperadmin) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"statusCode": 403, "message": "kms key operations require the kms-admin role",
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
