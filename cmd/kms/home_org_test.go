// The deployment boundary: which tenants this KMS's secret store answers to.
//
// The secret keyspace is kms/secrets/{path}/{env}/{name} — it carries NO org.
// The {org} in the URL is therefore not a selector: it is caller-chosen, and a
// caller can only ever name an org its own token already authorizes, so it
// partitions nothing. What partitions the store is KMS_HOME_ORG.
//
// Why that matters here: one IAM issues valid tokens for every brand and ~90
// applications. Before the home-org gate, a token from ANY of them reached this
// store — the attack is not naming a FOREIGN org in the URL (that has always
// been 403), it is naming your OWN authorized org and asking for the victim's
// PATH. These tests pin that exact request shape closed, and pin the gate itself
// as the thing doing the closing.

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

// tenantFixture stands up one stub IAM and a secrets surface over a real store,
// plus a minter for validly-signed tokens of any org. Both the home tenant and
// the foreign tenant get REAL tokens from the SAME issuer — that is the whole
// point: the attacker is not forging anything, it holds a legitimate token from
// the shared IAM.
type tenantFixture struct {
	url   string
	mint  func(owner string, roles ...string) string
	close func()
}

func newTenantFixture(t *testing.T, homeOrgs ...string) *tenantFixture {
	t.Helper()
	signer, jwks := newTestSigner(t)
	iam := httptest.NewServer(jwksHandler(jwks))
	auth := newOrgJWTAuth(iam.URL, "")
	auth.homeOrgs = homeOrgs

	mux := http.NewServeMux()
	registerSecretRoutes(mux, auth, newTestSecretStore(t))
	srv := httptest.NewServer(mux)

	return &tenantFixture{
		url: srv.URL,
		mint: func(owner string, roles ...string) string {
			return signOrgClaims(t, signer, orgClaims{
				Claims: jwt.Claims{
					Issuer:  iam.URL,
					Subject: "svc",
					Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
				Owner: owner,
				Roles: roles,
			})
		},
		close: func() { srv.Close(); iam.Close() },
	}
}

func (f *tenantFixture) do(t *testing.T, method, path, bearer, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// The crown-jewel path used throughout: the key that signs this platform's own
// IAM tokens. If a foreign tenant can read this one, it can mint identities.
const (
	victimPath  = "iam-signing-keys"
	victimName  = "cert-hanzo"
	victimValue = "test-signing-material"
)

func (f *tenantFixture) seedVictim(t *testing.T, homeBearer string) {
	t.Helper()
	code, body := f.do(t, "POST", "/v1/kms/secrets", homeBearer,
		`{"path":"`+victimPath+`","name":"`+victimName+`","env":"prod","value":"`+victimValue+`"}`)
	if code/100 != 2 {
		t.Fatalf("seed = %d: %s", code, body)
	}
}

// A foreign tenant holding a VALID token from the shared IAM must not reach the
// home tenant's store — through any door, by any verb. Each case names its own
// authorized org where the URL takes one, which is the shape that used to work.
func TestHomeOrg_ForeignTenantCannotReachTheStore(t *testing.T) {
	f := newTenantFixture(t, "hanzo")
	defer f.close()

	home, foreign := f.mint("hanzo"), f.mint("acme")
	f.seedVictim(t, home)

	// Control: the home tenant reads its own secret. If this ever stops being
	// 200 the negatives below prove nothing.
	if code, body := f.do(t, "GET", "/v1/kms/orgs/hanzo/secrets/"+victimPath+"/"+victimName+"?env=prod", home, ""); code != 200 {
		t.Fatalf("home tenant read = %d, want 200: %s", code, body)
	}

	for _, tc := range []struct{ name, method, path string }{
		// Red's exploit: the attacker's OWN authorized org in the URL, the
		// victim's path after it.
		{"own-org label, victim path", "GET", "/v1/kms/orgs/acme/secrets/" + victimPath + "/" + victimName + "?env=prod"},
		// The org-less door, where there is no URL org to reconcile at all.
		{"org-less door", "GET", "/v1/kms/secrets/" + victimPath + "/" + victimName + "?env=prod"},
		// Enumeration is a read too: the coordinate list is a map of the store.
		{"enumerate, own-org label", "GET", "/v1/kms/orgs/acme/secrets?path=" + victimPath + "&env=prod"},
		{"enumerate, org-less door", "GET", "/v1/kms/secrets?path=" + victimPath + "&env=prod"},
		// Write and delete are the destructive half of the same hole.
		{"delete, own-org label", "DELETE", "/v1/kms/orgs/acme/secrets/" + victimPath + "/" + victimName + "?env=prod"},
		{"delete, org-less door", "DELETE", "/v1/kms/secrets/" + victimPath + "/" + victimName + "?env=prod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := f.do(t, tc.method, tc.path, foreign, "")
			if code != http.StatusForbidden {
				t.Fatalf("%s %s = %d, want 403; body=%s", tc.method, tc.path, code, body)
			}
			if strings.Contains(body, victimValue) {
				t.Fatal("response carried the secret value")
			}
		})
	}

	// A foreign write must not land either — a tenant that cannot read must not
	// be able to overwrite a credential the platform depends on.
	if code, body := f.do(t, "POST", "/v1/kms/secrets", foreign,
		`{"path":"`+victimPath+`","name":"`+victimName+`","env":"prod","value":"attacker"}`); code != http.StatusForbidden {
		t.Fatalf("foreign write = %d, want 403: %s", code, body)
	}
	// …and the home tenant's value is untouched.
	if code, body := f.do(t, "GET", "/v1/kms/orgs/hanzo/secrets/"+victimPath+"/"+victimName+"?env=prod", home, ""); code != 200 || !strings.Contains(body, victimValue) {
		t.Fatalf("home value after foreign write = %d: %s", code, body)
	}
}

// The gate is what closes it. With no KMS_HOME_ORG the foreign tenant reads the
// crown jewel — this is the vulnerability, executed. Pinning it here means a
// future refactor that quietly drops homeOrgs fails a test instead of shipping.
func TestHomeOrg_UnconfiguredLeavesTheStoreOpen(t *testing.T) {
	f := newTenantFixture(t) // no home org — the state the deployment ran in
	defer f.close()

	home, foreign := f.mint("hanzo"), f.mint("acme")
	f.seedVictim(t, home)

	code, body := f.do(t, "GET", "/v1/kms/orgs/acme/secrets/"+victimPath+"/"+victimName+"?env=prod", foreign, "")
	if code != 200 || !strings.Contains(body, victimValue) {
		t.Fatalf("ungated read = %d, want 200 with the value: %s", code, body)
	}
	// Which is exactly why main refuses to boot the secret surface unconfigured.
	if err := requireHomeOrgConfig(nil); err == nil {
		t.Fatal("requireHomeOrgConfig(nil) = nil; the surface would serve ungated")
	}
}

// A sub-scope token is not the parent. A token minted for a project org under
// the home org reaches only what its own org authorizes — it does not inherit
// the whole deployment store. Fail-closed is the correct direction here: the
// parent reaches its projects, a project never reaches the parent.
func TestHomeOrg_SubScopeTokenDoesNotInheritTheParentStore(t *testing.T) {
	f := newTenantFixture(t, "hanzo")
	defer f.close()

	home := f.mint("hanzo")
	f.seedVictim(t, home)

	if code, body := f.do(t, "GET", "/v1/kms/secrets/"+victimPath+"/"+victimName+"?env=prod", f.mint("hanzo-infra"), ""); code != http.StatusForbidden {
		t.Fatalf("sub-scope read = %d, want 403: %s", code, body)
	}
	// A brand whose slug merely shares a prefix is not a sub-scope either.
	if code, body := f.do(t, "GET", "/v1/kms/secrets/"+victimPath+"/"+victimName+"?env=prod", f.mint("hanzox"), ""); code != http.StatusForbidden {
		t.Fatalf("prefix-collision read = %d, want 403: %s", code, body)
	}
}

// kms-admin is the platform's cross-cutting override for audit and rotation and
// deliberately crosses the boundary. It is a role granted in IAM, not something
// a tenant can assert about itself, so it is the one intended way through.
func TestHomeOrg_KMSAdminCrossesTheBoundary(t *testing.T) {
	f := newTenantFixture(t, "hanzo")
	defer f.close()

	f.seedVictim(t, f.mint("hanzo"))

	if code, body := f.do(t, "GET", "/v1/kms/secrets/"+victimPath+"/"+victimName+"?env=prod", f.mint("acme", roleKMSAdmin), ""); code != 200 {
		t.Fatalf("kms-admin read = %d, want 200: %s", code, body)
	}
}

// parseHomeOrgs feeds the gate; a spelling that silently parsed to the empty set
// would make the gate inert while looking configured.
func TestParseHomeOrgs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"hanzo", []string{"hanzo"}},
		{" hanzo , lux ", []string{"hanzo", "lux"}},
		{"hanzo,hanzo", []string{"hanzo"}},
		{"", []string{}},
		{" , ", []string{}},
	} {
		got := parseHomeOrgs(tc.in)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("parseHomeOrgs(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	// An empty parse must be refused at boot, not served.
	if err := requireHomeOrgConfig(parseHomeOrgs("")); err == nil {
		t.Error("empty KMS_HOME_ORG accepted; want boot refusal")
	}
}
