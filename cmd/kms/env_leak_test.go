// Regression coverage for the deleted env-var fetch route.
//
// A prior `GET /v1/kms/secrets/{name}` handler read os.Getenv(name) and
// returned it UNWRAPPED — registered with no auth middleware — so anyone who
// reached :8080 past the network boundary (NetworkPolicy gap, port-forward,
// pod compromise, SSRF) could exfiltrate the KMS process environment: the
// KMS_MASTER_KEY_B64 root REK that protects every per-secret DEK, MPC_TOKEN,
// the S3 backup keys, IAM/OIDC client secrets. On the live lux-kms-go pod
// KMS_MASTER_KEY_B64 is populated, so the leak was CRITICAL, gated only by the
// network.
//
// The route is gone. Secrets are served ONLY through the org-scoped,
// JWT-gated routes registerSecretRoutes installs (and the ZAP wire). These
// tests pin that invariant against the REAL production registrar: no path
// echoes process env, with or without a valid admin bearer. If anyone
// re-introduces such a route, the leak assertion fails.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luxfi/kms/pkg/store"
)

// A sentinel that must never appear in any HTTP response body. Installed into
// the process env under the exact name the deleted route would have echoed.
const leakSentinel = "MASTER-KEY-LEAK-CANARY-c1a9f0e7-do-not-return"

// TestSecretRoutes_NoEnvVarLeak drives the production secret surface and proves
// the vestigial env-fetch path leaks nothing — the fix for the HIGH/CRITICAL
// os.Getenv hole. Fail-closed: unauthenticated AND authenticated-admin both get
// no env echo.
func TestSecretRoutes_NoEnvVarLeak(t *testing.T) {
	// Populate the crown-jewel env var the deleted route echoed. registerSecretRoutes
	// reads no env at all; the value is here only so a canary would surface if it did.
	t.Setenv("KMS_MASTER_KEY_B64", leakSentinel)

	auth, bearer, cleanup := newTestKeyAuth(t, roleKMSAdmin)
	defer cleanup()
	secStore := newTestSecretStore(t)

	// The SAME registrar main() calls — this is the real route set, not a mock.
	mux := http.NewServeMux()
	registerSecretRoutes(mux, auth, secStore)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The vestigial env-fetch path, probed the way an attacker on :8080 would.
	url := srv.URL + "/v1/kms/secrets/KMS_MASTER_KEY_B64"

	cases := []struct {
		name   string
		bearer string
	}{
		{"unauthenticated", ""},
		{"authenticated kms-admin", bearer}, // even a valid admin gets no env echo
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				t.Fatalf("build req: %v", err)
			}
			if c.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+c.bearer)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			// Load-bearing assertion: the process-env value is never returned,
			// regardless of status code.
			if strings.Contains(string(body), leakSentinel) {
				t.Fatalf("LEAK: response body contained the process-env master key (status=%d)", resp.StatusCode)
			}

			// No handler serves this path anymore → 404. A 200 would mean an
			// env-echoing route came back.
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("deleted env route: got status %d, want 404 (no handler)", resp.StatusCode)
			}
		})
	}
}

// TestSecretRoutes_OrgScopedReadStillWorks proves the extraction into
// registerSecretRoutes didn't break the real read path, and that a read returns
// the STORED value — never process env. Guards against a "delete broke the good
// path" regression.
func TestSecretRoutes_OrgScopedReadStillWorks(t *testing.T) {
	auth, bearer, cleanup := newTestKeyAuth(t, roleKMSAdmin)
	defer cleanup()
	secStore := newTestSecretStore(t)

	if err := secStore.Put(&store.Secret{
		Name: "API_KEY", Path: "svc", Env: "prod", Ciphertext: []byte("stored-value-ok"),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	mux := http.NewServeMux()
	registerSecretRoutes(mux, auth, secStore)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/kms/orgs/operator-org/secrets/svc/API_KEY?env=prod", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("org read: got %d want 200", resp.StatusCode)
	}
	var m map[string]map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := m["secret"]["value"]; got != "stored-value-ok" {
		t.Fatalf("org read value: got %q want stored-value-ok", got)
	}
}

// TestSecretRoutes_UnauthOrgReadRejected confirms the surviving org-scoped read
// still fails closed without a bearer — the extraction preserved requireOrgJWT.
func TestSecretRoutes_UnauthOrgReadRejected(t *testing.T) {
	auth, _, cleanup := newTestKeyAuth(t, roleKMSAdmin)
	defer cleanup()
	secStore := newTestSecretStore(t)

	mux := http.NewServeMux()
	registerSecretRoutes(mux, auth, secStore)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/kms/orgs/operator-org/secrets/svc/API_KEY?env=prod")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth org read: got %d want 401", resp.StatusCode)
	}
}
