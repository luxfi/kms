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

			// This path is now the tenant surface's GET (org-less secrets),
			// which resolves against the STORE and never the process env:
			// unauthenticated → 401 at the guard; authenticated → 404 from the
			// store, because no secret named after an env var exists. A 200
			// would mean an env-echoing route came back — still the failure
			// this test exists to catch, together with the sentinel assertion
			// above, which holds regardless of status.
			want := http.StatusNotFound
			if c.bearer == "" {
				want = http.StatusUnauthorized
			}
			if resp.StatusCode != want {
				t.Fatalf("env-named path: got status %d, want %d (store-resolved, never env)", resp.StatusCode, want)
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

// TestSecretRoutes_ListAndGetDoNotShadow pins the two GET patterns apart.
//
// `GET .../secrets` (the collection) and `GET .../secrets/{rest...}` (one
// secret) are registered on the same mux. ServeMux routes the bare collection
// to the first and anything below it to the second; if that ever inverts, list
// would swallow every get, or get would 400 on the bare collection because
// {rest...} has no slash to split. Both directions are asserted here.
func TestSecretRoutes_ListAndGetDoNotShadow(t *testing.T) {
	auth, bearer, cleanup := newTestKeyAuth(t, roleKMSAdmin)
	defer cleanup()
	secStore := newTestSecretStore(t)

	if err := secStore.Put(&store.Secret{
		Path: "gateway", Name: "routes", Env: "default", Ciphertext: []byte("yaml: here"),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	mux := http.NewServeMux()
	registerSecretRoutes(mux, auth, secStore)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	get := func(path string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// The collection lists names — it must NOT fall through to the {rest...}
	// handler, which would 400 for want of a slash.
	code, body := get("/v1/kms/orgs/hanzo/secrets?path=gateway&env=default")
	if code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", code, body)
	}
	if !strings.Contains(body, `"names"`) || !strings.Contains(body, "routes") {
		t.Errorf("list body = %s, want a names array containing the seeded secret", body)
	}

	// A path below the collection still reaches the single-secret handler.
	code, body = get("/v1/kms/orgs/hanzo/secrets/gateway/routes?env=default")
	if code != http.StatusOK {
		t.Fatalf("get: status %d, body %s", code, body)
	}
	if !strings.Contains(body, "yaml: here") {
		t.Errorf("get body = %s, want the secret value", body)
	}

	// Listing an empty path is an empty array, never null — clients range over it.
	code, body = get("/v1/kms/orgs/hanzo/secrets?path=nothing-here&env=default")
	if code != http.StatusOK || !strings.Contains(body, `"names":[]`) {
		t.Errorf("empty list = %d %s, want 200 with an empty array", code, body)
	}
}

// TestSecretRoutes_RootLevelSecretIsAddressable pins the round trip for a
// secret stored at the root of an org (empty path).
//
// The store keys on (path, name) and accepts path="", so List and POST have
// always handled root-level secrets. GET and DELETE split `{rest...}` on the
// last "/" and used to 400 "path and name required" when there wasn't one —
// which made every root-level secret permanently unreachable while List
// cheerfully reported it. That was not academic: the whole `bootnode` org in
// prod stores its secrets flat (DATABASE_URL, API_KEY, APP_SECRET, ...), so the
// kms-operator could enumerate them and never fetch one, and 54 KMSSecret CRs
// sat failing.
func TestSecretRoutes_RootLevelSecretIsAddressable(t *testing.T) {
	auth, bearer, cleanup := newTestKeyAuth(t, roleKMSAdmin)
	defer cleanup()
	secStore := newTestSecretStore(t)

	if err := secStore.Put(&store.Secret{
		Path: "", Name: "DATABASE_URL", Env: "prod", Ciphertext: []byte("postgres://x"),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	mux := http.NewServeMux()
	registerSecretRoutes(mux, auth, secStore)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	do := func(method, path string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// List sees it at the root — this always worked.
	code, body := do(http.MethodGet, "/v1/kms/orgs/hanzo/secrets?path=&env=prod")
	if code != http.StatusOK || !strings.Contains(body, "DATABASE_URL") {
		t.Fatalf("list root: status %d, body %s", code, body)
	}

	// ...and GET must be able to fetch what list just advertised.
	code, body = do(http.MethodGet, "/v1/kms/orgs/hanzo/secrets/DATABASE_URL?env=prod")
	if code != http.StatusOK {
		t.Fatalf("get root-level secret: status %d, body %s (list advertised it; get must resolve it)", code, body)
	}
	if !strings.Contains(body, "postgres://x") {
		t.Errorf("get body = %s, want the seeded value", body)
	}

	// A trailing-slash-only rest has no name and stays a 400.
	if code, _ := do(http.MethodGet, "/v1/kms/orgs/hanzo/secrets/?env=prod"); code != http.StatusBadRequest {
		t.Errorf("empty name: status %d, want 400", code)
	}

	// DELETE had the identical split, so it gets the identical guarantee.
	if code, body := do(http.MethodDelete, "/v1/kms/orgs/hanzo/secrets/DATABASE_URL?env=prod"); code != http.StatusOK {
		t.Fatalf("delete root-level secret: status %d, body %s", code, body)
	}
	if code, _ := do(http.MethodGet, "/v1/kms/orgs/hanzo/secrets/DATABASE_URL?env=prod"); code != http.StatusNotFound {
		t.Errorf("after delete: status %d, want 404", code)
	}
}
