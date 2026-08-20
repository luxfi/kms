package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The org-less tenant surface: the SAME handlers as the org-addressed routes,
// addressed without an org in the URL — the tenant is the token's. Every verb
// gets its negative (unauthenticated 401), the round-trip proves the store, and
// the old org-addressed shape reads the SAME record back (one store behind both
// surfaces; the compat routes go once ATS + the browser extension sweep).
func TestSecretRoutes_TenantSurface(t *testing.T) {
	auth, bearer, cleanup := newTestKeyAuth(t, roleKMSAdmin)
	defer cleanup()
	secStore := newTestSecretStore(t)
	mux := http.NewServeMux()
	registerSecretRoutes(mux, auth, secStore, testREK())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// NEGATIVE: unauthenticated is refused on every verb of the new surface.
	for _, tc := range []struct{ method, path string }{
		{"GET", "/v1/kms/secrets"},
		{"GET", "/v1/kms/secrets/ci/TOKEN"},
		{"POST", "/v1/kms/secrets"},
		{"DELETE", "/v1/kms/secrets/ci/TOKEN"},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path+"?env=default", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s unauthenticated = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}

	do := func(method, path, body string) (*http.Response, string) {
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
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
		return resp, string(b)
	}

	// Round-trip on the new surface — no org in any URL.
	if resp, b := do("POST", "/v1/kms/secrets", `{"path":"ci","name":"TOKEN","env":"default","value":"v1"}`); resp.StatusCode/100 != 2 {
		t.Fatalf("put = %d: %s", resp.StatusCode, b)
	}
	if resp, b := do("GET", "/v1/kms/secrets/ci/TOKEN?env=default", ""); resp.StatusCode != 200 || !strings.Contains(b, "v1") {
		t.Fatalf("get = %d: %s", resp.StatusCode, b)
	}
	if resp, b := do("GET", "/v1/kms/secrets?path=ci&env=default", ""); resp.StatusCode != 200 || !strings.Contains(b, "TOKEN") {
		t.Fatalf("list = %d: %s", resp.StatusCode, b)
	}

	// One store behind both surfaces: the org-addressed compat route reads the
	// SAME record (kms-admin role authorizes any org segment).
	if resp, b := do("GET", "/v1/kms/orgs/acme/secrets/ci/TOKEN?env=default", ""); resp.StatusCode != 200 {
		t.Fatalf("compat get = %d: %s", resp.StatusCode, b)
	}

	if resp, b := do("DELETE", "/v1/kms/secrets/ci/TOKEN?env=default", ""); resp.StatusCode/100 != 2 {
		t.Fatalf("delete = %d: %s", resp.StatusCode, b)
	}
	if resp, _ := do("GET", "/v1/kms/secrets/ci/TOKEN?env=default", ""); resp.StatusCode != 404 {
		t.Fatalf("get after delete = %d, want 404", resp.StatusCode)
	}
}
