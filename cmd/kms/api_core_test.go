package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

func coreTestServer(t *testing.T) (*httptest.Server, *badger.DB) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, db
}

func do(t *testing.T, method, url, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// TestCoreAuthFlow exercises Tier 0+1 end to end: render-gate → first-admin
// signup → login → org select → identify user → list orgs, plus the negative
// paths (bad password, double-init, unauth).
func TestCoreAuthFlow(t *testing.T) {
	srv, _ := coreTestServer(t)

	// Tier 0: status renders.
	if code, body := do(t, "GET", srv.URL+"/v1/status", "", nil); code != 200 || body["message"] != "ok" {
		t.Fatalf("status: code=%d body=%v", code, body)
	}

	// admin/config before any user → initialized=false (SPA shows signup).
	_, cfg := do(t, "GET", srv.URL+"/v1/admin/config", "", nil)
	if c := cfg["config"].(map[string]any); c["initialized"] != false {
		t.Fatalf("expected initialized=false on fresh instance, got %v", c["initialized"])
	}

	// First-admin signup.
	code, signup := do(t, "POST", srv.URL+"/v1/admin/signup", "", map[string]any{
		"email": "z@lux.network", "password": "S3cret-pw!", "firstName": "Z", "organizationName": "Lux",
	})
	if code != 200 {
		t.Fatalf("signup: code=%d body=%v", code, signup)
	}
	if signup["token"] == nil || signup["user"] == nil || signup["organization"] == nil {
		t.Fatalf("signup missing token/user/org: %v", signup)
	}

	// admin/config now → initialized=true.
	_, cfg2 := do(t, "GET", srv.URL+"/v1/admin/config", "", nil)
	if c := cfg2["config"].(map[string]any); c["initialized"] != true {
		t.Fatalf("expected initialized=true after signup")
	}

	// Second signup is refused (instance already initialized).
	if code, _ := do(t, "POST", srv.URL+"/v1/admin/signup", "", map[string]any{"email": "x@y.z", "password": "p"}); code != 403 {
		t.Fatalf("expected 403 on double-init, got %d", code)
	}

	// Login with the right password.
	code, login := do(t, "POST", srv.URL+"/v1/auth/login", "", map[string]any{"email": "z@lux.network", "password": "S3cret-pw!"})
	if code != 200 || login["accessToken"] == nil || login["mfaEnabled"] != false {
		t.Fatalf("login: code=%d body=%v", code, login)
	}
	pre := login["accessToken"].(string)

	// Wrong password → 401.
	if code, _ := do(t, "POST", srv.URL+"/v1/auth/login", "", map[string]any{"email": "z@lux.network", "password": "nope"}); code != 401 {
		t.Fatalf("expected 401 on bad password, got %d", code)
	}

	// Select organization → scoped token.
	code, sel := do(t, "POST", srv.URL+"/v1/auth/select-organization", pre, map[string]any{})
	if code != 200 || sel["token"] == nil || sel["isMfaEnabled"] != false {
		t.Fatalf("select-org: code=%d body=%v", code, sel)
	}
	scoped := sel["token"].(string)

	// GET /v1/user with scoped token → identifies the admin.
	code, me := do(t, "GET", srv.URL+"/v1/user", scoped, nil)
	if code != 200 {
		t.Fatalf("user: code=%d", code)
	}
	u := me["user"].(map[string]any)
	if u["email"] != "z@lux.network" || u["superAdmin"] != true {
		t.Fatalf("user shape wrong: %v", u)
	}

	// Unauthenticated /v1/user → 401.
	if code, _ := do(t, "GET", srv.URL+"/v1/user", "", nil); code != 401 {
		t.Fatalf("expected 401 unauth, got %d", code)
	}

	// Org list.
	code, orgs := do(t, "GET", srv.URL+"/v1/organization", scoped, nil)
	if code != 200 {
		t.Fatalf("orgs: code=%d", code)
	}
	list := orgs["organizations"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["name"] != "Lux" {
		t.Fatalf("org list wrong: %v", list)
	}
}
