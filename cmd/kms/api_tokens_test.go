package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// tokensTestServer wires core + tokens APIs and returns an org-scoped session.
func tokensTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	registerTokensAPI(mux, db) // must not panic on duplicate patterns
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if code, _ := do(t, "POST", srv.URL+"/v1/admin/signup", "", map[string]any{
		"email": "z@lux.network", "password": "S3cret-pw!", "organizationName": "Lux",
	}); code != 200 {
		t.Fatalf("signup: %d", code)
	}
	_, login := do(t, "POST", srv.URL+"/v1/auth/login", "", map[string]any{"email": "z@lux.network", "password": "S3cret-pw!"})
	_, sel := do(t, "POST", srv.URL+"/v1/auth/select-organization", login["accessToken"].(string), map[string]any{})
	return srv, sel["token"].(string)
}

func TestTokensUnauthorized(t *testing.T) {
	srv, _ := tokensTestServer(t)
	if code, _ := do(t, "POST", srv.URL+"/v1/api-key", "", map[string]any{"name": "x"}); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", code)
	}
}

func TestAPIKeyCRUD(t *testing.T) {
	srv, tok := tokensTestServer(t)

	code, cr := do(t, "POST", srv.URL+"/v1/api-key", tok, map[string]any{"name": "ci"})
	if code != 200 {
		t.Fatalf("create api-key: %d %v", code, cr)
	}
	if cr["apiKey"] == nil || cr["apiKey"].(string) == "" {
		t.Fatalf("expected one-time apiKey secret")
	}
	kd := cr["apiKeyData"].(map[string]any)
	id := kd["id"].(string)
	if kd["name"] != "ci" {
		t.Fatalf("name: %v", kd["name"])
	}

	_, up := do(t, "PATCH", srv.URL+"/v3/api-key/"+id, tok, map[string]any{"name": "ci-renamed"})
	if up["apiKeyData"].(map[string]any)["name"] != "ci-renamed" {
		t.Fatalf("rename: %v", up)
	}

	if code, _ := do(t, "DELETE", srv.URL+"/v3/api-key/"+id, tok, nil); code != 200 {
		t.Fatalf("delete api-key: %d", code)
	}
	if code, _ := do(t, "PATCH", srv.URL+"/v3/api-key/"+id, tok, map[string]any{"name": "x"}); code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", code)
	}
}

func TestServiceTokenCRUD(t *testing.T) {
	srv, tok := tokensTestServer(t)
	pid := "proj-1"

	// list empty (wrapper present, array empty — never 404)
	code, le := do(t, "GET", srv.URL+"/v1/projects/"+pid+"/service-token-data", tok, nil)
	if code != 200 {
		t.Fatalf("list empty: %d", code)
	}
	if len(le["serviceTokenData"].([]any)) != 0 {
		t.Fatalf("expected empty service-token list")
	}

	// create (trailing-slash route)
	code, cr := do(t, "POST", srv.URL+"/v1/service-token/", tok, map[string]any{
		"name": "deploy", "workspaceId": pid, "expiresIn": 3600,
		"scopes": []map[string]any{{"environment": "dev", "secretPath": "/"}},
	})
	if code != 200 {
		t.Fatalf("create service-token: %d %v", code, cr)
	}
	if cr["serviceToken"].(string) == "" {
		t.Fatalf("expected serviceToken value")
	}
	std := cr["serviceTokenData"].(map[string]any)
	id := std["id"].(string)
	if std["projectId"] != pid || len(std["scopes"].([]any)) != 1 {
		t.Fatalf("service-token shape: %v", std)
	}

	// list now has 1
	_, l2 := do(t, "GET", srv.URL+"/v1/projects/"+pid+"/service-token-data", tok, nil)
	if len(l2["serviceTokenData"].([]any)) != 1 {
		t.Fatalf("expected 1 service-token after create")
	}

	// delete
	_, del := do(t, "DELETE", srv.URL+"/v2/service-token/"+id, tok, nil)
	if del["serviceTokenData"].(map[string]any)["id"] != id {
		t.Fatalf("delete returns the token: %v", del)
	}
	_, l3 := do(t, "GET", srv.URL+"/v1/projects/"+pid+"/service-token-data", tok, nil)
	if len(l3["serviceTokenData"].([]any)) != 0 {
		t.Fatalf("expected empty after delete")
	}
}

func TestBotLifecycle(t *testing.T) {
	srv, tok := tokensTestServer(t)
	wid := "ws-1"

	// GET auto-materializes an inactive bot (never 404)
	code, g := do(t, "GET", srv.URL+"/v1/bot/"+wid, tok, nil)
	if code != 200 {
		t.Fatalf("get bot: %d", code)
	}
	b := g["bot"].(map[string]any)
	if b["workspace"] != wid || b["isActive"] != false {
		t.Fatalf("bot shape: %v", b)
	}

	// activate
	_, pa := do(t, "PATCH", srv.URL+"/v1/bot/"+wid+"/active", tok, map[string]any{"isActive": true})
	if pa["bot"].(map[string]any)["isActive"] != true {
		t.Fatalf("activate: %v", pa)
	}

	// persisted active
	_, g2 := do(t, "GET", srv.URL+"/v1/bot/"+wid, tok, nil)
	if g2["bot"].(map[string]any)["isActive"] != true {
		t.Fatalf("active not persisted")
	}
}

func TestAssumePrivileges(t *testing.T) {
	srv, tok := tokensTestServer(t)
	pid := "proj-1"
	if code, p := do(t, "POST", srv.URL+"/v1/projects/"+pid+"/assume-privileges", tok, map[string]any{
		"actorId": "u-1", "actorType": "user",
	}); code != 200 || p["message"] == nil {
		t.Fatalf("assume: %d %v", code, p)
	}
	if code, p := do(t, "DELETE", srv.URL+"/v1/projects/"+pid+"/assume-privileges", tok, nil); code != 200 || p["message"] == nil {
		t.Fatalf("exit assume: %d %v", code, p)
	}
}

func TestProjectUserAdditionalPrivilege(t *testing.T) {
	srv, tok := tokensTestServer(t)
	mid := "membership-1"

	// list empty
	code, le := do(t, "GET", srv.URL+"/v1/user-project-additional-privilege?projectMembershipId="+mid, tok, nil)
	if code != 200 || len(le["privileges"].([]any)) != 0 {
		t.Fatalf("list empty: %d %v", code, le)
	}

	// create permanent privilege with arbitrary permissions array (round-trips)
	_, cr := do(t, "POST", srv.URL+"/v1/user-project-additional-privilege", tok, map[string]any{
		"projectMembershipId": mid, "slug": "read-secrets",
		"permissions": []map[string]any{{"action": "read", "subject": "secrets"}},
		"type":        map[string]any{"isTemporary": false},
	})
	priv := cr["privilege"].(map[string]any)
	id := priv["id"].(string)
	if priv["isTemporary"] != false {
		t.Fatalf("expected permanent")
	}
	if perms := priv["permissions"].([]any); len(perms) != 1 {
		t.Fatalf("permissions round-trip: %v", priv["permissions"])
	}

	// get
	if code, _ := do(t, "GET", srv.URL+"/v1/user-project-additional-privilege/"+id, tok, nil); code != 200 {
		t.Fatalf("get privilege: %d", code)
	}

	// list now 1
	_, l2 := do(t, "GET", srv.URL+"/v1/user-project-additional-privilege?projectMembershipId="+mid, tok, nil)
	if len(l2["privileges"].([]any)) != 1 {
		t.Fatalf("expected 1 privilege")
	}

	// update to temporary
	_, up := do(t, "PATCH", srv.URL+"/v1/user-project-additional-privilege/"+id, tok, map[string]any{
		"projectMembershipId": mid,
		"type": map[string]any{
			"isTemporary": true, "temporaryMode": "relative",
			"temporaryRange": "1h", "temporaryAccessStartTime": "2026-01-01T00:00:00Z",
		},
	})
	if up["privilege"].(map[string]any)["isTemporary"] != true {
		t.Fatalf("update to temporary: %v", up)
	}

	// delete
	if code, _ := do(t, "DELETE", srv.URL+"/v1/user-project-additional-privilege/"+id, tok, nil); code != 200 {
		t.Fatalf("delete privilege: %d", code)
	}
	if code, _ := do(t, "GET", srv.URL+"/v1/user-project-additional-privilege/"+id, tok, nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", code)
	}
}
