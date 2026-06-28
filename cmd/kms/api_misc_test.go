package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// miscDoArr issues a request expecting a bare-JSON-array body (e.g. GET
// /v1/relays returns TRelay[]), which the map-typed do() helper can't decode.
func miscDoArr(t *testing.T, method, url, bearer string) (int, []any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var out []any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// miscTestServer wires core + misc APIs and returns an org-scoped session token.
func miscTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	registerMiscAPI(mux, db)
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

// TestMiscListsAreEmptyArrays: every list-backed dashboard tab returns its
// correctly-keyed empty wrapper (HTTP 200, never 404) on a fresh instance.
func TestMiscListsAreEmptyArrays(t *testing.T) {
	srv, tok := miscTestServer(t)

	// gateways → {gateways: []}
	if code, b := do(t, "GET", srv.URL+"/v1/gateways", tok, nil); code != 200 || len(b["gateways"].([]any)) != 0 {
		t.Fatalf("gateways: %d %v", code, b)
	}
	// relays → bare []
	{
		code, arr := miscDoArr(t, "GET", srv.URL+"/v1/relays", tok)
		if code != 200 || len(arr) != 0 {
			t.Fatalf("relays: %d %v", code, arr)
		}
	}
	// notifications → {notifications: []}
	if code, b := do(t, "GET", srv.URL+"/v1/notifications/user", tok, nil); code != 200 || len(b["notifications"].([]any)) != 0 {
		t.Fatalf("notifications: %d %v", code, b)
	}
	// project-templates → {projectTemplates: []}
	if code, b := do(t, "GET", srv.URL+"/v1/project-templates", tok, nil); code != 200 || len(b["projectTemplates"].([]any)) != 0 {
		t.Fatalf("project-templates: %d %v", code, b)
	}
	// upgrade-path versions → {versions: []}
	if code, b := do(t, "GET", srv.URL+"/v1/upgrade-path/versions", tok, nil); code != 200 || len(b["versions"].([]any)) != 0 {
		t.Fatalf("upgrade-path: %d %v", code, b)
	}
	// vault migration configs → {configs: []}
	if code, b := do(t, "GET", srv.URL+"/v1/external-migration/vault/configs", tok, nil); code != 200 || len(b["configs"].([]any)) != 0 {
		t.Fatalf("vault configs: %d %v", code, b)
	}
	// vault introspection (external, empty) → {namespaces: []}
	if code, b := do(t, "GET", srv.URL+"/v1/external-migration/vault/namespaces", tok, nil); code != 200 || len(b["namespaces"].([]any)) != 0 {
		t.Fatalf("vault namespaces: %d %v", code, b)
	}
	// custom-migration-enabled → {enabled:false}
	if code, b := do(t, "GET", srv.URL+"/v3/external-migration/custom-migration-enabled/vault", tok, nil); code != 200 || b["enabled"] != false {
		t.Fatalf("custom-migration: %d %v", code, b)
	}

	// unauth is rejected on a representative route
	if code, _ := do(t, "GET", srv.URL+"/v1/gateways", "", nil); code != 401 {
		t.Fatalf("expected 401 unauth, got %d", code)
	}
}

// TestRateLimitRoundTrip: defaults on GET, persisted on PUT.
func TestRateLimitRoundTrip(t *testing.T) {
	srv, tok := miscTestServer(t)

	_, g := do(t, "GET", srv.URL+"/v1/rate-limit", tok, nil)
	rl := g["rateLimit"].(map[string]any)
	if rl["readRateLimit"].(float64) != 600 {
		t.Fatalf("default readRateLimit: %v", rl["readRateLimit"])
	}

	if code, _ := do(t, "PUT", srv.URL+"/v1/rate-limit", tok, map[string]any{
		"readRateLimit": 999, "writeRateLimit": 100, "secretsRateLimit": 50,
		"authRateLimit": 40, "inviteUserRateLimit": 10, "mfaRateLimit": 5, "publicEndpointLimit": 3,
	}); code != 200 {
		t.Fatalf("put rate-limit: %d", code)
	}
	_, g2 := do(t, "GET", srv.URL+"/v1/rate-limit", tok, nil)
	if g2["rateLimit"].(map[string]any)["readRateLimit"].(float64) != 999 {
		t.Fatalf("rate-limit not persisted: %v", g2)
	}
}

// TestProjectTemplateCRUD: create → list → get → patch → delete.
func TestProjectTemplateCRUD(t *testing.T) {
	srv, tok := miscTestServer(t)

	code, c := do(t, "POST", srv.URL+"/v1/project-templates", tok, map[string]any{"name": "Web App"})
	if code != 200 {
		t.Fatalf("create template: %d %v", code, c)
	}
	id := c["projectTemplate"].(map[string]any)["id"].(string)

	_, l := do(t, "GET", srv.URL+"/v1/project-templates", tok, nil)
	if len(l["projectTemplates"].([]any)) != 1 {
		t.Fatalf("expected 1 template")
	}

	if code, _ := do(t, "GET", srv.URL+"/v1/project-templates/"+id, tok, nil); code != 200 {
		t.Fatalf("get template: %d", code)
	}

	_, p := do(t, "PATCH", srv.URL+"/v1/project-templates/"+id, tok, map[string]any{"name": "Renamed"})
	if p["projectTemplate"].(map[string]any)["name"] != "Renamed" {
		t.Fatalf("patch name: %v", p)
	}

	if code, _ := do(t, "DELETE", srv.URL+"/v1/project-templates/"+id, tok, nil); code != 200 {
		t.Fatalf("delete template: %d", code)
	}
	_, l2 := do(t, "GET", srv.URL+"/v1/project-templates", tok, nil)
	if len(l2["projectTemplates"].([]any)) != 0 {
		t.Fatalf("expected 0 templates after delete")
	}
}

// TestUserActionRoundTrip: empty until set, echoed back after.
func TestUserActionRoundTrip(t *testing.T) {
	srv, tok := miscTestServer(t)

	_, g := do(t, "GET", srv.URL+"/v1/user-action?action=first_time_secrets_setting", tok, nil)
	if g["userAction"] != "" {
		t.Fatalf("expected empty userAction, got %v", g["userAction"])
	}
	if code, _ := do(t, "POST", srv.URL+"/v1/user-action", tok, map[string]any{"action": "first_time_secrets_setting"}); code != 200 {
		t.Fatalf("post user-action: %d", code)
	}
	_, g2 := do(t, "GET", srv.URL+"/v1/user-action?action=first_time_secrets_setting", tok, nil)
	if g2["userAction"] != "first_time_secrets_setting" {
		t.Fatalf("user-action not persisted: %v", g2)
	}
}

// TestSecretSharingFlow: create shared secret → list → public reveal → delete.
func TestSecretSharingFlow(t *testing.T) {
	srv, tok := miscTestServer(t)

	_, c := do(t, "POST", srv.URL+"/v1/secret-sharing/shared", tok, map[string]any{
		"name": "db creds", "secretValue": "s3cr3t", "accessType": "organization",
	})
	id := c["id"].(string)

	_, l := do(t, "GET", srv.URL+"/v1/secret-sharing/shared?offset=0&limit=25", tok, nil)
	if l["totalCount"].(float64) != 1 || len(l["secrets"].([]any)) != 1 {
		t.Fatalf("expected 1 shared secret: %v", l)
	}

	// public reveal serves the value (sealed at rest, plaintext on read)
	_, rev := do(t, "POST", srv.URL+"/v1/secret-sharing/shared/public/"+id, "", map[string]any{})
	if rev["secret"].(map[string]any)["secretValue"] != "s3cr3t" {
		t.Fatalf("public reveal: %v", rev)
	}

	if code, _ := do(t, "DELETE", srv.URL+"/v1/secret-sharing/shared/"+id, tok, nil); code != 200 {
		t.Fatalf("delete shared secret: %d", code)
	}
	_, l2 := do(t, "GET", srv.URL+"/v1/secret-sharing/shared?offset=0&limit=25", tok, nil)
	if l2["totalCount"].(float64) != 0 {
		t.Fatalf("expected 0 shared secrets after delete: %v", l2)
	}
}

// TestInviteOrgSignup: returns the success envelope with empty invite links.
func TestInviteOrgSignup(t *testing.T) {
	srv, tok := miscTestServer(t)
	code, b := do(t, "POST", srv.URL+"/v1/invite-org/signup", tok, map[string]any{
		"inviteeEmails": []string{"new@lux.network"}, "organizationRoleSlug": "member", "organizationId": "",
	})
	if code != 200 {
		t.Fatalf("invite-org signup: %d %v", code, b)
	}
	if _, ok := b["completeInviteLinks"].([]any); !ok {
		t.Fatalf("expected completeInviteLinks array: %v", b)
	}
}
