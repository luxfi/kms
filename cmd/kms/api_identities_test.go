package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// idTestServer wires core + identities APIs and returns an org-scoped token.
func idTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	registerIdentitiesAPI(mux, db)
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

// TestIdentityFlow: create (trailing-slash) → get → search → patch → universal-auth
// round-trip (records authMethods) → client-secret → delete-auth → delete identity.
func TestIdentityFlow(t *testing.T) {
	srv, tok := idTestServer(t)

	// create (note trailing slash — matches the SPA's useCreateOrgIdentity)
	code, ci := do(t, "POST", srv.URL+"/v1/identities/", tok, map[string]any{
		"name": "ci-bot", "hasDeleteProtection": true,
		"metadata": []any{map[string]any{"key": "team", "value": "infra"}},
	})
	if code != 200 {
		t.Fatalf("create identity: %d %v", code, ci)
	}
	it := ci["identity"].(map[string]any)
	id := it["id"].(string)
	if it["name"] != "ci-bot" {
		t.Fatalf("name: %v", it["name"])
	}
	if md := it["metadata"].([]any); len(md) != 1 || md[0].(map[string]any)["id"] == "" {
		t.Fatalf("metadata not stamped with id: %v", it["metadata"])
	}

	// get → org-membership wrapper shape with nested identity
	_, gi := do(t, "GET", srv.URL+"/v1/identities/"+id, tok, nil)
	if gi["identity"].(map[string]any)["identity"].(map[string]any)["id"] != id {
		t.Fatalf("get identity membership shape wrong: %v", gi)
	}

	// search → finds it, totalCount 1
	code, si := do(t, "POST", srv.URL+"/v1/identities/search", tok, map[string]any{"limit": 50, "offset": 0})
	if code != 200 || int(si["totalCount"].(float64)) != 1 || len(si["identities"].([]any)) != 1 {
		t.Fatalf("search: %d %v", code, si)
	}

	// patch name
	if code, _ := do(t, "PATCH", srv.URL+"/v1/identities/"+id, tok, map[string]any{"name": "ci-bot-2"}); code != 200 {
		t.Fatalf("patch identity failed")
	}

	// add universal-auth → method recorded on the identity
	code, ua := do(t, "POST", srv.URL+"/v1/auth/universal-auth/identities/"+id, tok, map[string]any{
		"accessTokenTTL": 3600,
	})
	if code != 200 {
		t.Fatalf("add universal-auth: %d %v", code, ua)
	}
	if ua["identityUniversalAuth"].(map[string]any)["identityId"] != id {
		t.Fatalf("universal-auth identityId not stamped: %v", ua)
	}

	// GET the auth config back
	if code, _ := do(t, "GET", srv.URL+"/v1/auth/universal-auth/identities/"+id, tok, nil); code != 200 {
		t.Fatalf("get universal-auth failed")
	}

	// identity now lists universal in authMethods
	_, gi2 := do(t, "GET", srv.URL+"/v1/org-identities/"+id, tok, nil)
	am := gi2["identity"].(map[string]any)["authMethods"].([]any)
	if len(am) != 1 || am[0] != "universal" {
		t.Fatalf("authMethods not recorded: %v", am)
	}

	// create a client secret → returns secret + data with prefix
	code, cs := do(t, "POST", srv.URL+"/v1/auth/universal-auth/identities/"+id+"/client-secrets", tok, map[string]any{"description": "ci"})
	if code != 200 || cs["clientSecret"].(string) == "" {
		t.Fatalf("client-secret create: %d %v", code, cs)
	}

	// delete universal-auth → method removed
	if code, _ := do(t, "DELETE", srv.URL+"/v1/auth/universal-auth/identities/"+id, tok, nil); code != 200 {
		t.Fatalf("delete universal-auth failed")
	}
	_, gi3 := do(t, "GET", srv.URL+"/v1/org-identities/"+id, tok, nil)
	if len(gi3["identity"].(map[string]any)["authMethods"].([]any)) != 0 {
		t.Fatalf("authMethods not cleared after delete")
	}

	// delete identity → search empty
	if code, _ := do(t, "DELETE", srv.URL+"/v1/identities/"+id, tok, nil); code != 200 {
		t.Fatalf("delete identity failed")
	}
	_, si2 := do(t, "POST", srv.URL+"/v1/identities/search", tok, map[string]any{})
	if int(si2["totalCount"].(float64)) != 0 {
		t.Fatalf("expected 0 identities after delete, got %v", si2["totalCount"])
	}

	// unauth rejected
	if code, _ := do(t, "POST", srv.URL+"/v1/identities/search", "", nil); code != 401 {
		t.Fatalf("expected 401 unauth, got %d", code)
	}
}

// TestIdentityProjectScope: project-scoped identity create/list + membership +
// additional-privilege CRUD, and empty-list tabs return 200 (never 404).
func TestIdentityProjectScope(t *testing.T) {
	srv, tok := idTestServer(t)
	pid := "proj-abc"

	// project identity create + list
	code, ci := do(t, "POST", srv.URL+"/v1/projects/"+pid+"/identities", tok, map[string]any{"name": "deploy-bot"})
	if code != 200 {
		t.Fatalf("create project identity: %d %v", code, ci)
	}
	iid := ci["identity"].(map[string]any)["id"].(string)
	_, li := do(t, "GET", srv.URL+"/v1/projects/"+pid+"/identities", tok, nil)
	if len(li["identities"].([]any)) != 1 {
		t.Fatalf("project identities list != 1: %v", li)
	}

	// membership upsert binds; available-identities + V2 list return 200 arrays
	if code, _ := do(t, "POST", srv.URL+"/v1/projects/"+pid+"/memberships/identities/"+iid, tok, map[string]any{"role": "admin"}); code != 200 {
		t.Fatalf("membership create failed")
	}
	for _, p := range []string{
		"/v1/projects/" + pid + "/memberships/available-identities",
		"/v1/projects/" + pid + "/memberships/identities",
		"/v1/projects/" + pid + "/identity-memberships/" + iid,
	} {
		if code, _ := do(t, "GET", srv.URL+p, tok, nil); code != 200 {
			t.Fatalf("expected 200 from %s, got %d", p, code)
		}
	}

	// additional privilege create → list → patch → delete
	code, cp := do(t, "POST", srv.URL+"/v1/identity-project-additional-privilege", tok, map[string]any{
		"identityId": iid, "projectId": pid, "slug": "read-secrets", "permissions": []any{},
	})
	if code != 200 {
		t.Fatalf("create privilege: %d %v", code, cp)
	}
	privID := cp["privilege"].(map[string]any)["id"].(string)

	_, lp := do(t, "GET", srv.URL+"/v1/identity-project-additional-privilege?projectId="+pid+"&identityId="+iid, tok, nil)
	if len(lp["privileges"].([]any)) != 1 {
		t.Fatalf("privileges list != 1: %v", lp)
	}
	if code, _ := do(t, "PATCH", srv.URL+"/v2/identity-project-additional-privilege/"+privID, tok, map[string]any{"slug": "read-only"}); code != 200 {
		t.Fatalf("patch privilege failed")
	}
	if code, _ := do(t, "DELETE", srv.URL+"/v2/identity-project-additional-privilege/"+privID, tok, nil); code != 200 {
		t.Fatalf("delete privilege failed")
	}
}

// TestIdentityAuthTemplates: template CRUD + search, usage tabs empty-200.
func TestIdentityAuthTemplates(t *testing.T) {
	srv, tok := idTestServer(t)

	code, ct := do(t, "POST", srv.URL+"/v1/identity-templates", tok, map[string]any{
		"name": "ldap-prod", "authMethod": "ldap",
		"templateFields": map[string]any{"url": "ldaps://x", "bindDN": "cn=a"},
	})
	if code != 200 {
		t.Fatalf("create template: %d %v", code, ct)
	}
	tid := ct["template"].(map[string]any)["id"].(string)

	_, sr := do(t, "GET", srv.URL+"/v1/identity-templates/search", tok, nil)
	if int(sr["totalCount"].(float64)) != 1 {
		t.Fatalf("template search totalCount != 1: %v", sr)
	}
	if code, _ := do(t, "GET", srv.URL+"/v1/identity-templates/"+tid, tok, nil); code != 200 {
		t.Fatalf("get template failed")
	}
	if code, _ := do(t, "PATCH", srv.URL+"/v1/identity-templates/"+tid, tok, map[string]any{"name": "ldap-prod-2"}); code != 200 {
		t.Fatalf("patch template failed")
	}
	if code, _ := do(t, "GET", srv.URL+"/v1/identity-templates/"+tid+"/usage", tok, nil); code != 200 {
		t.Fatalf("template usage tab should be 200")
	}
	if code, _ := do(t, "DELETE", srv.URL+"/v1/identity-templates/"+tid, tok, nil); code != 200 {
		t.Fatalf("delete template failed")
	}
}
