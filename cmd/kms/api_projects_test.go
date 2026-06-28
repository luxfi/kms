package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// projTestServer wires core + project APIs and returns a logged-in,
// org-scoped session token to drive the project flow.
func projTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	registerProjectAPI(mux, db)
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

// TestProjectFlow: create project (default envs) → list → get → add/patch/delete
// env → my-workspaces → env-folder-tree. Tier 2.
func TestProjectFlow(t *testing.T) {
	srv, tok := projTestServer(t)

	// create
	code, cp := do(t, "POST", srv.URL+"/v1/projects", tok, map[string]any{"projectName": "App Secrets"})
	if code != 200 {
		t.Fatalf("create project: %d %v", code, cp)
	}
	p := cp["project"].(map[string]any)
	pid := p["id"].(string)
	if p["slug"] != "app-secrets" {
		t.Fatalf("slug: %v", p["slug"])
	}
	if envs := p["environments"].([]any); len(envs) != 3 {
		t.Fatalf("expected 3 default envs, got %d", len(envs))
	}

	// list
	_, lp := do(t, "GET", srv.URL+"/v1/projects", tok, nil)
	if len(lp["projects"].([]any)) != 1 {
		t.Fatalf("list projects != 1")
	}

	// get
	if code, _ := do(t, "GET", srv.URL+"/v1/projects/"+pid, tok, nil); code != 200 {
		t.Fatalf("get project: %d", code)
	}

	// add env
	code, ae := do(t, "POST", srv.URL+"/v1/projects/"+pid+"/environments", tok, map[string]any{"name": "QA", "slug": "qa"})
	if code != 200 || ae["environment"].(map[string]any)["slug"] != "qa" {
		t.Fatalf("add env: %d %v", code, ae)
	}
	envID := ae["environment"].(map[string]any)["id"].(string)

	// project now has 4 envs
	_, gp := do(t, "GET", srv.URL+"/v1/projects/"+pid, tok, nil)
	if len(gp["project"].(map[string]any)["environments"].([]any)) != 4 {
		t.Fatalf("expected 4 envs after add")
	}

	// patch env
	if code, _ := do(t, "PATCH", srv.URL+"/v1/projects/"+pid+"/environments/"+envID, tok, map[string]any{"name": "Quality"}); code != 200 {
		t.Fatalf("patch env failed")
	}

	// delete env → back to 3
	if code, _ := do(t, "DELETE", srv.URL+"/v1/projects/"+pid+"/environments/"+envID, tok, nil); code != 200 {
		t.Fatalf("delete env failed")
	}
	_, gp2 := do(t, "GET", srv.URL+"/v1/projects/"+pid, tok, nil)
	if len(gp2["project"].(map[string]any)["environments"].([]any)) != 3 {
		t.Fatalf("expected 3 envs after delete")
	}

	// env-folder-tree has an entry per env slug
	_, tree := do(t, "GET", srv.URL+"/v1/projects/"+pid+"/environment-folder-tree", tok, nil)
	if _, ok := tree["dev"]; !ok {
		t.Fatalf("env-folder-tree missing dev env: %v", tree)
	}

	// unauth is rejected
	if code, _ := do(t, "GET", srv.URL+"/v1/projects", "", nil); code != 401 {
		t.Fatalf("expected 401 unauth, got %d", code)
	}
}
