package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// secretsTestServer wires all three tiers and returns a scoped token + a project id.
func secretsTestServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	registerProjectAPI(mux, db)
	registerSecretsAPI(mux, db)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	do(t, "POST", srv.URL+"/v1/admin/signup", "", map[string]any{"email": "z@lux.network", "password": "S3cret-pw!", "organizationName": "Lux"})
	_, login := do(t, "POST", srv.URL+"/v1/auth/login", "", map[string]any{"email": "z@lux.network", "password": "S3cret-pw!"})
	_, sel := do(t, "POST", srv.URL+"/v1/auth/select-organization", login["accessToken"].(string), map[string]any{})
	tok := sel["token"].(string)
	_, cp := do(t, "POST", srv.URL+"/v1/projects", tok, map[string]any{"projectName": "App"})
	pid := cp["project"].(map[string]any)["id"].(string)
	return srv, tok, pid
}

// TestSecretsFlow: create secret (/v4) → list (/v1/secrets) → read value
// (dashboard) → update → delete; folder create/list/delete. Tier 3 — the real job.
func TestSecretsFlow(t *testing.T) {
	srv, tok, pid := secretsTestServer(t)

	// create a secret at root of the dev env
	code, cs := do(t, "POST", srv.URL+"/v4/secrets/DATABASE_URL", tok, map[string]any{
		"projectId": pid, "environment": "dev", "secretPath": "/", "secretValue": "postgres://x",
	})
	if code != 200 || cs["secret"].(map[string]any)["secretKey"] != "DATABASE_URL" {
		t.Fatalf("create secret: %d %v", code, cs)
	}

	// list secrets → DATABASE_URL present with value
	_, ls := do(t, "GET", srv.URL+"/v1/secrets?projectId="+pid+"&environment=dev&secretPath=%2F", tok, nil)
	secs := ls["secrets"].([]any)
	if len(secs) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secs))
	}
	s0 := secs[0].(map[string]any)
	if s0["secretKey"] != "DATABASE_URL" || s0["secretValue"] != "postgres://x" {
		t.Fatalf("secret round-trip wrong: %v", s0)
	}

	// read value via dashboard
	_, dv := do(t, "GET", srv.URL+"/v1/dashboard/secret-value?projectId="+pid+"&environment=dev&secretPath=%2F&secretKey=DATABASE_URL", tok, nil)
	if dv["secretValue"] != "postgres://x" {
		t.Fatalf("dashboard secret-value: %v", dv)
	}

	// env isolation: prod has no secrets
	_, lp := do(t, "GET", srv.URL+"/v1/secrets?projectId="+pid+"&environment=prod&secretPath=%2F", tok, nil)
	if len(lp["secrets"].([]any)) != 0 {
		t.Fatalf("prod env should be empty")
	}

	// update the secret
	do(t, "PATCH", srv.URL+"/v4/secrets/DATABASE_URL", tok, map[string]any{"projectId": pid, "environment": "dev", "secretPath": "/", "secretValue": "postgres://y"})
	_, dv2 := do(t, "GET", srv.URL+"/v1/dashboard/secret-value?projectId="+pid+"&environment=dev&secretPath=%2F&secretKey=DATABASE_URL", tok, nil)
	if dv2["secretValue"] != "postgres://y" {
		t.Fatalf("update didn't persist: %v", dv2)
	}

	// folders: create one at root, list it
	code, cf := do(t, "POST", srv.URL+"/v1/folders", tok, map[string]any{"projectId": pid, "environment": "dev", "name": "services", "path": "/"})
	if code != 200 {
		t.Fatalf("create folder: %d", code)
	}
	fid := cf["folder"].(map[string]any)["id"].(string)
	_, lf := do(t, "GET", srv.URL+"/v1/folders?projectId="+pid+"&environment=dev&path=%2F", tok, nil)
	if len(lf["folders"].([]any)) != 1 {
		t.Fatalf("expected 1 folder")
	}

	// dashboard secrets-details surfaces both secret + folder
	_, dd := do(t, "GET", srv.URL+"/v1/dashboard/secrets-details?projectId="+pid+"&environment=dev&secretPath=%2F", tok, nil)
	if len(dd["secrets"].([]any)) != 1 || len(dd["folders"].([]any)) != 1 {
		t.Fatalf("secrets-details wrong: %v", dd)
	}

	// delete folder + secret
	do(t, "DELETE", srv.URL+"/v2/folders/"+fid, tok, map[string]any{"projectId": pid, "environment": "dev", "path": "/"})
	do(t, "DELETE", srv.URL+"/v4/secrets/DATABASE_URL", tok, map[string]any{"projectId": pid, "environment": "dev", "secretPath": "/"})
	_, after := do(t, "GET", srv.URL+"/v1/dashboard/secrets-details?projectId="+pid+"&environment=dev&secretPath=%2F", tok, nil)
	if len(after["secrets"].([]any)) != 0 || len(after["folders"].([]any)) != 0 {
		t.Fatalf("delete didn't clear: %v", after)
	}

	// unauth rejected
	if code, _ := do(t, "GET", srv.URL+"/v1/secrets?projectId="+pid+"&environment=dev&secretPath=%2F", "", nil); code != 401 {
		t.Fatalf("expected 401 unauth, got %d", code)
	}
}
