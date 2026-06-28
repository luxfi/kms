package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// dynRotTestServer wires core + dynrotation APIs and returns an org-scoped token.
func dynRotTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	registerDynRotationAPI(mux, db)
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

// TestDynamicSecretFlow: create → list → get(details w/ inputs) → patch → leases
// create/list/renew/revoke → delete.
func TestDynamicSecretFlow(t *testing.T) {
	srv, tok := dynRotTestServer(t)
	base := map[string]any{"projectSlug": "proj1", "environmentSlug": "dev", "path": "/"}

	// empty list (200 + empty array, never 404)
	if code, lr := do(t, "GET", srv.URL+"/v1/dynamic-secrets?projectSlug=proj1&environmentSlug=dev&path=/", tok, nil); code != 200 || len(lr["dynamicSecrets"].([]any)) != 0 {
		t.Fatalf("empty list: %d %v", code, lr)
	}

	// create
	code, cr := do(t, "POST", srv.URL+"/v1/dynamic-secrets", tok, map[string]any{
		"name": "db-creds", "projectSlug": "proj1", "environmentSlug": "dev", "path": "/",
		"defaultTTL": "1h", "maxTTL": "24h",
		"provider": map[string]any{"type": "sql-database", "inputs": map[string]any{"host": "db.local", "port": 5432}},
	})
	if code != 200 {
		t.Fatalf("create: %d %v", code, cr)
	}
	ds := cr["dynamicSecret"].(map[string]any)
	if ds["name"] != "db-creds" || ds["type"] != "sql-database" {
		t.Fatalf("bad create shape: %v", ds)
	}

	// list now has 1
	_, lr := do(t, "GET", srv.URL+"/v1/dynamic-secrets?projectSlug=proj1&environmentSlug=dev&path=/", tok, nil)
	if len(lr["dynamicSecrets"].([]any)) != 1 {
		t.Fatalf("list != 1: %v", lr)
	}

	// details include inputs
	_, gr := do(t, "GET", srv.URL+"/v1/dynamic-secrets/db-creds?projectSlug=proj1&environmentSlug=dev&path=/", tok, nil)
	det := gr["dynamicSecret"].(map[string]any)
	if det["inputs"].(map[string]any)["host"] != "db.local" {
		t.Fatalf("details missing inputs: %v", det)
	}

	// patch (rename + ttl)
	code, pr := do(t, "PATCH", srv.URL+"/v1/dynamic-secrets/db-creds", tok, map[string]any{
		"projectSlug": "proj1", "environmentSlug": "dev", "path": "/",
		"data": map[string]any{"newName": "db-creds-2", "defaultTTL": "2h"},
	})
	if code != 200 || pr["dynamicSecret"].(map[string]any)["name"] != "db-creds-2" {
		t.Fatalf("patch: %d %v", code, pr)
	}

	// leases: empty
	if _, llr := do(t, "GET", srv.URL+"/v1/dynamic-secrets/db-creds-2/leases?projectSlug=proj1&environmentSlug=dev&path=/", tok, nil); len(llr["leases"].([]any)) != 0 {
		t.Fatalf("expected 0 leases")
	}

	// create lease
	clBody := map[string]any{"dynamicSecretName": "db-creds-2", "projectSlug": "proj1", "environmentSlug": "dev", "path": "/", "ttl": "30m", "provider": "sql-database"}
	code, cl := do(t, "POST", srv.URL+"/v1/dynamic-secrets/leases", tok, clBody)
	if code != 200 {
		t.Fatalf("create lease: %d %v", code, cl)
	}
	lease := cl["lease"].(map[string]any)
	leaseID := lease["id"].(string)
	if _, ok := cl["data"]; !ok {
		t.Fatalf("lease response missing data envelope")
	}

	// list leases: 1
	if _, llr := do(t, "GET", srv.URL+"/v1/dynamic-secrets/db-creds-2/leases?projectSlug=proj1&environmentSlug=dev&path=/", tok, nil); len(llr["leases"].([]any)) != 1 {
		t.Fatalf("expected 1 lease")
	}

	// renew lease → version bumps
	_, rn := do(t, "POST", srv.URL+"/v1/dynamic-secrets/leases/"+leaseID+"/renew", tok, map[string]any{"ttl": "1h"})
	if rn["lease"].(map[string]any)["version"].(float64) != 2 {
		t.Fatalf("renew did not bump version: %v", rn)
	}

	// revoke lease
	if code, _ := do(t, "DELETE", srv.URL+"/v1/dynamic-secrets/leases/"+leaseID, tok, map[string]any{}); code != 200 {
		t.Fatalf("revoke lease failed")
	}

	// delete dynamic secret
	if code, _ := do(t, "DELETE", srv.URL+"/v1/dynamic-secrets/db-creds-2", tok, base); code != 200 {
		t.Fatalf("delete dyn secret failed")
	}
	if _, lr2 := do(t, "GET", srv.URL+"/v1/dynamic-secrets?projectSlug=proj1&environmentSlug=dev&path=/", tok, nil); len(lr2["dynamicSecrets"].([]any)) != 0 {
		t.Fatalf("expected empty list after delete")
	}

	// unauth rejected
	if code, _ := do(t, "GET", srv.URL+"/v1/dynamic-secrets?projectSlug=proj1&environmentSlug=dev&path=/", "", nil); code != 401 {
		t.Fatalf("expected 401, got %d", code)
	}
}

// TestSecretRotationV1Flow: providers (empty) → create → list → restart → delete.
func TestSecretRotationV1Flow(t *testing.T) {
	srv, tok := dynRotTestServer(t)

	// providers wrapper present + empty
	_, pv := do(t, "GET", srv.URL+"/v1/secret-rotation-providers/ws1", tok, nil)
	if _, ok := pv["providers"]; !ok {
		t.Fatalf("providers wrapper missing: %v", pv)
	}

	// empty list
	if _, lr := do(t, "GET", srv.URL+"/v1/secret-rotations?workspaceId=ws1", tok, nil); len(lr["secretRotations"].([]any)) != 0 {
		t.Fatalf("expected empty rotations")
	}

	// create
	code, cr := do(t, "POST", srv.URL+"/v1/secret-rotations", tok, map[string]any{
		"workspaceId": "ws1", "secretPath": "/", "environment": "dev",
		"interval": 24, "provider": "postgres", "inputs": map[string]any{}, "outputs": map[string]any{},
	})
	if code != 200 {
		t.Fatalf("create rotation: %d %v", code, cr)
	}
	rid := cr["secretRotation"].(map[string]any)["id"].(string)

	// list now 1
	if _, lr := do(t, "GET", srv.URL+"/v1/secret-rotations?workspaceId=ws1", tok, nil); len(lr["secretRotations"].([]any)) != 1 {
		t.Fatalf("expected 1 rotation")
	}

	// restart
	if code, _ := do(t, "POST", srv.URL+"/v1/secret-rotations/restart", tok, map[string]any{"id": rid}); code != 200 {
		t.Fatalf("restart failed")
	}

	// delete
	if code, _ := do(t, "DELETE", srv.URL+"/v1/secret-rotations/"+rid, tok, nil); code != 200 {
		t.Fatalf("delete rotation failed")
	}
}

// TestSecretRotationV2Flow: options → create → patch → rotate → reconcile →
// generated-credentials → delete.
func TestSecretRotationV2Flow(t *testing.T) {
	srv, tok := dynRotTestServer(t)

	// options: 13 entries, each with name/type/connection/template
	_, opts := do(t, "GET", srv.URL+"/v1/secret-rotations/options", tok, nil)
	list := opts["secretRotationOptions"].([]any)
	if len(list) != 13 {
		t.Fatalf("expected 13 rotation options, got %d", len(list))
	}
	first := list[0].(map[string]any)
	if first["type"] == nil || first["template"] == nil {
		t.Fatalf("option shape missing fields: %v", first)
	}

	// create
	code, cr := do(t, "POST", srv.URL+"/v2/secret-rotations/postgres-credentials", tok, map[string]any{
		"name": "pg-rot", "projectId": "proj1", "environment": "dev", "secretPath": "/",
		"connectionId": "conn1", "rotationInterval": 86400, "isAutoRotationEnabled": true,
		"parameters":     map[string]any{"username1": "a", "username2": "b"},
		"secretsMapping": map[string]any{"username": "U", "password": "P"},
	})
	if code != 200 {
		t.Fatalf("create v2: %d %v", code, cr)
	}
	rot := cr["secretRotation"].(map[string]any)
	rid := rot["id"].(string)
	if rot["type"] != "postgres-credentials" || rot["isAutoRotationEnabled"] != true {
		t.Fatalf("bad v2 shape: %v", rot)
	}
	if _, ok := rot["nextRotationAt"]; !ok {
		t.Fatalf("auto rotation missing nextRotationAt")
	}

	// patch
	code, pr := do(t, "PATCH", srv.URL+"/v2/secret-rotations/postgres-credentials/"+rid, tok, map[string]any{
		"projectId": "proj1", "secretPath": "/", "name": "pg-rot-2",
	})
	if code != 200 || pr["secretRotation"].(map[string]any)["name"] != "pg-rot-2" {
		t.Fatalf("patch v2: %d %v", code, pr)
	}

	// rotate-secrets
	if code, _ := do(t, "POST", srv.URL+"/v2/secret-rotations/postgres-credentials/"+rid+"/rotate-secrets", tok, map[string]any{}); code != 200 {
		t.Fatalf("rotate failed")
	}

	// reconcile
	_, rc := do(t, "POST", srv.URL+"/v2/secret-rotations/unix-linux-local-account/"+rid+"/reconcile", tok, map[string]any{})
	if rc["reconciled"] != true {
		t.Fatalf("reconcile shape: %v", rc)
	}

	// generated-credentials envelope
	_, gc := do(t, "GET", srv.URL+"/v2/secret-rotations/postgres-credentials/"+rid+"/generated-credentials", tok, nil)
	if _, ok := gc["generatedCredentials"]; !ok {
		t.Fatalf("generated-credentials missing: %v", gc)
	}

	// delete
	if code, _ := do(t, "DELETE", srv.URL+"/v2/secret-rotations/postgres-credentials/"+rid+"?deleteSecrets=true&revokeGeneratedCredentials=true", tok, nil); code != 200 {
		t.Fatalf("delete v2 failed")
	}
}
