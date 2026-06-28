package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// kmsKmipTestServer wires core + project + kmskmip APIs and returns an
// org-scoped session token.
func kmsKmipTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	registerProjectAPI(mux, db)
	registerKmsKmipAPI(mux, db)
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

// TestCmekFlow: create CMEK → list → encrypt → decrypt round-trip → delete.
func TestCmekFlow(t *testing.T) {
	srv, tok := kmsKmipTestServer(t)

	// create
	code, cr := do(t, "POST", srv.URL+"/v1/cmek/keys", tok, map[string]any{
		"projectId": "proj-1", "name": "app-key", "keyUsage": "encrypt-decrypt",
		"encryptionAlgorithm": "aes-256-gcm",
	})
	if code != 200 {
		t.Fatalf("create cmek: %d %v", code, cr)
	}
	key := cr["key"].(map[string]any)
	keyID := key["id"].(string)
	if key["name"] != "app-key" {
		t.Fatalf("name: %v", key["name"])
	}

	// list (project-scoped)
	_, lr := do(t, "GET", srv.URL+"/v1/cmek/keys?projectId=proj-1", tok, nil)
	if len(lr["keys"].([]any)) != 1 {
		t.Fatalf("expected 1 key, got %v", lr["keys"])
	}

	// encrypt
	plain := base64.StdEncoding.EncodeToString([]byte("hello-secret"))
	code, er := do(t, "POST", srv.URL+"/v1/cmek/keys/"+keyID+"/encrypt", tok, map[string]any{"plaintext": plain})
	if code != 200 {
		t.Fatalf("encrypt: %d %v", code, er)
	}
	ct := er["ciphertext"].(string)
	if ct == "" {
		t.Fatalf("empty ciphertext")
	}

	// decrypt → round-trip
	code, dr := do(t, "POST", srv.URL+"/v1/cmek/keys/"+keyID+"/decrypt", tok, map[string]any{"ciphertext": ct})
	if code != 200 {
		t.Fatalf("decrypt: %d %v", code, dr)
	}
	if dr["plaintext"].(string) != plain {
		t.Fatalf("round-trip mismatch: got %v want %v", dr["plaintext"], plain)
	}

	// delete
	if code, _ := do(t, "DELETE", srv.URL+"/v1/cmek/keys/"+keyID, tok, nil); code != 200 {
		t.Fatalf("delete cmek failed")
	}
	_, lr2 := do(t, "GET", srv.URL+"/v1/cmek/keys?projectId=proj-1", tok, nil)
	if len(lr2["keys"].([]any)) != 0 {
		t.Fatalf("expected 0 keys after delete")
	}

	// unauth rejected
	if code, _ := do(t, "GET", srv.URL+"/v1/cmek/keys?projectId=proj-1", "", nil); code != 401 {
		t.Fatalf("expected 401 unauth, got %d", code)
	}
}

// TestKmipFlow: create client → list → patch → cert stub → delete; org config.
func TestKmipFlow(t *testing.T) {
	srv, tok := kmsKmipTestServer(t)

	// org config (unconfigured → empty chains, 200)
	if code, gc := do(t, "GET", srv.URL+"/v1/kmip", tok, nil); code != 200 || gc["serverCertificateChain"] != "" {
		t.Fatalf("get org kmip: %d %v", code, gc)
	}

	// create client
	code, cr := do(t, "POST", srv.URL+"/v1/kmip/clients", tok, map[string]any{
		"projectId": "proj-1", "name": "kmip-1", "permissions": []string{"create", "get"},
	})
	if code != 200 {
		t.Fatalf("create kmip client: %d %v", code, cr)
	}
	cli := cr["kmipClient"].(map[string]any)
	id := cli["id"].(string)
	if len(cli["permissions"].([]any)) != 2 {
		t.Fatalf("permissions: %v", cli["permissions"])
	}

	// list
	_, lr := do(t, "GET", srv.URL+"/v1/kmip/clients?projectId=proj-1", tok, nil)
	if len(lr["kmipClients"].([]any)) != 1 {
		t.Fatalf("expected 1 kmip client")
	}

	// patch
	if code, _ := do(t, "PATCH", srv.URL+"/v1/kmip/clients/"+id, tok, map[string]any{"description": "updated"}); code != 200 {
		t.Fatalf("patch kmip client failed")
	}

	// cert stub
	if code, cc := do(t, "POST", srv.URL+"/v1/kmip/clients/"+id+"/certificates", tok, map[string]any{"keyAlgorithm": "RSA_2048", "ttl": "1h"}); code != 200 || cc["serialNumber"] == "" {
		t.Fatalf("kmip cert: %d %v", code, cc)
	}

	// delete
	if code, _ := do(t, "DELETE", srv.URL+"/v1/kmip/clients/"+id, tok, nil); code != 200 {
		t.Fatalf("delete kmip client failed")
	}
}

// TestExternalKmsFlow: create → list → get → patch → project KMS select → delete.
func TestExternalKmsFlow(t *testing.T) {
	srv, tok := kmsKmipTestServer(t)

	// empty list
	if _, lr := do(t, "GET", srv.URL+"/v1/external-kms", tok, nil); len(lr["externalKmsList"].([]any)) != 0 {
		t.Fatalf("expected empty external-kms list")
	}

	// create (aws)
	code, cr := do(t, "POST", srv.URL+"/v1/external-kms/aws", tok, map[string]any{
		"name": "aws-kms", "description": "prod", "configuration": map[string]any{"awsRegion": "us-east-1"},
	})
	if code != 200 {
		t.Fatalf("create external kms: %d %v", code, cr)
	}
	ext := cr["externalKms"].(map[string]any)
	kmsID := ext["id"].(string)
	if ext["externalKms"].(map[string]any)["provider"] != "aws" {
		t.Fatalf("provider: %v", ext["externalKms"])
	}

	// list now has 1
	_, lr := do(t, "GET", srv.URL+"/v1/external-kms", tok, nil)
	if len(lr["externalKmsList"].([]any)) != 1 {
		t.Fatalf("expected 1 external kms")
	}

	// get by provider/id
	if code, _ := do(t, "GET", srv.URL+"/v1/external-kms/aws/"+kmsID, tok, nil); code != 200 {
		t.Fatalf("get external kms failed")
	}

	// patch
	if code, _ := do(t, "PATCH", srv.URL+"/v1/external-kms/aws/"+kmsID, tok, map[string]any{"description": "staging"}); code != 200 {
		t.Fatalf("patch external kms failed")
	}

	// project KMS selection: default internal → set external → read back
	if _, gp := do(t, "GET", srv.URL+"/v1/projects/proj-1/kms", tok, nil); gp["secretManagerKmsKey"].(map[string]any)["id"] != "internal" {
		t.Fatalf("default project kms not internal: %v", gp)
	}
	if code, _ := do(t, "PATCH", srv.URL+"/v1/projects/proj-1/kms", tok, map[string]any{"kms": map[string]any{"type": "external", "kmsId": kmsID}}); code != 200 {
		t.Fatalf("patch project kms failed")
	}
	_, gp2 := do(t, "GET", srv.URL+"/v1/projects/proj-1/kms", tok, nil)
	if gp2["secretManagerKmsKey"].(map[string]any)["id"] != kmsID {
		t.Fatalf("project kms not switched to external: %v", gp2)
	}

	// gcp keys probe returns empty set
	if code, gk := do(t, "POST", srv.URL+"/v1/external-kms/gcp/keys", tok, map[string]any{"authMethod": "credential", "region": "us"}); code != 200 || len(gk["keys"].([]any)) != 0 {
		t.Fatalf("gcp keys probe: %d %v", code, gk)
	}

	// delete
	if code, _ := do(t, "DELETE", srv.URL+"/v1/external-kms/aws/"+kmsID, tok, nil); code != 200 {
		t.Fatalf("delete external kms failed")
	}
}
