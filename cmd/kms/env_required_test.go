// Regression coverage for the one-way env contract on secret writes. env is
// a first-class component of the storage key (kms/secrets/{path}/{env}/{name});
// a POST that omits env must fail loud (400) rather than silently landing in a
// "default" bucket that project/env/path readers (the kms-operator, cluster
// syncs) never resolve. That split is what let an IAM z-password land in
// env=default while prod kept serving the stale value.
//
// Secret values are never printed — round-trip fidelity is asserted by
// comparing SHA-256 digests.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luxfi/kms/pkg/store"
	badger "github.com/luxfi/zapdb"
)

func newTestSecretStore(t *testing.T) *store.SecretStore {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions(t.TempDir()).WithLogger(nil))
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return store.NewSecretStore(db)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func postJSON(t *testing.T, url string, body map[string]string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

// A write that omits env fails loud (400) and lands nowhere.
func TestPutSecret_WithoutEnv_400(t *testing.T) {
	secStore := newTestSecretStore(t)
	srv := httptest.NewServer(putSecretHandler(secStore))
	defer srv.Close()

	resp := postJSON(t, srv.URL, map[string]string{
		"path": "iam-passwords", "name": "Z_PASSWORD", "value": "irrelevant",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("omitted-env write: want 400, got %d", resp.StatusCode)
	}
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	if msg, _ := m["message"].(string); !strings.Contains(msg, "env is required") {
		t.Fatalf("want env-required message, got %q", msg)
	}

	// The rejected write must not have populated the default bucket.
	if _, err := secStore.Get("iam-passwords", "Z_PASSWORD", "default"); err == nil {
		t.Fatal("omitted-env write must not land in env=default, but a record exists there")
	}
}

// A write with an explicit env is readable through the exact project/env/path
// resolution the kms-operator uses, and is not visible in any other bucket.
func TestPutSecret_WithEnvProd_StoredUnderProd(t *testing.T) {
	secStore := newTestSecretStore(t)
	srv := httptest.NewServer(putSecretHandler(secStore))
	defer srv.Close()

	const secret = "z-password-98f3-do-not-log"
	want := sha256hex(secret)

	resp := postJSON(t, srv.URL, map[string]string{
		"path": "iam-passwords", "name": "Z_PASSWORD", "env": "prod", "value": secret,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("explicit-env write: want 201, got %d", resp.StatusCode)
	}

	// Operator resolution: env=prod, path=/iam-passwords, name=Z_PASSWORD.
	got, err := secStore.Get("iam-passwords", "Z_PASSWORD", "prod")
	if err != nil {
		t.Fatalf("project/env/path read (prod): %v", err)
	}
	if h := sha256hex(string(got.Ciphertext)); h != want {
		t.Fatalf("round-trip value digest mismatch: got %s want %s", h, want)
	}

	// No cross-bucket bleed: env=default must not resolve the prod write.
	if _, err := secStore.Get("iam-passwords", "Z_PASSWORD", "default"); err == nil {
		t.Fatal("prod write must not be visible in env=default")
	}
}
