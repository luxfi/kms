package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/store"
)

func setup(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	// Mock MPC daemon.
	keygenCount := 0
	mpcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/reshare"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "reshare_complete"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/transactions"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"signature": "sig123"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/wallets"):
			keygenCount++
			pub := "04pub"
			edpub := "edpub"
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"walletId":     "wallet-" + string(rune('0'+keygenCount)),
				"ecdsaPubkey":  pub,
				"eddsaPubkey":  edpub,
				"threshold":    3,
				"participants": []string{"n0", "n1", "n2", "n3", "n4"},
				"status":       "active",
			})
		case r.URL.Path == "/api/v1/status":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"node_id": "node0", "ready": true, "threshold": 3,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(mpcSrv.Close)

	storePath := t.TempDir() + "/keys.json"
	keyStore, err := store.New(storePath)
	if err != nil {
		t.Fatal(err)
	}

	mpcClient := mpc.NewClient(mpcSrv.URL, "test")
	mgr := keys.NewManager(mpcClient, keyStore, "vault-1")
	srv := New(mgr, mpcClient, ":0")

	return srv, mpcSrv
}

func TestHealthz(t *testing.T) {
	srv, _ := setup(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGenerateAndGet(t *testing.T) {
	srv, _ := setup(t)

	// Generate
	body, _ := json.Marshal(keys.GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("generate: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var ks keys.ValidatorKeySet
	json.NewDecoder(w.Body).Decode(&ks)
	if ks.ValidatorID != "val-1" {
		t.Errorf("expected val-1, got %s", ks.ValidatorID)
	}

	// Get
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/api/v1/keys/val-1", nil)
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestList(t *testing.T) {
	srv, _ := setup(t)

	// Generate two keys
	for _, id := range []string{"val-1", "val-2"} {
		body, _ := json.Marshal(keys.GenerateRequest{
			ValidatorID: id,
			Threshold:   3,
			Parties:     5,
		})
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		srv.Router().ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("generate %s: %d %s", id, w.Code, w.Body.String())
		}
	}

	// List
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}

	var list []keys.ValidatorKeySet
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 2 {
		t.Errorf("expected 2 keys, got %d", len(list))
	}
}

func TestSign(t *testing.T) {
	srv, _ := setup(t)

	// Generate
	body, _ := json.Marshal(keys.GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.Router().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("generate: %d %s", w.Code, w.Body.String())
	}

	// Sign BLS
	signBody, _ := json.Marshal(keys.SignRequest{
		KeyType: "bls",
		Message: []byte("hello"),
	})
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/api/v1/keys/val-1/sign", bytes.NewReader(signBody))
	r.Header.Set("Content-Type", "application/json")
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("sign: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp keys.SignResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Signature != "sig123" {
		t.Errorf("expected sig123, got %s", resp.Signature)
	}
}

func TestSignInvalidKeyType(t *testing.T) {
	srv, _ := setup(t)

	body, _ := json.Marshal(keys.SignRequest{
		KeyType: "invalid",
		Message: []byte("hello"),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/keys/val-1/sign", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRotate(t *testing.T) {
	srv, _ := setup(t)

	// Generate
	body, _ := json.Marshal(keys.GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.Router().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("generate: %d", w.Code)
	}

	// Rotate
	rotateBody, _ := json.Marshal(keys.RotateRequest{
		NewThreshold:    4,
		NewParticipants: []string{"n0", "n1", "n2", "n3", "n4", "n5"},
	})
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/api/v1/keys/val-1/rotate", bytes.NewReader(rotateBody))
	r.Header.Set("Content-Type", "application/json")
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("rotate: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetNotFound(t *testing.T) {
	srv, _ := setup(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/keys/nonexistent", nil)
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestStatus(t *testing.T) {
	srv, _ := setup(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	srv.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["kms"] != "ok" {
		t.Errorf("expected kms=ok, got %v", resp["kms"])
	}
}

func TestGenerateConflict(t *testing.T) {
	srv, _ := setup(t)

	body, _ := json.Marshal(keys.GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})

	// First
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.Router().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("first generate: %d", w.Code)
	}

	// Second (conflict)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.Router().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}
