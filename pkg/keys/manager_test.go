package keys

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// memStore is an in-memory Store for testing.
type memStore struct {
	mu   sync.RWMutex
	data map[string]*ValidatorKeySet
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string]*ValidatorKeySet)}
}

func (s *memStore) Put(ks *ValidatorKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[ks.ValidatorID]; ok {
		return errAlreadyExists
	}
	s.data[ks.ValidatorID] = ks
	return nil
}

func (s *memStore) Update(ks *ValidatorKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[ks.ValidatorID]; !ok {
		return errNotFound
	}
	s.data[ks.ValidatorID] = ks
	return nil
}

func (s *memStore) Get(id string) (*ValidatorKeySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ks, ok := s.data[id]
	if !ok {
		return nil, errNotFound
	}
	cp := *ks
	return &cp, nil
}

func (s *memStore) List() []*ValidatorKeySet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*ValidatorKeySet, 0, len(s.data))
	for _, ks := range s.data {
		cp := *ks
		result = append(result, &cp)
	}
	return result
}

func (s *memStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; !ok {
		return errNotFound
	}
	delete(s.data, id)
	return nil
}

var (
	errAlreadyExists = errorString("already exists")
	errNotFound      = errorString("not found")
)

type errorString string

func (e errorString) Error() string { return string(e) }

func mockMPCServer(t *testing.T) *httptest.Server {
	t.Helper()
	keygenCount := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/reshare"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "reshare_complete"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/transactions"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"signature": "sig-deadbeef",
				"r":         "aabb",
				"s":         "ccdd",
			})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/wallets"):
			keygenCount++
			pub := "04pubkey" + string(rune('0'+keygenCount))
			edpub := "edpub" + string(rune('0'+keygenCount))
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":           "id-" + string(rune('0'+keygenCount)),
				"walletId":     "wallet-" + string(rune('0'+keygenCount)),
				"vaultId":      "vault-1",
				"ecdsaPubkey":  pub,
				"eddsaPubkey":  edpub,
				"threshold":    3,
				"participants": []string{"node0", "node1", "node2", "node3", "node4"},
				"status":       "active",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestGenerateValidatorKeys(t *testing.T) {
	srv := mockMPCServer(t)
	defer srv.Close()

	// Need to import mpc package -- but we're in keys package.
	// Use the real mpc.Client pointing at mock server.
	mpcClient := newTestMPCClient(srv.URL)
	store := newMemStore()
	mgr := NewManager(mpcClient, store, "vault-1")

	ks, err := mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if ks.ValidatorID != "val-1" {
		t.Errorf("expected val-1, got %s", ks.ValidatorID)
	}
	if ks.BLSWalletID == "" {
		t.Error("expected bls wallet id")
	}
	if ks.CoronaWalletID == "" {
		t.Error("expected corona wallet id")
	}
	if ks.BLSPublicKey == "" {
		t.Error("expected bls public key")
	}
	if ks.CoronaPublicKey == "" {
		t.Error("expected corona public key")
	}
	if ks.Status != "active" {
		t.Errorf("expected active, got %s", ks.Status)
	}
}

func TestGenerateDuplicate(t *testing.T) {
	srv := mockMPCServer(t)
	defer srv.Close()

	mpcClient := newTestMPCClient(srv.URL)
	store := newMemStore()
	mgr := NewManager(mpcClient, store, "vault-1")

	_, err := mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})
	if err == nil {
		t.Fatal("expected error for duplicate")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerateValidation(t *testing.T) {
	srv := mockMPCServer(t)
	defer srv.Close()

	mpcClient := newTestMPCClient(srv.URL)
	store := newMemStore()
	mgr := NewManager(mpcClient, store, "vault-1")

	tests := []struct {
		name string
		req  GenerateRequest
		want string
	}{
		{"empty validator", GenerateRequest{Threshold: 3, Parties: 5}, "validator_id is required"},
		{"low threshold", GenerateRequest{ValidatorID: "v", Threshold: 1, Parties: 5}, "threshold must be >= 2"},
		{"parties < threshold", GenerateRequest{ValidatorID: "v", Threshold: 3, Parties: 2}, "parties must be >= threshold"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mgr.GenerateValidatorKeys(context.Background(), tc.req)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected %q in error, got: %v", tc.want, err)
			}
		})
	}
}

func TestSignWithBLS(t *testing.T) {
	srv := mockMPCServer(t)
	defer srv.Close()

	mpcClient := newTestMPCClient(srv.URL)
	store := newMemStore()
	mgr := NewManager(mpcClient, store, "vault-1")

	mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})

	resp, err := mgr.SignWithBLS(context.Background(), "val-1", []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if resp.Signature != "sig-deadbeef" {
		t.Errorf("expected sig-deadbeef, got %s", resp.Signature)
	}
}

func TestSignWithRingtail(t *testing.T) {
	srv := mockMPCServer(t)
	defer srv.Close()

	mpcClient := newTestMPCClient(srv.URL)
	store := newMemStore()
	mgr := NewManager(mpcClient, store, "vault-1")

	mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})

	resp, err := mgr.SignWithRingtail(context.Background(), "val-1", []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if resp.Signature != "sig-deadbeef" {
		t.Errorf("expected sig-deadbeef, got %s", resp.Signature)
	}
}

func TestSignNotFound(t *testing.T) {
	srv := mockMPCServer(t)
	defer srv.Close()

	mpcClient := newTestMPCClient(srv.URL)
	store := newMemStore()
	mgr := NewManager(mpcClient, store, "vault-1")

	_, err := mgr.SignWithBLS(context.Background(), "nonexistent", []byte("hello"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRotate(t *testing.T) {
	srv := mockMPCServer(t)
	defer srv.Close()

	mpcClient := newTestMPCClient(srv.URL)
	store := newMemStore()
	mgr := NewManager(mpcClient, store, "vault-1")

	mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})

	ks, err := mgr.Rotate(context.Background(), "val-1", RotateRequest{
		NewThreshold:    4,
		NewParticipants: []string{"node0", "node1", "node2", "node3", "node4", "node5"},
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if ks.Threshold != 4 {
		t.Errorf("expected threshold 4, got %d", ks.Threshold)
	}
	if ks.Parties != 6 {
		t.Errorf("expected 6 parties, got %d", ks.Parties)
	}
}

func TestList(t *testing.T) {
	srv := mockMPCServer(t)
	defer srv.Close()

	mpcClient := newTestMPCClient(srv.URL)
	store := newMemStore()
	mgr := NewManager(mpcClient, store, "vault-1")

	mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})
	mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-2",
		Threshold:   3,
		Parties:     5,
	})

	list := mgr.List()
	if len(list) != 2 {
		t.Errorf("expected 2 keys, got %d", len(list))
	}
}
