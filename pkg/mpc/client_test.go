package mpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKeygen(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/vaults/vault-1/wallets" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing auth header")
		}

		var req KeygenRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.KeyType != "secp256k1" {
			t.Errorf("expected secp256k1, got %s", req.KeyType)
		}
		if req.Protocol != "cggmp21" {
			t.Errorf("expected cggmp21, got %s", req.Protocol)
		}

		pub := "04abcdef"
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(KeygenResult{
			ID:           "id-1",
			WalletID:     "wallet-1",
			VaultID:      "vault-1",
			ECDSAPubkey:  &pub,
			Threshold:    3,
			Participants: []string{"node0", "node1", "node2", "node3", "node4"},
			Status:       "active",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	result, err := c.Keygen(context.Background(), "vault-1", KeygenRequest{
		Name:     "test-bls",
		KeyType:  "secp256k1",
		Protocol: "cggmp21",
	})
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if !called {
		t.Fatal("server not called")
	}
	if result.WalletID != "wallet-1" {
		t.Errorf("expected wallet-1, got %s", result.WalletID)
	}
	if result.Threshold != 3 {
		t.Errorf("expected threshold 3, got %d", result.Threshold)
	}
	if result.ECDSAPubkey == nil || *result.ECDSAPubkey != "04abcdef" {
		t.Errorf("unexpected ecdsa pubkey")
	}
}

func TestSign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/transactions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(SignResult{
			Signature: "deadbeef",
			R:         "aabb",
			S:         "ccdd",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	result, err := c.Sign(context.Background(), "wallet-1", "secp256k1", []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if result.Signature != "deadbeef" {
		t.Errorf("expected deadbeef, got %s", result.Signature)
	}
}

func TestReshare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/wallets/wallet-1/reshare" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var req ReshareRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.NewThreshold != 4 {
			t.Errorf("expected threshold 4, got %d", req.NewThreshold)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "reshare_complete"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	err := c.Reshare(context.Background(), "wallet-1", ReshareRequest{
		NewThreshold:    4,
		NewParticipants: []string{"node0", "node1", "node2", "node3", "node4", "node5"},
	})
	if err != nil {
		t.Fatalf("reshare: %v", err)
	}
}

func TestGetWallet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/wallets/wallet-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Wallet{
			ID:       "id-1",
			WalletID: "wallet-1",
			Status:   "active",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	wallet, err := c.GetWallet(context.Background(), "wallet-1")
	if err != nil {
		t.Fatalf("get wallet: %v", err)
	}
	if wallet.WalletID != "wallet-1" {
		t.Errorf("expected wallet-1, got %s", wallet.WalletID)
	}
}

func TestStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ClusterStatus{
			NodeID:    "node0",
			Mode:      "consensus",
			Ready:     true,
			Threshold: 3,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	status, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.Ready {
		t.Error("expected ready")
	}
	if status.Threshold != 3 {
		t.Errorf("expected threshold 3, got %d", status.Threshold)
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "wallet not found"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	_, err := c.GetWallet(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "wallet not found" {
		t.Errorf("unexpected message: %s", apiErr.Message)
	}
}
