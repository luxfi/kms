// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mpcServerReporting returns a mock MPC server whose keygen response reports the
// given threshold and participant set — i.e. it lets a test say "the ring
// actually produced THIS" independently of what the caller requested.
//
// A nil participants slice with threshold 0 models a pre-v1.17.15 mpcd, which
// omitted both fields entirely. That is the shape that made every real
// validator key set record 0-of-0 while its caller asked for 3-of-5.
func mpcServerReporting(t *testing.T, threshold int, participants []string) *httptest.Server {
	t.Helper()
	n := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.Contains(r.URL.Path, "/wallets") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n++
		body := map[string]interface{}{
			"wallet_id":     "wallet-" + string(rune('0'+n)),
			"vault_id":      "vault-1",
			"ecdsa_pub_key": "04pubkey",
			"eddsa_pub_key": "edpub",
		}
		if threshold != 0 {
			body["threshold"] = threshold
		}
		if participants != nil {
			body["participants"] = participants
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func nodes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "node" + string(rune('0'+i))
	}
	return out
}

// TestGenerateRefusesUnverifiableThreshold is the regression guard for the KMS
// half of the 1-of-n incident.
//
// GenerateValidatorKeys validates req.Threshold and then never sends it —
// mpc.KeygenRequest has no threshold field, because the MPC ring's own
// --threshold decides the CGGMP21 degree. So the request is advisory, and the
// only real check is comparing what came back. Each case below is a way that
// comparison can fail; every one must refuse the key rather than record it.
func TestGenerateRefusesUnverifiableThreshold(t *testing.T) {
	cases := []struct {
		name         string
		threshold    int
		participants []string
		wantErr      string
	}{
		{
			name:         "ring reports nothing (pre-v1.17.15 mpcd)",
			threshold:    0,
			participants: nil,
			wantErr:      "cannot be verified",
		},
		{
			name:         "weaker threshold than requested",
			threshold:    2,
			participants: nodes(5),
			wantErr:      "refusing to record it",
		},
		{
			name:         "degree-0: a single node can sign",
			threshold:    1,
			participants: nodes(5),
			wantErr:      "refusing to record it",
		},
		{
			name:         "fewer parties than requested",
			threshold:    3,
			participants: nodes(3),
			wantErr:      "refusing to record it",
		},
		{
			name:         "stronger than requested is still a mismatch",
			threshold:    4,
			participants: nodes(5),
			wantErr:      "refusing to record it",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := mpcServerReporting(t, tc.threshold, tc.participants)
			defer srv.Close()

			store := newMemStore()
			mgr := NewManager(newTestMPCClient(srv.URL), store, "vault-1")

			ks, err := mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
				ValidatorID: "val-1",
				Threshold:   3,
				Parties:     5,
			})
			if err == nil {
				t.Fatalf("expected refusal for %d-of-%d, got key set %+v",
					tc.threshold, len(tc.participants), ks)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
			// A refused key must leave nothing behind — a stored record would
			// assert a security property that was never established.
			if _, gerr := store.Get("val-1"); gerr == nil {
				t.Fatal("refused key set was still written to the store")
			}
		})
	}
}

// TestGenerateAcceptsMatchingThreshold is the positive control: when the ring
// reports exactly what was asked for, the key is accepted and the recorded
// t-of-n reflects reality rather than a zero value.
func TestGenerateAcceptsMatchingThreshold(t *testing.T) {
	srv := mpcServerReporting(t, 3, nodes(5))
	defer srv.Close()

	store := newMemStore()
	mgr := NewManager(newTestMPCClient(srv.URL), store, "vault-1")

	ks, err := mgr.GenerateValidatorKeys(context.Background(), GenerateRequest{
		ValidatorID: "val-1",
		Threshold:   3,
		Parties:     5,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if ks.Threshold != 3 || ks.Parties != 5 {
		t.Fatalf("recorded %d-of-%d, want 3-of-5", ks.Threshold, ks.Parties)
	}
}
