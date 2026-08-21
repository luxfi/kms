package mpc

import (
	"encoding/json"
	"testing"
)

// The ring reads vault_id, key_id and ciphertext, and refuses a request missing
// any of them. That refusal is why this call never once succeeded: the client
// sent key_id, ciphertext and a scheme, so every reveal died at the door with
// "vault_id and key_id required" and the REK that depends on it stayed unwired.
//
// The names are the contract with a service in another repo, so they are held
// here rather than left to a struct tag nobody reads.
func TestRevealRequestNamesWhatTheRingReads(t *testing.T) {
	b, err := json.Marshal(revealRequest{"acme", "master", []byte("sealed")})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, k := range []string{"vault_id", "key_id", "ciphertext"} {
		if _, ok := got[k]; !ok {
			t.Errorf("%s is absent; the ring refuses the request without it", k)
		}
	}
	if got["vault_id"] != "acme" {
		t.Errorf("vault_id = %v, want acme", got["vault_id"])
	}
	if got["key_id"] != "master" {
		t.Errorf("key_id = %v, want master", got["key_id"])
	}
	if len(got) != 3 {
		t.Errorf("sends %d fields, want exactly 3: %v", len(got), got)
	}
}

// 0x0031 is the op the ring answers with a quorum opening. There is no seal op
// beside it: sealing needs the group's public key alone, so it never travels.
func TestRevealOpIsWhatTheRingServes(t *testing.T) {
	if OpReveal != 0x0031 {
		t.Fatalf("OpReveal = %#04x, want 0x0031", OpReveal)
	}
}
