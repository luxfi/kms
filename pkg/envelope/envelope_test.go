// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package envelope_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

func mustIdent(t *testing.T, path string) *keys.ServiceIdentity {
	t.Helper()
	id, err := keys.NewServiceIdentity(testMnemonic, path)
	if err != nil {
		t.Fatalf("NewServiceIdentity: %v", err)
	}
	return id
}

func mustHeader(ident *keys.ServiceIdentity) envelope.IdentityHeader {
	return envelope.IdentityHeader{
		NodeID:      ident.NodeID,
		FullDigest:  ident.FullDigest,
		ServicePath: ident.ServicePath,
		PublicKey:   ident.PublicKey,
	}
}

// TestEnvelope_BuildVerify_RoundTrip — a freshly built envelope
// verifies under the canonical keys.VerifyServiceEnvelope hook.
func TestEnvelope_BuildVerify_RoundTrip(t *testing.T) {
	ident := mustIdent(t, "hanzo/kms-operator")
	defer ident.Wipe()
	req := json.RawMessage(`{"path":"hanzo/commerce","name":"api-key","env":"prod"}`)
	now := time.Unix(1_717_200_000, 0)

	env, err := envelope.Build(mustHeader(ident), ident, 0x0040, req, "nonce-1", now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := envelope.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := envelope.Verify(parsed, now, keys.VerifyServiceEnvelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.NodeID != ident.NodeID {
		t.Errorf("NodeID mismatch")
	}
	if verified.ServicePath != ident.ServicePath {
		t.Errorf("path mismatch: got %q want %q", verified.ServicePath, ident.ServicePath)
	}
}

// TestEnvelope_Stale_Rejected — outside the freshness window fails.
func TestEnvelope_Stale_Rejected(t *testing.T) {
	ident := mustIdent(t, "hanzo/auto")
	defer ident.Wipe()
	old := time.Unix(1_717_200_000, 0)
	env, err := envelope.Build(mustHeader(ident), ident, 0x0040, json.RawMessage(`{}`), "n", old)
	if err != nil {
		t.Fatal(err)
	}
	tooLate := old.Add(envelope.MaxClockSkew + time.Second)
	if _, err := envelope.Verify(env, tooLate, keys.VerifyServiceEnvelope); err == nil {
		t.Errorf("stale envelope should be rejected")
	}
}

// TestEnvelope_Tamper_Sig_Rejected — flipping a sig byte fails.
func TestEnvelope_Tamper_Sig_Rejected(t *testing.T) {
	ident := mustIdent(t, "hanzo/auto")
	defer ident.Wipe()
	now := time.Unix(1_717_200_000, 0)
	env, err := envelope.Build(mustHeader(ident), ident, 0x0040, json.RawMessage(`{}`), "n", now)
	if err != nil {
		t.Fatal(err)
	}
	env.Sig[0] ^= 0xFF
	if _, err := envelope.Verify(env, now, keys.VerifyServiceEnvelope); err == nil {
		t.Errorf("tampered sig should be rejected")
	}
}

// TestEnvelope_BadShape_Rejected — version, scheme, missing fields.
func TestEnvelope_BadShape_Rejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ``},
		{"not json", `not json`},
		{"wrong version", `{"v":99,"id":{"scheme":66,"node":"NodeID-",
			"digest":"","path":"","pubkey":""},"ts":0,"nonce":"x","op":0,"req":{},"sig":"x"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := envelope.Parse([]byte(c.raw)); err == nil {
				t.Errorf("expected reject for %q", c.name)
			}
		})
	}
}
