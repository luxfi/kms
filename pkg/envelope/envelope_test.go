// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package envelope_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

// testBind stands in for the binding a real transport derives with its
// peer. Any 32 bytes will do here — what the tests care about is that
// the same value is on both sides.
var testBind = bytes.Repeat([]byte{0x5A}, envelope.BindSize)

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

	env, err := envelope.Build(mustHeader(ident), ident, 0x0040, req, "nonce-1", testBind, now)
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
	verified, err := envelope.Verify(parsed, now, keys.VerifyServiceEnvelope, testBind)
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
	env, err := envelope.Build(mustHeader(ident), ident, 0x0040, json.RawMessage(`{}`), "n", testBind, old)
	if err != nil {
		t.Fatal(err)
	}
	tooLate := old.Add(envelope.MaxClockSkew + time.Second)
	if _, err := envelope.Verify(env, tooLate, keys.VerifyServiceEnvelope, testBind); err == nil {
		t.Errorf("stale envelope should be rejected")
	}
}

// TestEnvelope_Tamper_Sig_Rejected — flipping a sig byte fails.
func TestEnvelope_Tamper_Sig_Rejected(t *testing.T) {
	ident := mustIdent(t, "hanzo/auto")
	defer ident.Wipe()
	now := time.Unix(1_717_200_000, 0)
	env, err := envelope.Build(mustHeader(ident), ident, 0x0040, json.RawMessage(`{}`), "n", testBind, now)
	if err != nil {
		t.Fatal(err)
	}
	env.Sig[0] ^= 0xFF
	if _, err := envelope.Verify(env, now, keys.VerifyServiceEnvelope, testBind); err == nil {
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

// An envelope that names no channel does not parse. Refusing it at the
// shape check means no later code has to remember to look.
func TestAnEnvelopeThatNamesNoChannelDoesNotParse(t *testing.T) {
	ident := mustIdent(t, "hanzo/auto")
	defer ident.Wipe()
	now := time.Unix(1_717_200_000, 0)
	env, err := envelope.Build(mustHeader(ident), ident, 0x0040, json.RawMessage(`{}`), "n", testBind, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		bind []byte
	}{
		{"absent", nil},
		{"empty", []byte{}},
		{"short", testBind[:envelope.BindSize-1]},
		{"long", append(append([]byte{}, testBind...), 0x00)},
	} {
		t.Run(c.name, func(t *testing.T) {
			env.Bind = c.bind
			raw, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := envelope.Parse(raw); err == nil {
				t.Error("parsed an envelope with no usable channel name")
			}
		})
	}
}

// Building one is refused for the same reason: there is no way to sign a
// request that is not addressed to anybody.
func TestAnEnvelopeCannotBeBuiltWithoutAChannel(t *testing.T) {
	ident := mustIdent(t, "hanzo/auto")
	defer ident.Wipe()
	now := time.Unix(1_717_200_000, 0)
	for _, c := range []struct {
		name string
		bind []byte
	}{
		{"absent", nil},
		{"empty", []byte{}},
		{"short", testBind[:envelope.BindSize-1]},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := envelope.Build(mustHeader(ident), ident, 0x0040, json.RawMessage(`{}`), "n", c.bind, now); err == nil {
				t.Error("built a signed envelope addressed to nobody")
			}
		})
	}
}
