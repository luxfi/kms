// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mnemonic

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/keys"
)

// validMnemonic is the canonical BIP-39 all-zero-entropy English test vector.
const validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// fakeReader is an in-memory KMS stand-in injected through the dialKMS seam so
// the precedence + validation logic is exercised without any network.
type fakeReader struct {
	val    string
	err    error
	closed bool
	calls  int
}

func (f *fakeReader) GetAt(context.Context, string, string, string) (string, error) {
	f.calls++
	return f.val, f.err
}
func (f *fakeReader) Close() { f.closed = true }

// withDial swaps the production dial seam for the duration of a test.
func withDial(t *testing.T, r Reader, dialErr error) {
	t.Helper()
	orig := dialKMS
	dialKMS = func(context.Context, string, *keys.ServiceIdentity) (Reader, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		return r, nil
	}
	t.Cleanup(func() { dialKMS = orig })
}

// Load must return the MNEMONIC env value and NEVER reach KMS when env is set.
func TestLoad_EnvWinsWithoutDialingKMS(t *testing.T) {
	dialed := false
	orig := dialKMS
	dialKMS = func(context.Context, string, *keys.ServiceIdentity) (Reader, error) {
		dialed = true
		return nil, errors.New("KMS must not be dialed when MNEMONIC env is set")
	}
	t.Cleanup(func() { dialKMS = orig })

	t.Setenv("MNEMONIC", validMnemonic)
	got, err := Load(context.Background(), "kms:9999", "devnet", "/mnemonic", nil)
	if err != nil {
		t.Fatalf("Load env path: %v", err)
	}
	if got != validMnemonic {
		t.Fatalf("got %q, want env mnemonic", got)
	}
	if dialed {
		t.Fatal("env short-circuit must not dial KMS")
	}
}

// An invalid BIP-39 phrase in env is rejected, not blindly returned.
func TestLoad_InvalidEnvRejected(t *testing.T) {
	t.Setenv("MNEMONIC", "totally not a valid bip39 phrase")
	if _, err := Load(context.Background(), "kms:9999", "devnet", "/mnemonic", nil); err == nil {
		t.Fatal("expected error for invalid BIP-39 MNEMONIC env")
	}
}

// Production path: a valid (whitespace-padded) phrase from KMS is trimmed,
// validated, and the client is closed.
func TestLoadFromKMS_ValidPhrase(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	fr := &fakeReader{val: "  " + validMnemonic + "  "}
	withDial(t, fr, nil)
	got, err := LoadFromKMS(context.Background(), "kms:9999", "mainnet", "/staking/mnemonic", nil)
	if err != nil {
		t.Fatalf("LoadFromKMS: %v", err)
	}
	if got != validMnemonic {
		t.Fatalf("got %q, want trimmed valid mnemonic", got)
	}
	if fr.calls != 1 {
		t.Fatalf("GetAt calls = %d, want 1", fr.calls)
	}
	if !fr.closed {
		t.Fatal("client must be Closed")
	}
}

// A non-BIP-39 value from KMS is rejected.
func TestLoadFromKMS_InvalidPhraseRejected(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	withDial(t, &fakeReader{val: "garbage not bip39"}, nil)
	if _, err := LoadFromKMS(context.Background(), "kms:9999", "mainnet", "/mnemonic", nil); err == nil {
		t.Fatal("expected error for invalid BIP-39 from KMS")
	}
}

// An empty/whitespace secret is rejected.
func TestLoadFromKMS_EmptyRejected(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	withDial(t, &fakeReader{val: "   "}, nil)
	if _, err := LoadFromKMS(context.Background(), "kms:9999", "mainnet", "/mnemonic", nil); err == nil {
		t.Fatal("expected error for empty mnemonic")
	}
}

// addr/env/path are all required (checked before any dial).
func TestLoadFromKMS_RequiresAddrEnvPath(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	cases := []struct{ addr, env, path string }{
		{"", "mainnet", "/m"},
		{"kms:9999", "", "/m"},
		{"kms:9999", "mainnet", ""},
	}
	for _, c := range cases {
		if _, err := LoadFromKMS(context.Background(), c.addr, c.env, c.path, nil); err == nil {
			t.Fatalf("expected error for addr=%q env=%q path=%q", c.addr, c.env, c.path)
		}
	}
}

// SplitSecretPath is the one canonical addressing convention.
func TestSplitSecretPath(t *testing.T) {
	cases := []struct{ in, dir, name string }{
		{"/mnemonic", "", "mnemonic"},
		{"mnemonic", "", "mnemonic"},
		{"/foo/bar/baz", "/foo/bar/", "baz"},
		{"/staking/mnemonic", "/staking/", "mnemonic"},
	}
	for _, c := range cases {
		d, n := SplitSecretPath(c.in)
		if d != c.dir || n != c.name {
			t.Fatalf("SplitSecretPath(%q)=(%q,%q), want (%q,%q)", c.in, d, n, c.dir, c.name)
		}
	}
}
