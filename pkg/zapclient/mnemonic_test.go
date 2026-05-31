// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapclient

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const validBIP39 = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

type fakeReader struct {
	path, name, env string
	value           string
	getErr          error
	gotPath         string
	gotName         string
	gotEnv          string
	closed          bool
}

func (f *fakeReader) GetAt(_ context.Context, path, name, env string) (string, error) {
	f.gotPath, f.gotName, f.gotEnv = path, name, env
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.value, nil
}
func (f *fakeReader) Close() { f.closed = true }

func withDial(t *testing.T, r *fakeReader, err error) {
	t.Helper()
	prev := dialMnemonic
	dialMnemonic = func(_ context.Context, _ string) (MnemonicReader, error) {
		if err != nil {
			return nil, err
		}
		return r, nil
	}
	t.Cleanup(func() { dialMnemonic = prev })
}

// MNEMONIC env wins when set + valid. KMS is not even dialed.
func TestLoadMnemonic_EnvWins(t *testing.T) {
	t.Setenv("MNEMONIC", validBIP39+"\n")
	r := &fakeReader{value: "should not be used"}
	withDial(t, r, nil)
	got, err := LoadMnemonic(context.Background(), "addr", "main", "/mnemonic")
	if err != nil {
		t.Fatalf("LoadMnemonic: %v", err)
	}
	if got != validBIP39 {
		t.Errorf("env-trimmed mismatch: got %q want %q", got, validBIP39)
	}
	if r.closed {
		t.Error("KMS should NOT have been dialed when MNEMONIC env is set")
	}
}

// Invalid MNEMONIC env fails fast — does NOT silently fall through to KMS.
func TestLoadMnemonic_EnvInvalid(t *testing.T) {
	t.Setenv("MNEMONIC", "not a bip39 phrase")
	_, err := LoadMnemonic(context.Background(), "addr", "main", "/mnemonic")
	if err == nil || !strings.Contains(err.Error(), "MNEMONIC env") {
		t.Fatalf("expected MNEMONIC env error, got %v", err)
	}
}

// Empty MNEMONIC env: falls through to KMS.
func TestLoadMnemonic_FallsThroughToKMS(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	r := &fakeReader{value: validBIP39}
	withDial(t, r, nil)
	got, err := LoadMnemonic(context.Background(), "addr", "main", "/mnemonic")
	if err != nil {
		t.Fatalf("LoadMnemonic: %v", err)
	}
	if got != validBIP39 {
		t.Errorf("KMS value mismatch: got %q want %q", got, validBIP39)
	}
	if !r.closed {
		t.Error("KMS reader should have been closed")
	}
	if r.gotPath != "" || r.gotName != "mnemonic" || r.gotEnv != "main" {
		t.Errorf("unexpected GetAt args: path=%q name=%q env=%q",
			r.gotPath, r.gotName, r.gotEnv)
	}
}

// addr/env/path validation kicks in before dialing.
func TestLoadMnemonicFromKMS_RequiredArgs(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	cases := []struct {
		addr, env, path, wantMsg string
	}{
		{"", "main", "/m", "addr is required"},
		{"a", "", "/m", "env is required"},
		{"a", "main", "", "path is required"},
	}
	for _, c := range cases {
		_, err := LoadMnemonicFromKMS(context.Background(), c.addr, c.env, c.path)
		if err == nil || !strings.Contains(err.Error(), c.wantMsg) {
			t.Errorf("addr=%q env=%q path=%q → err=%v, want %q",
				c.addr, c.env, c.path, err, c.wantMsg)
		}
	}
}

// KMS returns the wrong shape — rejected before being returned to caller.
func TestLoadMnemonicFromKMS_InvalidValue(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	r := &fakeReader{value: "not a bip39"}
	withDial(t, r, nil)
	_, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m")
	if err == nil || !strings.Contains(err.Error(), "not a valid BIP-39") {
		t.Fatalf("expected invalid-BIP39 error, got %v", err)
	}
}

func TestLoadMnemonicFromKMS_EmptyValue(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	r := &fakeReader{value: ""}
	withDial(t, r, nil)
	_, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m")
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected empty-value error, got %v", err)
	}
}

func TestLoadMnemonicFromKMS_DialError(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	withDial(t, nil, errors.New("dial timeout"))
	_, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m")
	if err == nil || !strings.Contains(err.Error(), "dial timeout") {
		t.Fatalf("expected dial error, got %v", err)
	}
}

func TestLoadMnemonicFromKMS_GetError(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	r := &fakeReader{getErr: errors.New("kms 403")}
	withDial(t, r, nil)
	_, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m")
	if err == nil || !strings.Contains(err.Error(), "kms 403") {
		t.Fatalf("expected GetAt error, got %v", err)
	}
	if !r.closed {
		t.Error("reader should be closed even when GetAt fails")
	}
}

// SplitSecretPath is the canonical (dir,name) addressing convention.
func TestSplitSecretPath(t *testing.T) {
	cases := []struct {
		in, dir, name string
	}{
		{"/mnemonic", "", "mnemonic"},
		{"mnemonic", "", "mnemonic"},
		{"/foo/bar", "/foo/", "bar"},
		{"/foo/bar/baz", "/foo/bar/", "baz"},
		{"", "", ""},
		{"  /a/b  ", "/a/", "b"}, // trims whitespace
	}
	for _, c := range cases {
		d, n := SplitSecretPath(c.in)
		if d != c.dir || n != c.name {
			t.Errorf("SplitSecretPath(%q) = (%q,%q), want (%q,%q)",
				c.in, d, n, c.dir, c.name)
		}
	}
}
