package store

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("CKIEWZCK3V3ADW6AL55UVSD2KP")

	secret, err := Seal(mk, "/liquidity/ats", "ALPACA_API_KEY", "dev", plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if secret.Scheme != ModeStandard {
		t.Errorf("scheme = %q, want %q", secret.Scheme, ModeStandard)
	}
	if len(secret.Ciphertext) < 1+12+16 {
		t.Errorf("ciphertext too small: %d", len(secret.Ciphertext))
	}
	if len(secret.WrappedDEK) < 1+12+16 {
		t.Errorf("wrapped dek too small: %d", len(secret.WrappedDEK))
	}

	got, err := Open(mk, secret)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestOpenTamperedCiphertext(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	secret, err := Seal(mk, "/x", "K", "dev", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext payload (after version+nonce).
	secret.Ciphertext[14] ^= 0xFF
	if _, err := Open(mk, secret); err == nil {
		t.Fatal("expected tampered ciphertext to fail, got nil")
	}
}

func TestOpenWrongKey(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	secret, _ := Seal(mk, "/x", "K", "dev", []byte("v"))
	wrong := make([]byte, 32)
	rand.Read(wrong)
	if _, err := Open(wrong, secret); err == nil {
		t.Fatal("expected wrong master key to fail, got nil")
	}
}

func TestAADBindingPreventsSwap(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	a, _ := Seal(mk, "/x", "K1", "dev", []byte("v1"))
	b, _ := Seal(mk, "/x", "K2", "dev", []byte("v2"))
	// Swap a's wrapped DEK into b — AAD binds name so this must fail.
	b.WrappedDEK = a.WrappedDEK
	if _, err := Open(mk, b); err == nil {
		t.Fatal("expected cross-secret DEK swap to fail, got nil")
	}
}

func TestBadKeySize(t *testing.T) {
	if _, err := Seal(make([]byte, 16), "/", "K", "dev", []byte("x")); err != ErrBadKey {
		t.Errorf("seal 16-byte key: got %v, want ErrBadKey", err)
	}
	if _, err := Open(make([]byte, 16), &Secret{}); err != ErrBadKey {
		t.Errorf("open 16-byte key: got %v, want ErrBadKey", err)
	}
}
