// The scheme label must describe the bytes Seal actually produced.
//
// This test decrypts the envelope INDEPENDENTLY — raw crypto/aes + GCM,
// not the package's own aeadOpen — so it fails on either drift:
//
//   - label claims a primitive the code does not run (the "aead+mlkem"
//     bug: metadata advertising ML-KEM over a plain AES-GCM wrap), or
//   - code changes primitive without the label following.
//
// Asserting `Scheme == ModeStandard` alone proves nothing: both sides
// move together when the constant is edited. The independent unwrap is
// what makes the claim falsifiable.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"
)

func TestSchemeLabelMatchesEnvelope(t *testing.T) {
	rek := make([]byte, 32)
	for i := range rek {
		rek[i] = byte(i + 1)
	}
	const (
		path = "/ci"
		name = "deploy-key"
		env  = "main"
	)
	plaintext := []byte("correct horse battery staple")

	secret, err := Seal(rek, path, name, env, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// The label may not advertise a primitive this envelope does not use.
	// ML-KEM appears nowhere in Seal's call graph; if the label says it
	// does, the label lies.
	for _, banned := range []string{"mlkem", "ml-kem", "kyber", "tfhe", "ckks"} {
		if strings.Contains(strings.ToLower(secret.Scheme), banned) {
			t.Fatalf("scheme %q claims %q, which Seal does not implement", secret.Scheme, banned)
		}
	}

	// Independent unwrap of the DEK: plain AES-256-GCM under the REK,
	// AAD = name, envelope = version(1) || nonce(12) || ct||tag.
	dek := unsealGCM(t, rek, []byte(name), secret.WrappedDEK)
	if len(dek) != 32 {
		t.Fatalf("unwrapped DEK: want 32 bytes, got %d", len(dek))
	}

	// Independent unwrap of the payload under that DEK, AAD = path/name/env.
	got := unsealGCM(t, dek, []byte(path+"/"+name+"/"+env), secret.Ciphertext)
	if string(got) != string(plaintext) {
		t.Fatalf("payload: got %q want %q", got, plaintext)
	}

	if secret.Scheme != "aes256-gcm" {
		t.Fatalf("scheme = %q; both layers verified as AES-256-GCM, so the "+
			"label must say so", secret.Scheme)
	}
	t.Logf("scheme %q verified against the bytes: DEK and payload both open "+
		"under raw AES-256-GCM", secret.Scheme)
}

// unsealGCM opens a version(1)||nonce(12)||ct||tag envelope using nothing
// but the Go standard library, so it cannot inherit a bug from the code
// under test.
func unsealGCM(t *testing.T, key, aad, envelope []byte) []byte {
	t.Helper()
	if len(envelope) < 1+12+16 {
		t.Fatalf("envelope too short: %d bytes", len(envelope))
	}
	if envelope[0] != 0x01 {
		t.Fatalf("envelope version: got 0x%02x want 0x01", envelope[0])
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher (key %d bytes): %v", len(key), err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	pt, err := gcm.Open(nil, envelope[1:13], envelope[13:], aad)
	if err != nil {
		t.Fatalf("AES-256-GCM open failed — the envelope is not what the "+
			"scheme label claims: %v", err)
	}
	return pt
}
