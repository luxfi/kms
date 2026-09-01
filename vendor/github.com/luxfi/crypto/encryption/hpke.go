// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package encryption

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/secret"
)

// HPKEKeyPair holds an HPKE key pair for X25519-based encryption.
type HPKEKeyPair struct {
	private hpke.PrivateKey
	public  hpke.PublicKey
}

var (
	// defaultKEM is X25519-based DHKEM, widely deployed and fast.
	defaultKEM = hpke.DHKEM(ecdh.X25519())
	// defaultKDF is HKDF-SHA256 per RFC 9180.
	defaultKDF = hpke.HKDFSHA256()
	// defaultAEAD is ChaCha20-Poly1305, fast on platforms without AES-NI.
	defaultAEAD = hpke.ChaCha20Poly1305()
)

// GenerateHPKEKeyPair generates a new X25519 HPKE key pair.
func GenerateHPKEKeyPair() (*HPKEKeyPair, error) {
	priv, err := defaultKEM.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("hpke: generate key: %w", err)
	}
	return &HPKEKeyPair{
		private: priv,
		public:  priv.PublicKey(),
	}, nil
}

// HPKEKeyPairFromBytes reconstructs an HPKE key pair from a serialized private key.
func HPKEKeyPairFromBytes(privBytes []byte) (*HPKEKeyPair, error) {
	priv, err := defaultKEM.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("hpke: parse private key: %w", err)
	}
	return &HPKEKeyPair{
		private: priv,
		public:  priv.PublicKey(),
	}, nil
}

// PublicKeyBytes returns the serialized public key.
func (kp *HPKEKeyPair) PublicKeyBytes() []byte {
	return kp.public.Bytes()
}

// PrivateKeyBytes returns the serialized private key.
// The caller should clear the returned slice when done.
func (kp *HPKEKeyPair) PrivateKeyBytes() ([]byte, error) {
	return kp.private.Bytes()
}

// HPKESeal encrypts plaintext to a recipient's public key using HPKE (RFC 9180).
//
// Returns the concatenation of the encapsulated key and ciphertext.
// The info parameter provides context binding (can be nil).
func HPKESeal(recipientPubKeyBytes []byte, info, plaintext []byte) ([]byte, error) {
	pub, err := defaultKEM.NewPublicKey(recipientPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("hpke seal: parse public key: %w", err)
	}
	return hpke.Seal(pub, defaultKDF, defaultAEAD, info, plaintext)
}

// HPKEOpen decrypts ciphertext using the recipient's private key.
//
// The ciphertext must be the concatenation of the encapsulated key and the
// actual ciphertext, as returned by HPKESeal.
// The info parameter must match what was used during encryption.
func HPKEOpen(kp *HPKEKeyPair, info, ciphertext []byte) ([]byte, error) {
	if kp == nil {
		return nil, errors.New("hpke open: nil key pair")
	}
	var plaintext []byte
	var openErr error
	secret.Do(func() {
		plaintext, openErr = hpke.Open(kp.private, defaultKDF, defaultAEAD, info, ciphertext)
	})
	return plaintext, openErr
}

// HPKEPublicKeyFromBytes deserializes an HPKE public key from bytes.
func HPKEPublicKeyFromBytes(pubBytes []byte) (hpke.PublicKey, error) {
	return defaultKEM.NewPublicKey(pubBytes)
}

// Hybrid HPKE: ML-KEM-768 + X25519 (post-quantum hybrid)

// HybridHPKEKeyPair holds a hybrid ML-KEM-768 + X25519 HPKE key pair.
type HybridHPKEKeyPair struct {
	private hpke.PrivateKey
	public  hpke.PublicKey
}

var hybridKEM = hpke.MLKEM768X25519()

// GenerateHybridHPKEKeyPair generates a new hybrid ML-KEM-768+X25519 HPKE key pair.
// This provides post-quantum security combined with classical X25519.
func GenerateHybridHPKEKeyPair() (*HybridHPKEKeyPair, error) {
	priv, err := hybridKEM.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("hybrid hpke: generate key: %w", err)
	}
	return &HybridHPKEKeyPair{
		private: priv,
		public:  priv.PublicKey(),
	}, nil
}

// HybridHPKEKeyPairFromBytes reconstructs a hybrid HPKE key pair from serialized bytes.
func HybridHPKEKeyPairFromBytes(privBytes []byte) (*HybridHPKEKeyPair, error) {
	priv, err := hybridKEM.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("hybrid hpke: parse private key: %w", err)
	}
	return &HybridHPKEKeyPair{
		private: priv,
		public:  priv.PublicKey(),
	}, nil
}

// PublicKeyBytes returns the serialized public key.
func (kp *HybridHPKEKeyPair) PublicKeyBytes() []byte {
	return kp.public.Bytes()
}

// PrivateKeyBytes returns the serialized private key.
func (kp *HybridHPKEKeyPair) PrivateKeyBytes() ([]byte, error) {
	return kp.private.Bytes()
}

// HybridHPKESeal encrypts plaintext using hybrid ML-KEM-768+X25519 HPKE.
func HybridHPKESeal(recipientPubKeyBytes []byte, info, plaintext []byte) ([]byte, error) {
	pub, err := hybridKEM.NewPublicKey(recipientPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("hybrid hpke seal: parse public key: %w", err)
	}
	return hpke.Seal(pub, defaultKDF, defaultAEAD, info, plaintext)
}

// HybridHPKEOpen decrypts ciphertext using hybrid ML-KEM-768+X25519 HPKE.
func HybridHPKEOpen(kp *HybridHPKEKeyPair, info, ciphertext []byte) ([]byte, error) {
	if kp == nil {
		return nil, errors.New("hybrid hpke open: nil key pair")
	}
	var plaintext []byte
	var openErr error
	secret.Do(func() {
		plaintext, openErr = hpke.Open(kp.private, defaultKDF, defaultAEAD, info, ciphertext)
	})
	return plaintext, openErr
}
