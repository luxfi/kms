// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// binding_test.go — coverage for the pubkey→identity binding that closes
// the impersonation class (RED CRITICAL). These are white-hat unit tests
// for the invariant itself, independent of the ML-DSA signature check.

package envelope_test

import (
	"crypto/rand"
	"errors"
	"testing"

	mldsa "github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
)

// recordingInner is an inner VerifierFunc that records whether the binding
// let the call through to the (would-be) signature check.
func recordingInner(called *bool) envelope.VerifierFunc {
	return func(_ []byte, _ ids.FullDigest, _, _ []byte) error {
		*called = true
		return nil
	}
}

// TestBoundVerifier_MatchingPubkeyDigest_DelegatesToInner — a pubkey whose
// canonical commitment equals the presented digest passes the binding and
// reaches the signature check.
func TestBoundVerifier_MatchingPubkeyDigest_DelegatesToInner(t *testing.T) {
	id := ledgerIdent(t, "hanzo/kms-operator")
	defer id.Wipe()

	var called bool
	bv := envelope.NewBoundVerifier(keys.ServiceChainID, recordingInner(&called))
	if err := bv(id.PublicKey, id.FullDigest, []byte("signed"), []byte("sig")); err != nil {
		t.Fatalf("legit identity must pass binding: %v", err)
	}
	if !called {
		t.Fatalf("inner signature verifier was not reached on a valid binding")
	}
}

// TestBoundVerifier_MismatchedDigest_Rejected — the exact RED attack: a real
// key but an attacker-chosen digest. Binding rejects BEFORE the signature
// check, so the inner verifier is never consulted.
func TestBoundVerifier_MismatchedDigest_Rejected(t *testing.T) {
	id := ledgerIdent(t, "hanzo/kms-operator")
	defer id.Wipe()

	var wrong ids.FullDigest
	if _, err := rand.Read(wrong[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var called bool
	bv := envelope.NewBoundVerifier(keys.ServiceChainID, recordingInner(&called))
	err := bv(id.PublicKey, wrong, []byte("signed"), []byte("sig"))
	if !errors.Is(err, envelope.ErrIdentityBinding) {
		t.Fatalf("mismatched digest err=%v, want ErrIdentityBinding", err)
	}
	if called {
		t.Fatalf("inner verifier must NOT run once the binding rejects")
	}
}

// TestBoundVerifier_NodeIDZerosForgery_Rejected — the specific shape RED
// exploited: digest = victimNodeID(20) || zeros(28). A prefix compare would
// pass; the full 48-byte compare must reject.
func TestBoundVerifier_NodeIDZerosForgery_Rejected(t *testing.T) {
	victim := ledgerIdent(t, "hanzo/kms-operator")
	defer victim.Wipe()

	// attacker holds their OWN key; forges digest = victim NodeID || zeros.
	attacker, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var forged ids.FullDigest
	copy(forged[:], victim.NodeID[:]) // 20-byte prefix, zero tail

	var called bool
	bv := envelope.NewBoundVerifier(keys.ServiceChainID, recordingInner(&called))
	err = bv(attacker.PublicKey.Bytes(), forged, []byte("signed"), []byte("sig"))
	if !errors.Is(err, envelope.ErrIdentityBinding) {
		t.Fatalf("NodeID||zeros forgery err=%v, want ErrIdentityBinding", err)
	}
	if called {
		t.Fatalf("inner verifier must NOT run for a NodeID||zeros forgery")
	}
}

// TestBoundVerifier_EmptyAndShortPubkey_Rejected — an empty pubkey is
// rejected by the derivation; a short/garbage pubkey cannot match any real
// commitment. Both must reject without reaching the signature check.
func TestBoundVerifier_EmptyAndShortPubkey_Rejected(t *testing.T) {
	id := ledgerIdent(t, "hanzo/kms-operator")
	defer id.Wipe()

	cases := map[string][]byte{
		"empty": {},
		"short": {0x01, 0x02, 0x03},
	}
	for name, pk := range cases {
		var called bool
		bv := envelope.NewBoundVerifier(keys.ServiceChainID, recordingInner(&called))
		if err := bv(pk, id.FullDigest, []byte("signed"), []byte("sig")); err == nil {
			t.Fatalf("%s pubkey must be rejected by binding", name)
		}
		if called {
			t.Fatalf("%s pubkey: inner verifier must NOT run", name)
		}
	}
}

// TestBoundVerifier_ConstructionGuards — a zero chain ID or nil inner is a
// wiring bug and must panic at construction, not silently degrade.
func TestBoundVerifier_ConstructionGuards(t *testing.T) {
	mustPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: expected panic", name)
			}
		}()
		f()
	}
	mustPanic("zero chainID", func() {
		envelope.NewBoundVerifier(ids.Empty, func(_ []byte, _ ids.FullDigest, _, _ []byte) error { return nil })
	})
	mustPanic("nil inner", func() {
		envelope.NewBoundVerifier(keys.ServiceChainID, nil)
	})
}
