// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// binding.go — the pubkey→identity binding step of envelope verification.
//
// The signature check alone proves only "the holder of PubKey signed these
// bytes over this FullDigest". It does NOT prove that PubKey is the key the
// claimed identity (NodeID / FullDigest) commits to. Without that second
// proof an attacker who holds ANY throwaway ML-DSA-65 key and knows a
// victim's PUBLIC NodeID can mint a signature that verifies AS the victim:
// set env.ID.PubKey = attackerPub, env.ID.Digest = victimNodeID‖zeros,
// env.ID.Node = victimNodeID, sign with the attacker key. The signature is
// valid for attackerPub over the attacker-chosen digest, the NodeID is the
// digest prefix, and the authorizer keys off the victim's NodeID → full
// impersonation.
//
// NewBoundVerifier closes that gap. It is the single source of the
// pubkey→identity binding invariant: BEFORE delegating the ML-DSA-65
// signature check it recomputes the canonical 48-byte SHAKE256-384
// commitment for the presented PubKey under the service chain ID
// (ids.NodeIDSchemeMLDSA65.DeriveMLDSA — byte-for-byte the derivation
// keys.NewServiceIdentity bakes into FullDigest) and rejects unless it
// equals the envelope-supplied FullDigest over ALL 48 bytes. A prefix
// compare would let a NodeID‖zeros forgery through; the full compare does
// not, because the trailing 28 bytes of a real commitment are non-zero
// SHAKE output.
//
// This is the correct home for the check: VerifierFunc's contract already
// says the verifier "MUST bind fullDigest into the signed prehash". Binding
// the PubKey to that same FullDigest is the completing half of the same
// responsibility, and composing it here means every production verify path
// (the ledger-backed Server verifier and the no-ledger VerifyEnvelope
// helper) gets it from one implementation — impossible to wire a verifier
// that skips it.

package envelope

import (
	"errors"
	"fmt"

	"github.com/luxfi/ids"
)

// ErrIdentityBinding is returned when the envelope's public key does not
// derive the claimed FullDigest under the service chain ID. It is a
// wire-safe sentinel: it names the class of failure without echoing any
// key material or internal state.
var ErrIdentityBinding = errors.New("envelope: pubkey does not derive the claimed identity digest")

// NewBoundVerifier wraps a signature VerifierFunc with the mandatory
// pubkey→identity binding check. Production callers MUST verify through a
// bound verifier; a raw signature verifier accepts forged identities.
//
//   - chainID: the service-identity chain ID the signer derived its NodeID
//     under (keys.ServiceChainID). A zero chainID is a wiring bug — an
//     unbound verifier is a wire-reachable auth bypass — so we panic at
//     construction rather than silently degrade at request time.
//   - inner: the ML-DSA-65 signature verifier (keys.VerifyServiceEnvelope).
//
// The returned VerifierFunc rejects, before ever running the signature
// check, any envelope whose PubKey does not commit to the presented
// FullDigest. Edge cases the binding closes:
//
//   - NodeID‖zeros forgery: full 48-byte compare, never a prefix.
//   - empty PubKey: DeriveMLDSA rejects it (so does Parse upstream).
//   - short / wrong-length PubKey: DeriveMLDSA still produces a digest that
//     will not match a real commitment, and the inner ML-DSA parse rejects
//     the malformed key regardless.
//   - wrong scheme: the derivation is scheme-domain-separated (the scheme
//     byte is absorbed into the SHAKE input) and Parse rejects any scheme
//     other than ML-DSA-65 before this runs.
func NewBoundVerifier(chainID ids.ID, inner VerifierFunc) VerifierFunc {
	if inner == nil {
		panic("envelope: NewBoundVerifier requires a non-nil signature verifier")
	}
	if chainID == ids.Empty {
		panic("envelope: NewBoundVerifier requires a non-zero service chain ID")
	}
	return func(pubKey []byte, fullDigest ids.FullDigest, signedBytes, sig []byte) error {
		// Recompute the identity commitment from the key that is about to
		// sign. This is the exact derivation the signer used when it minted
		// its NodeID, so a legitimate envelope always matches and a forged
		// one (attacker key, victim digest) never can.
		_, derived, err := ids.NodeIDSchemeMLDSA65.DeriveMLDSA(chainID, pubKey)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrIdentityBinding, err)
		}
		// Full-length commitment compare. ids.FullDigest is [48]byte, so
		// `!=` compares every byte in one shot; no prefix, no early-out.
		if derived != fullDigest {
			return ErrIdentityBinding
		}
		return inner(pubKey, fullDigest, signedBytes, sig)
	}
}
