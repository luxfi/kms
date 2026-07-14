// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package bls

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381"
	blssign "github.com/cloudflare/circl/sign/bls"
	"github.com/luxfi/crypto/secret"
)

// Domain separation tags - must match the CGO version (blst) exactly
var (
	dstSignature = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	dstPoP       = []byte("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
)

type (
	SecretKey struct {
		sk *blssign.PrivateKey[blssign.KeyG1SigG2]
	}

	PublicKey struct {
		pk *blssign.PublicKey[blssign.KeyG1SigG2]
	}

	Signature struct {
		sig blssign.Signature
	}

	AggregatePublicKey = PublicKey
	AggregateSignature = Signature
)

func NewSecretKey() (*SecretKey, error) {
	var result *SecretKey
	var keyErr error
	secret.Do(func() {
		ikm := make([]byte, 32)
		rand.Read(ikm)
		defer clear(ikm)

		sk, err := blssign.KeyGen[blssign.KeyG1SigG2](ikm, nil, nil)
		if err != nil {
			keyErr = err
			return
		}
		result = &SecretKey{sk: sk}
	})
	return result, keyErr
}

func SecretKeyToBytes(sk *SecretKey) []byte {
	if sk == nil || sk.sk == nil {
		return nil
	}
	data, _ := sk.sk.MarshalBinary()
	return data
}

// SecretKeyFromSeed derives a secret key from a seed using proper BLS key derivation.
// The seed is passed through internal key derivation, so any 32+ byte input
// will produce a valid secret key.
func SecretKeyFromSeed(seed []byte) (*SecretKey, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	sk, err := blssign.KeyGen[blssign.KeyG1SigG2](seed, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SecretKey{sk: sk}, nil
}

func SecretKeyFromBytes(skBytes []byte) (*SecretKey, error) {
	if len(skBytes) != SecretKeyLen {
		return nil, ErrFailedSecretKeyDeserialize
	}
	var result *SecretKey
	var keyErr error
	secret.Do(func() {
		sk := new(blssign.PrivateKey[blssign.KeyG1SigG2])
		if err := sk.UnmarshalBinary(skBytes); err != nil {
			keyErr = ErrFailedSecretKeyDeserialize
			return
		}
		result = &SecretKey{sk: sk}
	})
	return result, keyErr
}

func (sk *SecretKey) PublicKey() *PublicKey {
	if sk == nil || sk.sk == nil {
		return nil
	}
	return &PublicKey{pk: sk.sk.PublicKey()}
}

func (sk *SecretKey) Sign(msg []byte) (*Signature, error) {
	if sk == nil || sk.sk == nil {
		return nil, errors.New("nil secret key")
	}
	return &Signature{sig: blssign.Sign(sk.sk, msg)}, nil
}

// SignProofOfPossession signs a [msg] to prove the ownership of this secret key.
// Uses the PoP DST (BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_) for domain separation.
// This MUST use a different DST than Sign() to prevent cross-protocol attacks.
func (sk *SecretKey) SignProofOfPossession(msg []byte) (*Signature, error) {
	if sk == nil || sk.sk == nil {
		return nil, errors.New("nil secret key")
	}

	// Get the scalar from the private key
	skBytes, err := sk.sk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Create scalar from private key bytes
	var scalar bls12381.Scalar
	scalar.SetBytes(skBytes)

	// Hash message to G2 with PoP DST
	var sigPoint bls12381.G2
	sigPoint.Hash(msg, dstPoP)

	// Multiply by secret key scalar: sig = sk * H(msg)
	sigPoint.ScalarMult(&scalar, &sigPoint)

	return &Signature{sig: sigPoint.BytesCompressed()}, nil
}

func PublicKeyToCompressedBytes(pk *PublicKey) []byte {
	if pk == nil || pk.pk == nil {
		return nil
	}
	data, _ := pk.pk.MarshalBinary()
	return data
}

func PublicKeyFromCompressedBytes(pkBytes []byte) (*PublicKey, error) {
	if len(pkBytes) != PublicKeyLen {
		return nil, ErrFailedPublicKeyDecompress
	}
	// HIGH-1: reject the malformed "infinity bit set, compression bit clear"
	// encoding (top byte b[0]&0xC0 == 0x40) BEFORE handing the buffer to CIRCL's
	// SetBytes. In that branch SetBytes treats the input as UNCOMPRESSED
	// (length G1Size=96) and slices b[1:96] on this canonical 48-byte compressed
	// buffer → slice-bounds-out-of-range PANIC (ecc/bls12381/g1.go:53). On a
	// CGO_ENABLED=0 (purego) node — the canonical image — that is an
	// unauthenticated, consensus-halting DoS via any PoP / peer-handshake / warp
	// BLS field. The CGO/blst path returns an error for this input (never
	// panics); rejecting it here in-band restores parity. The canonical
	// compressed-infinity form (0xc0) falls through to Validate() below, which
	// already rejects the identity point — so this guard is additive.
	if pkBytes[0]&0xC0 == 0x40 {
		return nil, ErrFailedPublicKeyDecompress
	}
	pk := new(blssign.PublicKey[blssign.KeyG1SigG2])
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return nil, ErrFailedPublicKeyDecompress
	}
	if !pk.Validate() {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{pk: pk}, nil
}

func PublicKeyToUncompressedBytes(key *PublicKey) []byte {
	return PublicKeyToCompressedBytes(key)
}

func PublicKeyFromValidUncompressedBytes(pkBytes []byte) *PublicKey {
	pk := new(blssign.PublicKey[blssign.KeyG1SigG2])
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return nil
	}
	// Identity rejection lives at the ONE deserialization boundary (RESIDUAL C):
	// Validate() = !IsIdentity() && IsOnG1(), so an identity (or off-curve) key
	// never escapes a constructor. Downstream Verify therefore does NOT re-check
	// for the identity point — the check belongs here, once.
	if !pk.Validate() {
		return nil
	}
	return &PublicKey{pk: pk}
}

func AggregatePublicKeys(pks []*PublicKey) (*PublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrNoPublicKeys
	}

	var agg bls12381.G1
	agg.SetIdentity()

	for _, pk := range pks {
		if pk == nil || pk.pk == nil {
			return nil, ErrInvalidPublicKey
		}
		pkBytes, err := pk.pk.MarshalBinary()
		if err != nil {
			return nil, ErrFailedPublicKeyAggregation
		}
		var pt bls12381.G1
		if err := pt.SetBytes(pkBytes); err != nil {
			return nil, ErrFailedPublicKeyAggregation
		}
		agg.Add(&agg, &pt)
	}

	result := new(blssign.PublicKey[blssign.KeyG1SigG2])
	if err := result.UnmarshalBinary(agg.BytesCompressed()); err != nil {
		return nil, ErrFailedPublicKeyAggregation
	}
	// Defence in depth: reject an aggregate that is the IDENTITY (point at
	// infinity). Each INPUT key is a valid non-identity subgroup point (the
	// constructors call Validate), and the sum of subgroup points stays on-curve and
	// in-subgroup — but it can still be the identity when the inputs sum to zero (the
	// canonical rogue-key shape: pk + (-pk) = O). An identity aggregate public key
	// makes Verify trivially accept the identity signature (a forgery enabler).
	// Proof-of-possession at registration already prevents an attacker contributing a
	// key it cannot produce, but the verifier must NOT depend on that being enforced
	// everywhere: Validate() = !IsIdentity() && IsOnG1() fails the aggregate closed.
	if !result.Validate() {
		return nil, ErrFailedPublicKeyAggregation
	}
	return &PublicKey{pk: result}, nil
}

func Verify(pk *PublicKey, sig *Signature, msg []byte) bool {
	if pk == nil || pk.pk == nil || sig == nil {
		return false
	}
	// The identity (zero) public key is rejected at the deserialization boundary
	// (PublicKeyFromCompressedBytes / PublicKeyFromValidUncompressedBytes call
	// Validate() = !IsIdentity() && IsOnG1()), so a *PublicKey reaching Verify is
	// already a valid non-identity G1 point. Re-checking here was redundant — and
	// the old all-zero byte test was WRONG anyway (canonical compressed-G1
	// infinity is 0xc0||zeros, not 0x00||zeros) — so it is removed (RESIDUAL C):
	// identity rejection belongs at decode, in one place.
	return blssign.Verify(pk.pk, msg, sig.sig)
}

// VerifyProofOfPossession verifies the possession of the secret pre-image of [pk].
// Uses the PoP DST (BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_) for domain separation.
func VerifyProofOfPossession(pk *PublicKey, sig *Signature, msg []byte) bool {
	if pk == nil || pk.pk == nil || sig == nil {
		return false
	}
	// Identity (zero) pubkey already rejected at decode (Validate); see Verify.

	// Parse the signature as a G2 point
	var sigPoint bls12381.G2
	if err := sigPoint.SetBytes(sig.sig); err != nil {
		return false
	}

	// Get the public key as a G1 point
	pkBytes, err := pk.pk.MarshalBinary()
	if err != nil {
		return false
	}
	var pkPoint bls12381.G1
	if err := pkPoint.SetBytes(pkBytes); err != nil {
		return false
	}

	// Hash message to G2 with PoP DST
	var hashPoint bls12381.G2
	hashPoint.Hash(msg, dstPoP)

	// BLS verification: e(pk, H(msg)) == e(G1, sig)
	// This is equivalent to: e(pk, H(msg)) * e(-G1, sig) == 1
	// Or: e(pk, H(msg)) == e(G1, sig)

	// Verify using pairing check: e(G1, sig) == e(pk, H(msg))
	// Which is: e(-G1, sig) * e(pk, H(msg)) == 1
	// Copy the generator bytes then negate
	var negG1 bls12381.G1
	_ = negG1.SetBytes(bls12381.G1Generator().BytesCompressed())
	negG1.Neg()

	// Prepare points for pairing
	listG1 := []*bls12381.G1{&negG1, &pkPoint}
	listG2 := []*bls12381.G2{&sigPoint, &hashPoint}

	// ProdPairFrac computes the product of pairings and checks if result equals identity
	result := bls12381.ProdPairFrac(listG1, listG2, []int{1, 1})
	return result.IsIdentity()
}

func SignatureToBytes(sig *Signature) []byte {
	if sig == nil {
		return nil
	}
	return sig.sig
}

func SignatureFromBytes(sigBytes []byte) (*Signature, error) {
	if len(sigBytes) != SignatureLen {
		return nil, ErrFailedSignatureDecompress
	}
	// HIGH-1: reject the malformed "infinity bit set, compression bit clear"
	// encoding (top byte b[0]&0xC0 == 0x40) BEFORE SetBytes. In that branch
	// CIRCL treats the input as UNCOMPRESSED (length G2Size=192) and slices
	// b[1:192] on this canonical 96-byte compressed buffer → slice-bounds-out-of-
	// range PANIC (ecc/bls12381/g2.go:53). On a CGO_ENABLED=0 (purego) node that
	// is an unauthenticated, consensus-halting DoS via any peer/warp/quasar BLS
	// signature field. blst's Uncompress returns an error for this input (never
	// panics); rejecting it here in-band restores parity. The canonical
	// compressed-infinity form (0xc0) falls through to the IsIdentity() check
	// below — so this guard is additive, not a replacement.
	if sigBytes[0]&0xC0 == 0x40 {
		return nil, ErrFailedSignatureDecompress
	}
	// Validate that the bytes decode to a point that is on-curve AND in the
	// prime-order r-torsion subgroup of G2 — the exact contract the CGO/blst
	// path enforces with Uncompress + SigValidate(false). CIRCL's
	// bls12381.G2.SetBytes performs both checks: it decodes the compressed
	// point and then calls IsOnG2() (= isValidProjective && isOnCurve &&
	// isRTorsion) before returning, rejecting any input that is not a valid
	// subgroup element. Without this, a length-96 non-zero blob that is not a
	// real signature point would be accepted here (the prior byte-loop only
	// rejected all-zero), diverging from blst and admitting garbage signatures
	// into the verifier.
	var g bls12381.G2
	if err := g.SetBytes(sigBytes); err != nil {
		return nil, ErrFailedSignatureDecompress
	}
	// Reject the G2 identity (point at infinity) — symmetric with the pubkey
	// identity guard at decode (Validate, INFO-4). CIRCL's SetBytes accepts a well-formed
	// infinity encoding (0xc0 || zeros) and returns at the isInfinity branch BEFORE
	// IsOnG2, so without this the identity signature would deserialize cleanly; blst
	// SigValidate(false) likewise skips the infinity check. The identity sig does
	// not forge against a real key, but accepting it is an asymmetry with the pubkey
	// path and admits a degenerate point into the verifier — reject it here.
	if g.IsIdentity() {
		return nil, ErrFailedSignatureDecompress
	}
	// Store the validated compressed bytes; blssign.Signature is the raw
	// compressed form and blssign.Verify re-derives the point internally, so we
	// keep the canonical wire bytes (round-trips through SignatureToBytes).
	return &Signature{sig: sigBytes}, nil
}

func AggregateSignatures(sigs []*Signature) (*Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}

	sigBytes := make([]blssign.Signature, len(sigs))
	for i, sig := range sigs {
		if sig == nil {
			return nil, ErrFailedSignatureAggregation
		}
		sigBytes[i] = sig.sig
	}

	aggSig, err := blssign.Aggregate[blssign.KeyG1SigG2](blssign.KeyG1SigG2{}, sigBytes)
	if err != nil {
		return nil, ErrFailedSignatureAggregation
	}
	return &Signature{sig: aggSig}, nil
}
