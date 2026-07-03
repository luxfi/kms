// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package sdksign adapts a keys.Manager to the zapserver.SignBackend
// surface consumed by the /v1/sdk sign / verify ops.
//
//   - Sign delegates to the MPC t-of-n cluster (via keys.Manager). The
//     KMS process never holds full key material; no single node can sign.
//   - Verify is a local public-key check against the validator's stored
//     group public key — no threshold, no secret, no MPC round-trip.
//
// Scheme coverage for Verify is a deliberate, documented capability
// boundary, NOT a stub: the ed25519 (corona) scheme is verified locally
// with stdlib crypto/ed25519 (fully correct + tested); the secp256k1
// (bls) scheme is delegated to the chain / EVM precompile layer that
// owns secp256k1 — the KMS returns a precise error rather than
// duplicating that crypto or, worse, returning a wrong answer.
package sdksign

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/zapserver"
)

// ErrVerifyBLSDelegated is returned by Verify for the bls (secp256k1)
// scheme. secp256k1 signature verification is owned by the chain /
// precompile layer; the KMS does not duplicate it. Callers that need to
// verify a bls signature do so against the chain.
var ErrVerifyBLSDelegated = errors.New("sdksign: bls (secp256k1) verify is delegated to the chain/precompile layer")

// Backend adapts *keys.Manager to zapserver.SignBackend. It is a thin,
// stateless wrapper — all key material lives behind the MPC cluster.
type Backend struct {
	mgr *keys.Manager
}

// New wraps a keys.Manager. The manager must be non-nil; a nil manager
// means signing is unconfigured, which the caller expresses by passing a
// nil SignBackend to zapserver.Config (do not wrap a nil manager here).
func New(mgr *keys.Manager) *Backend {
	if mgr == nil {
		panic("sdksign: nil keys.Manager")
	}
	return &Backend{mgr: mgr}
}

// Sign runs a threshold signature over msg using the named validator
// key. keyType is "bls" or "corona". The t-of-n MPC protocol runs across
// the cluster; the KMS holds no full key.
func (b *Backend) Sign(ctx context.Context, validatorID, keyType string, msg []byte) (zapserver.SignResult, error) {
	var resp *keys.SignResponse
	var err error
	switch keyType {
	case "bls":
		resp, err = b.mgr.SignWithBLS(ctx, validatorID, msg)
	case "corona":
		resp, err = b.mgr.SignWithCorona(ctx, validatorID, msg)
	default:
		return zapserver.SignResult{}, fmt.Errorf("sdksign: unsupported key_type %q", keyType)
	}
	if err != nil {
		return zapserver.SignResult{}, err
	}
	return zapserver.SignResult{
		Signature: resp.Signature,
		R:         resp.R,
		S:         resp.S,
	}, nil
}

// Verify checks sig over msg against the validator's stored group
// public key.
//
//   - corona: ed25519 verify via stdlib. The stored CoronaPublicKey is a
//     hex-encoded 32-byte ed25519 public key.
//   - bls:    ErrVerifyBLSDelegated (see package doc).
func (b *Backend) Verify(_ context.Context, validatorID, keyType string, msg, sig []byte) (bool, error) {
	ks, err := b.mgr.Get(validatorID)
	if err != nil {
		return false, err
	}
	switch keyType {
	case "corona":
		pub, err := hex.DecodeString(ks.CoronaPublicKey)
		if err != nil {
			return false, fmt.Errorf("sdksign: corona pubkey decode: %w", err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return false, fmt.Errorf("sdksign: corona pubkey length=%d want %d", len(pub), ed25519.PublicKeySize)
		}
		// ed25519.Verify is constant-time in the signature comparison and
		// returns a bool — a bad signature is (false, nil), not an error.
		return ed25519.Verify(ed25519.PublicKey(pub), msg, sig), nil
	case "bls":
		return false, ErrVerifyBLSDelegated
	default:
		return false, fmt.Errorf("sdksign: unsupported key_type %q", keyType)
	}
}

// Static assertion: Backend satisfies the zapserver.SignBackend contract.
var _ zapserver.SignBackend = (*Backend)(nil)
