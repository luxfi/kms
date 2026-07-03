// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// sign.go — the OpSign / OpVerify threshold-key ops on the /v1/sdk
// surface. Both ride the same signed Envelope as the secret opcodes and
// run through the same verify→authorize→dispatch core: OpSign requires
// the operator (write) authority, OpVerify the validator (read)
// authority. The KMS process NEVER holds full key material — it hands a
// verified request to a SignBackend that delegates to the luxfi/mpc
// t-of-n cluster. A single node cannot produce a signature.

package zapserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// SignBackend is the threshold-signing surface OpSign / OpVerify
// dispatch to. Deliberately narrow and transport-free: the zapserver
// verifies the envelope and runs consensus authorization, then hands
// the verified request here. Implementations delegate to the MPC
// t-of-n cluster (luxfi/mpc); they hold no full private key.
type SignBackend interface {
	// Sign produces a threshold signature over msg using the named
	// validator key. keyType is "bls" or "corona". The t-of-n MPC
	// protocol runs across the cluster; no single node can sign.
	Sign(ctx context.Context, validatorID, keyType string, msg []byte) (SignResult, error)
	// Verify checks sig against the validator's group public key. Pure
	// public-key operation — no threshold, no secret material.
	Verify(ctx context.Context, validatorID, keyType string, msg, sig []byte) (bool, error)
}

// SignResult is the backend's signature output. Fields mirror the MPC
// daemon's response: Signature for schemes that emit a single blob,
// R/S for the (r,s) ECDSA pair.
type SignResult struct {
	Signature string `json:"signature,omitempty"`
	R         string `json:"r,omitempty"`
	S         string `json:"s,omitempty"`
}

// errSignerNotConfigured is returned in-band (statusError body) when a
// sign/verify op arrives but no SignBackend was wired. Callers get a
// parseable signal rather than a generic failure.
var errSignerNotConfigured = errors.New("signing not configured")

// isValidKeyType gates the two supported validator key schemes. Anything
// else is rejected before the backend is touched.
func isValidKeyType(kt string) bool { return kt == "bls" || kt == "corona" }

type signReq struct {
	ValidatorID string `json:"validator_id"`
	KeyType     string `json:"key_type"`
	Message     string `json:"message"` // base64 of the bytes to sign
}

// handleSign runs the threshold-sign op. Auth (operator/write authority)
// has already been enforced by verifyAndAuthorize before this is reached.
func (s *Server) handleSign(ctx context.Context, ident Identity, payload []byte) (byte, []byte, error) {
	if s.signer == nil {
		return statusError, errJSON(errSignerNotConfigured.Error()), nil
	}
	var req signReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	if req.ValidatorID == "" || !isValidKeyType(req.KeyType) {
		return statusError, errJSON("validator_id and key_type (bls|corona) required"), nil
	}
	msg, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil || len(msg) == 0 {
		return statusError, errJSON("message must be non-empty base64"), nil
	}
	res, err := s.signer.Sign(ctx, req.ValidatorID, req.KeyType, msg)
	if err != nil {
		return statusError, nil, err
	}
	// Audit: who signed what key — never the message or signature bytes.
	s.log.Info("kms.sdk sign", "ident", ident.String(), "validator", req.ValidatorID, "key_type", req.KeyType)
	b, _ := json.Marshal(res)
	return statusOK, b, nil
}

type verifyReq struct {
	ValidatorID string `json:"validator_id"`
	KeyType     string `json:"key_type"`
	Message     string `json:"message"`   // base64
	Signature   string `json:"signature"` // base64
}

// handleVerify runs the public-key verify op. Read authority (validator)
// has already been enforced. No secret material is touched.
func (s *Server) handleVerify(ctx context.Context, ident Identity, payload []byte) (byte, []byte, error) {
	if s.signer == nil {
		return statusError, errJSON(errSignerNotConfigured.Error()), nil
	}
	var req verifyReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	if req.ValidatorID == "" || !isValidKeyType(req.KeyType) {
		return statusError, errJSON("validator_id and key_type (bls|corona) required"), nil
	}
	msg, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		return statusError, errJSON("message must be base64"), nil
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return statusError, errJSON("signature must be base64"), nil
	}
	ok, err := s.signer.Verify(ctx, req.ValidatorID, req.KeyType, msg, sig)
	if err != nil {
		return statusError, nil, err
	}
	b, _ := json.Marshal(map[string]bool{"valid": ok})
	return statusOK, b, nil
}
