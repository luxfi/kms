// Package keys defines validator key types and the key manager.
package keys

import "time"

// ValidatorKeySet holds MPC wallet references for a validator's BLS and Corona keys.
type ValidatorKeySet struct {
	ValidatorID     string    `json:"validator_id"`
	BLSWalletID     string    `json:"bls_wallet_id"`
	CoronaWalletID  string    `json:"corona_wallet_id"`
	BLSPublicKey    string    `json:"bls_public_key"`
	CoronaPublicKey string    `json:"corona_public_key"`
	Threshold       int       `json:"threshold"`
	Parties         int       `json:"parties"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// GenerateRequest is the input for generating a new validator key set.
type GenerateRequest struct {
	ValidatorID string `json:"validator_id"`
	Threshold   int    `json:"threshold"`
	Parties     int    `json:"parties"`
}

// RotateRequest is the input for resharing a validator's keys.
type RotateRequest struct {
	NewThreshold    int      `json:"new_threshold,omitempty"`
	NewParticipants []string `json:"new_participants,omitempty"`
}

// SignRequest is the input for signing with a validator key.
type SignRequest struct {
	KeyType string `json:"key_type"` // "bls" or "corona"
	Message []byte `json:"message"`
}

// SignResponse contains the signature from a threshold signing operation.
//
// For secp256k1/ECDSA ("bls" slot): Signature is the canonical 65-byte
// r‖s‖v (ecrecover-ready), R/S are the EIP-2 low-S components, and V is the
// recovery id ("0" or "1"). A caller building an EVM tx uses V directly
// (legacy: 27+V; EIP-155: chainID*2+35+V). For ed25519/FROST ("corona"
// slot): Signature is the 64-byte blob and R/S/V are empty.
type SignResponse struct {
	Signature string `json:"signature"`
	R         string `json:"r,omitempty"`
	S         string `json:"s,omitempty"`
	V         string `json:"v,omitempty"`
}
