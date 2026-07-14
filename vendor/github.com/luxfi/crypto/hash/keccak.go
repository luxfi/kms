// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

import (
	// Ethereum Keccak-256 (0x01 domain pad), NOT FIPS-202 SHA3-256 (0x06 pad).
	// NewLegacyKeccak256 is the legacy (pre-standardization) Keccak that every
	// Lux GPU backend and EVM-compatible consumer hashes against; sha3.Sum256
	// would diverge byte-for-byte. Do not swap it.
	"golang.org/x/crypto/sha3"
)

// KeccakSize is the byte length of a Keccak-256 digest.
const KeccakSize = 32

// ComputeKeccak256Array computes the Ethereum Keccak-256 hash of the
// concatenation of the input byte slices.
func ComputeKeccak256Array(data ...[]byte) [KeccakSize]byte {
	h := sha3.NewLegacyKeccak256()
	for _, b := range data {
		h.Write(b)
	}
	var out [KeccakSize]byte
	h.Sum(out[:0])
	return out
}

// ComputeKeccak256 computes the Ethereum Keccak-256 hash of the concatenation
// of the input byte slices.
func ComputeKeccak256(data ...[]byte) []byte {
	out := ComputeKeccak256Array(data...)
	return out[:]
}
