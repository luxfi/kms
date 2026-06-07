package attestation

// Keccak-256 (Ethereum hash) — first-party implementation matching
// luxcpp/crypto/keccak/cpp/keccak.cpp byte-for-byte. Pre-FIPS-202 padding
// (delimiter 0x01) as used by Ethereum.
//
// Kept in this package because the KMS gate requires byte-identical roots
// across C++ and Go and the kms module does not vendor golang.org/x/crypto.

import (
	"encoding/binary"
	"math/bits"
)

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
}

// Rotation offsets r[x][y] reduced mod 64 (lanes are 64-bit).
var keccakR = [5][5]int{
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14},
}

func keccakF1600(state *[25]uint64) {
	var c [5]uint64
	var d [5]uint64
	var b [25]uint64
	for r := 0; r < 24; r++ {
		// theta
		for x := 0; x < 5; x++ {
			c[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				state[x+5*y] ^= d[x]
			}
		}
		// rho + pi
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				newX := y
				newY := (2*x + 3*y) % 5
				b[newX+5*newY] = bits.RotateLeft64(state[x+5*y], keccakR[x][y])
			}
		}
		// chi
		for y := 0; y < 5; y++ {
			var row [5]uint64
			for x := 0; x < 5; x++ {
				row[x] = b[x+5*y]
			}
			for x := 0; x < 5; x++ {
				state[x+5*y] = row[x] ^ ((^row[(x+1)%5]) & row[(x+2)%5])
			}
		}
		// iota
		state[0] ^= keccakRC[r]
	}
}

// keccak256 computes the 32-byte Keccak-256 (Ethereum) digest of input.
func keccak256(input []byte, out []byte) {
	const rate = 136
	var state [25]uint64
	i := 0
	// Absorb full blocks
	for len(input)-i >= rate {
		for j := 0; j < rate/8; j++ {
			state[j] ^= binary.LittleEndian.Uint64(input[i+j*8 : i+j*8+8])
		}
		keccakF1600(&state)
		i += rate
	}
	// Final block: pad10*1 with delimiter 0x01.
	var block [rate]byte
	rem := len(input) - i
	if rem > 0 {
		copy(block[:], input[i:])
	}
	block[rem] = 0x01
	block[rate-1] |= 0x80
	for j := 0; j < rate/8; j++ {
		state[j] ^= binary.LittleEndian.Uint64(block[j*8 : j*8+8])
	}
	keccakF1600(&state)
	// Squeeze 32 bytes
	for j := 0; j < 4; j++ {
		binary.LittleEndian.PutUint64(out[j*8:], state[j])
	}
}
