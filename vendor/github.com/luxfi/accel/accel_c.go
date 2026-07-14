//go:build cgo

// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package accel

import (
	"sync"
)

var (
	defaultSession     *Session
	defaultSessionOnce sync.Once
	defaultSessionErr  error
	defaultSessionMu   sync.Mutex
)

// DefaultSession returns a lazily initialized default session.
// It uses the best available backend (Metal on macOS, CUDA on Linux).
func DefaultSession() (*Session, error) {
	defaultSessionOnce.Do(func() {
		defaultSession, defaultSessionErr = NewSession()
	})
	return defaultSession, defaultSessionErr
}

// closeDefaultSession closes the default session if it was initialized.
// Called by Shutdown().
func closeDefaultSession() {
	defaultSessionMu.Lock()
	defer defaultSessionMu.Unlock()
	if defaultSession != nil {
		defaultSession.Close()
		defaultSession = nil
	}
}

// MetalAvailable returns true if Metal backend is available.
func MetalAvailable() bool {
	for _, b := range Backends() {
		if b == BackendMetal {
			return true
		}
	}
	return false
}

// CUDAAvailable returns true if CUDA backend is available.
func CUDAAvailable() bool {
	for _, b := range Backends() {
		if b == BackendCUDA {
			return true
		}
	}
	return false
}

// WebGPUAvailable returns true if WebGPU backend is available.
func WebGPUAvailable() bool {
	for _, b := range Backends() {
		if b == BackendWebGPU {
			return true
		}
	}
	return false
}

// =============================================================================
// BLS Operations
// =============================================================================

// BLSBatchVerify verifies multiple BLS signatures using GPU acceleration.
// Returns slice of bools indicating validity of each signature.
// Returns ErrNotSupported if GPU unavailable or batch too small.
func BLSBatchVerify(pks, sigs, msgs [][]byte) ([]bool, error) {
	n := len(pks)
	if n == 0 || n != len(sigs) || n != len(msgs) {
		return nil, ErrBatchSizeMismatch
	}

	if n < BLSBatchVerifyThreshold || !Available() {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	pkData := flattenBytes(pks)
	sigData := flattenBytes(sigs)
	msgData := flattenBytesWithLengths(msgs)

	pkTensor, err := NewTensorWithData[uint8](session, []int{n * 48}, pkData)
	if err != nil {
		return nil, err
	}
	defer pkTensor.Close()

	sigTensor, err := NewTensorWithData[uint8](session, []int{n * 96}, sigData)
	if err != nil {
		return nil, err
	}
	defer sigTensor.Close()

	msgTensor, err := NewTensorWithData[uint8](session, []int{len(msgData)}, msgData)
	if err != nil {
		return nil, err
	}
	defer msgTensor.Close()

	resultTensor, err := NewTensor[uint8](session, []int{n})
	if err != nil {
		return nil, err
	}
	defer resultTensor.Close()

	crypto := session.Crypto()
	if err := crypto.BLSVerifyBatch(msgTensor.Untyped(), sigTensor.Untyped(), pkTensor.Untyped(), resultTensor.Untyped()); err != nil {
		return nil, err
	}

	resultBytes, err := resultTensor.ToSlice()
	if err != nil {
		return nil, err
	}

	results := make([]bool, n)
	for i, r := range resultBytes {
		results[i] = r != 0
	}
	return results, nil
}

// =============================================================================
// Hash Operations
// =============================================================================

// SHA256Batch computes SHA256 hashes for multiple inputs using GPU.
// Returns ErrNotSupported if GPU unavailable or batch too small.
func SHA256Batch(inputs [][]byte) ([][]byte, error) {
	n := len(inputs)
	if n == 0 {
		return nil, ErrBatchSizeMismatch
	}
	if n < HashBatchThreshold || !Available() {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	inputData := flattenBytesWithLengths(inputs)
	inputTensor, err := NewTensorWithData[uint8](session, []int{len(inputData)}, inputData)
	if err != nil {
		return nil, err
	}
	defer inputTensor.Close()

	outputTensor, err := NewTensor[uint8](session, []int{n * 32})
	if err != nil {
		return nil, err
	}
	defer outputTensor.Close()

	if err := session.Crypto().SHA256(inputTensor.Untyped(), outputTensor.Untyped()); err != nil {
		return nil, err
	}

	outputData, err := outputTensor.ToSlice()
	if err != nil {
		return nil, err
	}

	results := make([][]byte, n)
	for i := 0; i < n; i++ {
		results[i] = make([]byte, 32)
		copy(results[i], outputData[i*32:(i+1)*32])
	}
	return results, nil
}

// Keccak256Batch computes Keccak256 hashes for multiple inputs using GPU.
// Returns ErrNotSupported if GPU unavailable or batch too small.
func Keccak256Batch(inputs [][]byte) ([][]byte, error) {
	n := len(inputs)
	if n == 0 {
		return nil, ErrBatchSizeMismatch
	}
	if n < HashBatchThreshold || !Available() {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	inputData := flattenBytesWithLengths(inputs)
	inputTensor, err := NewTensorWithData[uint8](session, []int{len(inputData)}, inputData)
	if err != nil {
		return nil, err
	}
	defer inputTensor.Close()

	outputTensor, err := NewTensor[uint8](session, []int{n * 32})
	if err != nil {
		return nil, err
	}
	defer outputTensor.Close()

	if err := session.Crypto().Keccak256(inputTensor.Untyped(), outputTensor.Untyped()); err != nil {
		return nil, err
	}

	outputData, err := outputTensor.ToSlice()
	if err != nil {
		return nil, err
	}

	results := make([][]byte, n)
	for i := 0; i < n; i++ {
		results[i] = make([]byte, 32)
		copy(results[i], outputData[i*32:(i+1)*32])
	}
	return results, nil
}

// MerkleRoot computes the Merkle root of leaves using GPU.
// Returns ErrNotSupported if GPU unavailable or batch too small.
func MerkleRoot(leaves [][]byte) ([]byte, error) {
	n := len(leaves)
	if n == 0 {
		return nil, ErrBatchSizeMismatch
	}
	if n < HashBatchThreshold || !Available() {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	inputData := flattenBytes(leaves)
	inputTensor, err := NewTensorWithData[uint8](session, []int{len(inputData)}, inputData)
	if err != nil {
		return nil, err
	}
	defer inputTensor.Close()

	outputTensor, err := NewTensor[uint8](session, []int{32})
	if err != nil {
		return nil, err
	}
	defer outputTensor.Close()

	if err := session.Crypto().MerkleRoot(inputTensor.Untyped(), outputTensor.Untyped()); err != nil {
		return nil, err
	}

	return outputTensor.ToSlice()
}

// =============================================================================
// Lattice Operations (Kyber/Dilithium)
// =============================================================================

// KyberKeyGen generates a Kyber keypair using GPU acceleration.
func KyberKeyGen() (pk, sk []byte, err error) {
	if !Available() {
		return nil, nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, nil, err
	}

	pkTensor, err := NewTensor[uint8](session, []int{KyberPublicKeySize})
	if err != nil {
		return nil, nil, err
	}
	defer pkTensor.Close()

	skTensor, err := NewTensor[uint8](session, []int{KyberSecretKeySize})
	if err != nil {
		return nil, nil, err
	}
	defer skTensor.Close()

	if err := session.Lattice().KyberKeyGen(pkTensor.Untyped(), skTensor.Untyped()); err != nil {
		return nil, nil, err
	}

	pk, err = pkTensor.ToSlice()
	if err != nil {
		return nil, nil, err
	}
	sk, err = skTensor.ToSlice()
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// KyberEncaps encapsulates a shared secret using a public key.
func KyberEncaps(pk []byte) (ct, ss []byte, err error) {
	if !Available() {
		return nil, nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, nil, err
	}

	pkTensor, err := NewTensorWithData[uint8](session, []int{KyberPublicKeySize}, pk)
	if err != nil {
		return nil, nil, err
	}
	defer pkTensor.Close()

	ctTensor, err := NewTensor[uint8](session, []int{KyberCiphertextSize})
	if err != nil {
		return nil, nil, err
	}
	defer ctTensor.Close()

	ssTensor, err := NewTensor[uint8](session, []int{KyberSharedKeySize})
	if err != nil {
		return nil, nil, err
	}
	defer ssTensor.Close()

	if err := session.Lattice().KyberEncaps(pkTensor.Untyped(), ctTensor.Untyped(), ssTensor.Untyped()); err != nil {
		return nil, nil, err
	}

	ct, err = ctTensor.ToSlice()
	if err != nil {
		return nil, nil, err
	}
	ss, err = ssTensor.ToSlice()
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

// KyberDecaps decapsulates a ciphertext using a secret key.
func KyberDecaps(ct, sk []byte) (ss []byte, err error) {
	if !Available() {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	ctTensor, err := NewTensorWithData[uint8](session, []int{KyberCiphertextSize}, ct)
	if err != nil {
		return nil, err
	}
	defer ctTensor.Close()

	skTensor, err := NewTensorWithData[uint8](session, []int{KyberSecretKeySize}, sk)
	if err != nil {
		return nil, err
	}
	defer skTensor.Close()

	ssTensor, err := NewTensor[uint8](session, []int{KyberSharedKeySize})
	if err != nil {
		return nil, err
	}
	defer ssTensor.Close()

	if err := session.Lattice().KyberDecaps(ctTensor.Untyped(), skTensor.Untyped(), ssTensor.Untyped()); err != nil {
		return nil, err
	}

	return ssTensor.ToSlice()
}

// DilithiumSign signs a message using Dilithium (ML-DSA).
func DilithiumSign(msg, sk []byte) (sig []byte, err error) {
	if !Available() {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	msgTensor, err := NewTensorWithData[uint8](session, []int{len(msg)}, msg)
	if err != nil {
		return nil, err
	}
	defer msgTensor.Close()

	skTensor, err := NewTensorWithData[uint8](session, []int{DilithiumSecretKeySize}, sk)
	if err != nil {
		return nil, err
	}
	defer skTensor.Close()

	sigTensor, err := NewTensor[uint8](session, []int{DilithiumSignatureSize})
	if err != nil {
		return nil, err
	}
	defer sigTensor.Close()

	if err := session.Lattice().DilithiumSign(msgTensor.Untyped(), skTensor.Untyped(), sigTensor.Untyped()); err != nil {
		return nil, err
	}

	return sigTensor.ToSlice()
}

// DilithiumVerify verifies a Dilithium signature.
func DilithiumVerify(msg, sig, pk []byte) (bool, error) {
	if !Available() {
		return false, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return false, err
	}

	msgTensor, err := NewTensorWithData[uint8](session, []int{len(msg)}, msg)
	if err != nil {
		return false, err
	}
	defer msgTensor.Close()

	sigTensor, err := NewTensorWithData[uint8](session, []int{DilithiumSignatureSize}, sig)
	if err != nil {
		return false, err
	}
	defer sigTensor.Close()

	pkTensor, err := NewTensorWithData[uint8](session, []int{DilithiumPublicKeySize}, pk)
	if err != nil {
		return false, err
	}
	defer pkTensor.Close()

	return session.Lattice().DilithiumVerify(msgTensor.Untyped(), sigTensor.Untyped(), pkTensor.Untyped())
}

// =============================================================================
// ML-DSA (FIPS 204) batched operations
// =============================================================================

// mldsaSizes returns (pk_bytes, sk_bytes, sig_bytes) for a FIPS 204 mode in
// {MLDSAMode44, MLDSAMode65, MLDSAMode87}. Returns (0, 0, 0) for unknown modes.
func mldsaSizes(mode int) (pk, sk, sig int) {
	switch mode {
	case MLDSAMode44:
		return MLDSA44PublicKeySize, MLDSA44SecretKeySize, MLDSA44SignatureSize
	case MLDSAMode65:
		return MLDSA65PublicKeySize, MLDSA65SecretKeySize, MLDSA65SignatureSize
	case MLDSAMode87:
		return MLDSA87PublicKeySize, MLDSA87SecretKeySize, MLDSA87SignatureSize
	default:
		return 0, 0, 0
	}
}

// MLDSAVerifyBatch verifies n ML-DSA signatures at the given FIPS 204 mode
// in {MLDSAMode44, MLDSAMode65, MLDSAMode87}. msgs, sigs, pks are flattened
// byte slices in row-major order with the per-mode widths. results[i] is set
// to true iff sigs[i] verifies under pks[i] for msgs[i]. The msgWidth
// argument pins the per-message tensor stride (callers MUST pad to a fixed
// width — the FIPS 204 verifier hashes the full padded width into mu).
//
// Returns ErrNotSupported when the GPU substrate or libluxaccel impl has
// not yet shipped the operation — callers should fall through to the
// per-element CPU verify path. Returns ErrBatchSizeMismatch on shape
// mismatch, ErrInvalidArgument on unknown mode.
func MLDSAVerifyBatch(mode int, msgs, sigs, pks [][]byte, msgWidth int) ([]bool, error) {
	n := len(msgs)
	if n == 0 || n != len(sigs) || n != len(pks) {
		return nil, ErrBatchSizeMismatch
	}
	pkSize, _, sigSize := mldsaSizes(mode)
	if pkSize == 0 {
		return nil, ErrInvalidArgument
	}
	if !Available() || n < MLDSABatchThreshold {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	msgFlat, err := flattenFixed(msgs, msgWidth)
	if err != nil {
		return nil, err
	}
	sigFlat, err := flattenFixed(sigs, sigSize)
	if err != nil {
		return nil, err
	}
	pkFlat, err := flattenFixed(pks, pkSize)
	if err != nil {
		return nil, err
	}

	msgTensor, err := NewTensorWithData[uint8](session, []int{n, msgWidth}, msgFlat)
	if err != nil {
		return nil, err
	}
	defer msgTensor.Close()

	sigTensor, err := NewTensorWithData[uint8](session, []int{n, sigSize}, sigFlat)
	if err != nil {
		return nil, err
	}
	defer sigTensor.Close()

	pkTensor, err := NewTensorWithData[uint8](session, []int{n, pkSize}, pkFlat)
	if err != nil {
		return nil, err
	}
	defer pkTensor.Close()

	resTensor, err := NewTensor[uint8](session, []int{n})
	if err != nil {
		return nil, err
	}
	defer resTensor.Close()

	if err := session.Lattice().MLDSAVerifyBatch(mode, msgTensor.Untyped(), sigTensor.Untyped(), pkTensor.Untyped(), resTensor.Untyped()); err != nil {
		return nil, err
	}

	raw, err := resTensor.ToSlice()
	if err != nil {
		return nil, err
	}
	out := make([]bool, n)
	for i, b := range raw {
		out[i] = b != 0
	}
	return out, nil
}

// MLDSASignBatch signs n messages with ML-DSA at the given FIPS 204 mode
// in {MLDSAMode44, MLDSAMode65, MLDSAMode87}. msgs and sks are flattened
// byte slices in row-major order; the returned [][]byte is one sig per
// input.
//
// Returns ErrNotSupported when the substrate has not shipped the op.
func MLDSASignBatch(mode int, msgs, sks [][]byte, msgWidth int) ([][]byte, error) {
	n := len(msgs)
	if n == 0 || n != len(sks) {
		return nil, ErrBatchSizeMismatch
	}
	_, skSize, sigSize := mldsaSizes(mode)
	if skSize == 0 {
		return nil, ErrInvalidArgument
	}
	if !Available() || n < MLDSABatchThreshold {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	msgFlat, err := flattenFixed(msgs, msgWidth)
	if err != nil {
		return nil, err
	}
	skFlat, err := flattenFixed(sks, skSize)
	if err != nil {
		return nil, err
	}

	msgTensor, err := NewTensorWithData[uint8](session, []int{n, msgWidth}, msgFlat)
	if err != nil {
		return nil, err
	}
	defer msgTensor.Close()

	skTensor, err := NewTensorWithData[uint8](session, []int{n, skSize}, skFlat)
	if err != nil {
		return nil, err
	}
	defer skTensor.Close()

	sigTensor, err := NewTensor[uint8](session, []int{n, sigSize})
	if err != nil {
		return nil, err
	}
	defer sigTensor.Close()

	if err := session.Lattice().MLDSASignBatch(mode, msgTensor.Untyped(), skTensor.Untyped(), sigTensor.Untyped()); err != nil {
		return nil, err
	}

	flat, err := sigTensor.ToSlice()
	if err != nil {
		return nil, err
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		sig := make([]byte, sigSize)
		copy(sig, flat[i*sigSize:(i+1)*sigSize])
		out[i] = sig
	}
	return out, nil
}

// LatticeNTTMLDSABatch performs the in-place forward (inverse=false) or
// inverse (inverse=true) Number-Theoretic Transform over Z_q[X]/(X^256 + 1)
// with q = 8380417 (the FIPS 204 ML-DSA prime), batched across n=len(polys)
// polynomials. Each polys[i] MUST have length MLDSANTTPolyLen (256). The
// transform writes back into the input slice.
//
// Byte-equal to PQCLEAN_MLDSA65_CLEAN_ntt (forward). The dispatcher
// engages the GPU substrate only when len(polys) >= MLDSABatchThreshold
// (default 8); below threshold ErrNotSupported is returned so callers
// route to the per-poly CPU oracle.
func LatticeNTTMLDSABatch(polys [][]int32, inverse bool) error {
	n := len(polys)
	if n == 0 {
		return ErrBatchSizeMismatch
	}
	for i, p := range polys {
		if len(p) != MLDSANTTPolyLen {
			_ = i
			return ErrShapeMismatch
		}
	}
	if !Available() || n < MLDSABatchThreshold {
		return ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return err
	}

	// Flatten into a single [n*256]int32 backing buffer; cgo will see
	// the contiguous bytes once it lands on the C side. We read back
	// via ToSlice() into the same flat buffer, then deinterleave.
	flat := make([]int32, n*MLDSANTTPolyLen)
	for i, p := range polys {
		copy(flat[i*MLDSANTTPolyLen:(i+1)*MLDSANTTPolyLen], p)
	}

	tensor, err := NewTensorWithData[int32](session, []int{n, MLDSANTTPolyLen}, flat)
	if err != nil {
		return err
	}
	defer tensor.Close()

	if err := session.Lattice().LatticeNTTMLDSABatch(tensor.Untyped(), inverse); err != nil {
		return err
	}

	out, err := tensor.ToSlice()
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		copy(polys[i], out[i*MLDSANTTPolyLen:(i+1)*MLDSANTTPolyLen])
	}
	return nil
}

// flattenFixed concatenates a [][]byte where every row MUST be exactly
// `width` bytes. Returns ErrShapeMismatch on any width violation.
func flattenFixed(rows [][]byte, width int) ([]byte, error) {
	out := make([]byte, len(rows)*width)
	for i, r := range rows {
		if len(r) != width {
			return nil, ErrShapeMismatch
		}
		copy(out[i*width:(i+1)*width], r)
	}
	return out, nil
}

// =============================================================================
// ZK Operations (NTT, MSM)
// =============================================================================

// NTTForward computes forward Number Theoretic Transform on a polynomial.
// Modifies coeffs in-place.
func NTTForward(coeffs, roots []uint64, modulus uint64) error {
	if !Available() {
		return ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return err
	}

	n := len(coeffs)
	inputTensor, err := NewTensorWithData[uint64](session, []int{n}, coeffs)
	if err != nil {
		return err
	}
	defer inputTensor.Close()

	outputTensor, err := NewTensor[uint64](session, []int{n})
	if err != nil {
		return err
	}
	defer outputTensor.Close()

	rootTensor, err := NewTensorWithData[uint64](session, []int{len(roots)}, roots)
	if err != nil {
		return err
	}
	defer rootTensor.Close()

	if err := session.ZK().NTT(inputTensor.Untyped(), outputTensor.Untyped(), rootTensor.Untyped(), modulus); err != nil {
		return err
	}

	output, err := outputTensor.ToSlice()
	if err != nil {
		return err
	}
	copy(coeffs, output)
	return nil
}

// NTTInverse computes inverse Number Theoretic Transform on a polynomial.
// Modifies coeffs in-place.
func NTTInverse(coeffs, invRoots []uint64, modulus uint64) error {
	if !Available() {
		return ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return err
	}

	n := len(coeffs)
	inputTensor, err := NewTensorWithData[uint64](session, []int{n}, coeffs)
	if err != nil {
		return err
	}
	defer inputTensor.Close()

	outputTensor, err := NewTensor[uint64](session, []int{n})
	if err != nil {
		return err
	}
	defer outputTensor.Close()

	rootTensor, err := NewTensorWithData[uint64](session, []int{len(invRoots)}, invRoots)
	if err != nil {
		return err
	}
	defer rootTensor.Close()

	if err := session.ZK().INTT(inputTensor.Untyped(), outputTensor.Untyped(), rootTensor.Untyped(), modulus); err != nil {
		return err
	}

	output, err := outputTensor.ToSlice()
	if err != nil {
		return err
	}
	copy(coeffs, output)
	return nil
}

// MSM computes Multi-Scalar Multiplication: sum(scalars[i] * bases[i])
// Returns ErrNotSupported if GPU unavailable or batch too small.
func MSM(scalars, bases [][]byte) ([]byte, error) {
	n := len(scalars)
	if n == 0 || n != len(bases) {
		return nil, ErrBatchSizeMismatch
	}
	if n < MSMBatchThreshold || !Available() {
		return nil, ErrNotSupported
	}

	session, err := DefaultSession()
	if err != nil {
		return nil, err
	}

	scalarData := flattenBytes(scalars)
	baseData := flattenBytes(bases)
	baseSize := len(bases[0])

	scalarTensor, err := NewTensorWithData[uint8](session, []int{len(scalarData)}, scalarData)
	if err != nil {
		return nil, err
	}
	defer scalarTensor.Close()

	baseTensor, err := NewTensorWithData[uint8](session, []int{len(baseData)}, baseData)
	if err != nil {
		return nil, err
	}
	defer baseTensor.Close()

	resultTensor, err := NewTensor[uint8](session, []int{baseSize})
	if err != nil {
		return nil, err
	}
	defer resultTensor.Close()

	if err := session.ZK().MSM(scalarTensor.Untyped(), baseTensor.Untyped(), resultTensor.Untyped()); err != nil {
		return nil, err
	}

	return resultTensor.ToSlice()
}

// =============================================================================
// Helpers
// =============================================================================

func flattenBytes(data [][]byte) []byte {
	total := 0
	for _, d := range data {
		total += len(d)
	}
	result := make([]byte, total)
	offset := 0
	for _, d := range data {
		copy(result[offset:], d)
		offset += len(d)
	}
	return result
}

func flattenBytesWithLengths(data [][]byte) []byte {
	total := len(data) * 4
	for _, d := range data {
		total += len(d)
	}
	result := make([]byte, total)
	offset := 0
	for _, d := range data {
		l := uint32(len(d))
		result[offset] = byte(l)
		result[offset+1] = byte(l >> 8)
		result[offset+2] = byte(l >> 16)
		result[offset+3] = byte(l >> 24)
		offset += 4
		copy(result[offset:], d)
		offset += len(d)
	}
	return result
}
