// Package attestation gates KMS epoch-key release on a composite confidential
// attestation root (CPU TEE + GPU TEE + binary/kernel/model hashes + policy).
//
// The canonical serialization MUST match the C ABI in
// luxcpp/crypto/attestation/include/lux/crypto/attestation/composite.h --
// any drift here is a consensus break.
//
// The gate is keyed on attestation_root, which is keccak256 over the
// canonical serialization. Approved roots are loaded from the KMS metadata
// store and updated on epoch boundary, binary upgrade, driver/firmware
// change, GPU reset, policy root change, or suspicious telemetry.
package attestation

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// ConfidentialIOLevel is the I/O attestation level a node claims.
type ConfidentialIOLevel uint8

const (
	IONone                       ConfidentialIOLevel = 0
	IOCpuTeeOnly                 ConfidentialIOLevel = 1
	IOCpuGpuComposite            ConfidentialIOLevel = 2
	IOGpuTeeWithProtectedTransfer ConfidentialIOLevel = 3
	IOFullDeviceIOAttested       ConfidentialIOLevel = 4
)

// CpuTeeKind identifies the CPU TEE family.
type CpuTeeKind uint8

const (
	CpuTeeNone   CpuTeeKind = 0
	CpuTeeSevSnp CpuTeeKind = 1
	CpuTeeTdx    CpuTeeKind = 2
	CpuTeeSgx    CpuTeeKind = 3
)

// GpuTeeKind identifies the GPU TEE family.
type GpuTeeKind uint8

const (
	GpuTeeNone               GpuTeeKind = 0
	GpuTeeNvH100Cc           GpuTeeKind = 1
	GpuTeeNvBlackwellTeeIo   GpuTeeKind = 2
	GpuTeeAmdMi300Cc         GpuTeeKind = 3
)

// Hash is a 32-byte digest (typically keccak256 output).
type Hash [32]byte

// IsZero reports whether h is the all-zero hash (used as wildcard in baselines).
func (h Hash) IsZero() bool {
	var z Hash
	return h == z
}

// NodeAttestation mirrors NodeConfidentialAttestation in the C ABI.
//
// Field order is the canonical serialization order; do not reorder.
type NodeAttestation struct {
	CpuTeeMeasurement          Hash                `json:"cpu_tee_measurement"`
	GpuAttestationReport       Hash                `json:"gpu_attestation_report"`
	DriverFirmwareMeasurement  Hash                `json:"driver_firmware_measurement"`
	QuasarGpuBinaryHash        Hash                `json:"quasar_gpu_binary_hash"`
	CryptoKernelHash           Hash                `json:"crypto_kernel_hash"`
	AiModelRuntimeHash         Hash                `json:"ai_model_runtime_hash"`
	PrecompileBinaryHash       Hash                `json:"precompile_binary_hash"`
	PolicyRoot                 Hash                `json:"policy_root"`
	NodeIdentity               Hash                `json:"node_identity"`
	Epoch                      uint64              `json:"epoch"`
	CpuTeeKind                 CpuTeeKind          `json:"cpu_tee_kind"`
	GpuTeeKind                 GpuTeeKind          `json:"gpu_tee_kind"`
	IOLevel                    ConfidentialIOLevel `json:"io_level"`
}

// Baseline is the expectation a verifier matches a NodeAttestation against.
//
// Hash fields set to all-zero are wildcards. RequiredCpuTeeKind /
// RequiredGpuTeeKind set to the respective None constant are wildcards.
type Baseline struct {
	ExpectedQuasarGpuBinaryHash Hash                `json:"expected_quasar_gpu_binary_hash"`
	ExpectedCryptoKernelHash    Hash                `json:"expected_crypto_kernel_hash"`
	ExpectedPrecompileBinaryHash Hash               `json:"expected_precompile_binary_hash"`
	ExpectedPolicyRoot          Hash                `json:"expected_policy_root"`
	MinIOLevel                  ConfidentialIOLevel `json:"min_io_level"`
	RequiredCpuTeeKind          CpuTeeKind          `json:"required_cpu_tee_kind"`
	RequiredGpuTeeKind          GpuTeeKind          `json:"required_gpu_tee_kind"`
}

// Errors returned by the gate.
var (
	ErrNilAttestation     = errors.New("attestation: nil attestation")
	ErrNilBaseline        = errors.New("attestation: nil baseline")
	ErrIOLevelTooLow      = errors.New("attestation: io_level below baseline floor")
	ErrCpuTeeKindMismatch = errors.New("attestation: cpu_tee_kind mismatch")
	ErrGpuTeeKindMismatch = errors.New("attestation: gpu_tee_kind mismatch")
	ErrQuasarHashMismatch = errors.New("attestation: quasar_gpu_binary_hash mismatch")
	ErrCryptoHashMismatch = errors.New("attestation: crypto_kernel_hash mismatch")
	ErrPrecompileMismatch = errors.New("attestation: precompile_binary_hash mismatch")
	ErrPolicyMismatch     = errors.New("attestation: policy_root mismatch")
	ErrRootNotApproved    = errors.New("attestation: composite root not approved")
)

// CompositeRoot returns keccak256 over the canonical serialization. Must be
// byte-equal to attestation_compute_composite_root in the C ABI.
func (a *NodeAttestation) CompositeRoot() Hash {
	if a == nil {
		var z Hash
		return z
	}
	buf := make([]byte, 0, 299)
	buf = append(buf, a.CpuTeeMeasurement[:]...)
	buf = append(buf, a.GpuAttestationReport[:]...)
	buf = append(buf, a.DriverFirmwareMeasurement[:]...)
	buf = append(buf, a.QuasarGpuBinaryHash[:]...)
	buf = append(buf, a.CryptoKernelHash[:]...)
	buf = append(buf, a.AiModelRuntimeHash[:]...)
	buf = append(buf, a.PrecompileBinaryHash[:]...)
	buf = append(buf, a.PolicyRoot[:]...)
	buf = append(buf, a.NodeIdentity[:]...)
	var epochBE [8]byte
	binary.BigEndian.PutUint64(epochBE[:], a.Epoch)
	buf = append(buf, epochBE[:]...)
	buf = append(buf, byte(a.CpuTeeKind))
	buf = append(buf, byte(a.GpuTeeKind))
	buf = append(buf, byte(a.IOLevel))

	var out Hash
	keccak256(buf, out[:])
	return out
}

// VerifyBaseline returns nil iff a satisfies b. Mirrors
// attestation_verify_baseline in the C ABI exactly.
func (a *NodeAttestation) VerifyBaseline(b *Baseline) error {
	if a == nil {
		return ErrNilAttestation
	}
	if b == nil {
		return ErrNilBaseline
	}
	if a.IOLevel < b.MinIOLevel {
		return ErrIOLevelTooLow
	}
	if b.RequiredCpuTeeKind != CpuTeeNone && a.CpuTeeKind != b.RequiredCpuTeeKind {
		return ErrCpuTeeKindMismatch
	}
	if b.RequiredGpuTeeKind != GpuTeeNone && a.GpuTeeKind != b.RequiredGpuTeeKind {
		return ErrGpuTeeKindMismatch
	}
	if !b.ExpectedQuasarGpuBinaryHash.IsZero() &&
		subtle.ConstantTimeCompare(a.QuasarGpuBinaryHash[:], b.ExpectedQuasarGpuBinaryHash[:]) != 1 {
		return ErrQuasarHashMismatch
	}
	if !b.ExpectedCryptoKernelHash.IsZero() &&
		subtle.ConstantTimeCompare(a.CryptoKernelHash[:], b.ExpectedCryptoKernelHash[:]) != 1 {
		return ErrCryptoHashMismatch
	}
	if !b.ExpectedPrecompileBinaryHash.IsZero() &&
		subtle.ConstantTimeCompare(a.PrecompileBinaryHash[:], b.ExpectedPrecompileBinaryHash[:]) != 1 {
		return ErrPrecompileMismatch
	}
	if !b.ExpectedPolicyRoot.IsZero() &&
		subtle.ConstantTimeCompare(a.PolicyRoot[:], b.ExpectedPolicyRoot[:]) != 1 {
		return ErrPolicyMismatch
	}
	return nil
}

// EpochKeys is the bundle the KMS releases when attestation passes.
type EpochKeys struct {
	Epoch        uint64            `json:"epoch"`
	WrappedKeys  map[string][]byte `json:"wrapped_keys"`  // key_id -> wrapped material
	PolicyRoot   Hash              `json:"policy_root"`
}

// ApprovedRootStore is the persistent set of attestation roots approved for a
// given epoch. Implementation lives in pkg/store; this interface keeps the
// gate decoupled from the storage layer.
type ApprovedRootStore interface {
	// IsApproved reports whether root is approved for epoch.
	IsApproved(epoch uint64, root Hash) (bool, error)
	// Approve adds root to the approved set for epoch.
	Approve(epoch uint64, root Hash) error
}

// EpochKeyProvider produces the wrapped key bundle for an attestation that
// has passed both the baseline and approved-root checks. Implementation lives
// alongside the validator key store.
type EpochKeyProvider interface {
	GetEpochKeys(epoch uint64) (EpochKeys, error)
}

// Gate is the attestation-gated release logic. Compose with Baseline,
// ApprovedRootStore, and EpochKeyProvider; never let any single check pass
// silently.
type Gate struct {
	Baseline *Baseline
	Roots    ApprovedRootStore
	Keys     EpochKeyProvider
}

// ReleaseEpochKeys returns the epoch keys iff the attestation matches the
// configured baseline AND its composite root is in the approved set for the
// declared epoch. Anything else returns an error and zero keys.
func (g *Gate) ReleaseEpochKeys(a *NodeAttestation) (EpochKeys, error) {
	if g == nil || g.Baseline == nil || g.Roots == nil || g.Keys == nil {
		return EpochKeys{}, errors.New("attestation: gate not configured")
	}
	if err := a.VerifyBaseline(g.Baseline); err != nil {
		return EpochKeys{}, fmt.Errorf("attestation: baseline: %w", err)
	}
	root := a.CompositeRoot()
	ok, err := g.Roots.IsApproved(a.Epoch, root)
	if err != nil {
		return EpochKeys{}, fmt.Errorf("attestation: approval lookup: %w", err)
	}
	if !ok {
		return EpochKeys{}, ErrRootNotApproved
	}
	return g.Keys.GetEpochKeys(a.Epoch)
}
