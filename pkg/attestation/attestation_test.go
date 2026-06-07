package attestation

import (
	"encoding/hex"
	"errors"
	"testing"
)

// fillHash mirrors fill_hash() in luxcpp/crypto/attestation/test/composite_test.cpp.
func fillHash(seed byte) Hash {
	var h Hash
	for i := 0; i < 32; i++ {
		h[i] = byte(int(seed) + i)
	}
	return h
}

// canonical mirrors make_canonical_attestation() in composite_test.cpp.
func canonical() *NodeAttestation {
	return &NodeAttestation{
		CpuTeeMeasurement:         fillHash(0x10),
		GpuAttestationReport:      fillHash(0x20),
		DriverFirmwareMeasurement: fillHash(0x30),
		QuasarGpuBinaryHash:       fillHash(0x40),
		CryptoKernelHash:          fillHash(0x50),
		AiModelRuntimeHash:        fillHash(0x60),
		PrecompileBinaryHash:      fillHash(0x70),
		PolicyRoot:                fillHash(0x80),
		NodeIdentity:              fillHash(0x90),
		Epoch:                     0x0102030405060708,
		CpuTeeKind:                CpuTeeSevSnp,
		GpuTeeKind:                GpuTeeNvH100Cc,
		IOLevel:                   IOGpuTeeWithProtectedTransfer,
	}
}

// Cross-language invariant: the Go composite root MUST equal the C ABI root
// for the same canonical inputs. The reference value comes from running
// composite_test in luxcpp/crypto.
const canonicalRootHex = "56f1d8e537973913091159c532ecc657f3e0cd63946dfcaea831d42a62682152"

func TestCompositeRoot_MatchesCABI(t *testing.T) {
	got := canonical().CompositeRoot()
	want, err := hex.DecodeString(canonicalRootHex)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hex.EncodeToString(got[:]) != canonicalRootHex {
		t.Fatalf("composite root drift\n  go:  %x\n  cpp: %s",
			got[:], canonicalRootHex)
	}
	_ = want
}

func TestCompositeRoot_Deterministic(t *testing.T) {
	a := canonical()
	r1 := a.CompositeRoot()
	r2 := a.CompositeRoot()
	if r1 != r2 {
		t.Fatalf("non-deterministic root: %x vs %x", r1, r2)
	}
}

func TestCompositeRoot_EpochSensitive(t *testing.T) {
	a := canonical()
	r1 := a.CompositeRoot()
	a.Epoch++
	r2 := a.CompositeRoot()
	if r1 == r2 {
		t.Fatalf("root unchanged under epoch bump")
	}
}

func TestVerifyBaseline_FullMatch(t *testing.T) {
	a := canonical()
	b := &Baseline{
		ExpectedQuasarGpuBinaryHash:  a.QuasarGpuBinaryHash,
		ExpectedCryptoKernelHash:     a.CryptoKernelHash,
		ExpectedPrecompileBinaryHash: a.PrecompileBinaryHash,
		ExpectedPolicyRoot:           a.PolicyRoot,
		MinIOLevel:                   IOCpuGpuComposite,
		RequiredCpuTeeKind:           CpuTeeSevSnp,
		RequiredGpuTeeKind:           GpuTeeNvH100Cc,
	}
	if err := a.VerifyBaseline(b); err != nil {
		t.Fatalf("baseline rejected canonical: %v", err)
	}
}

func TestVerifyBaseline_Wildcards(t *testing.T) {
	a := canonical()
	b := &Baseline{} // all zero = full wildcards, MinIOLevel=IONone
	if err := a.VerifyBaseline(b); err != nil {
		t.Fatalf("wildcard baseline rejected: %v", err)
	}
}

func TestVerifyBaseline_Rejects(t *testing.T) {
	a := canonical()

	tests := []struct {
		name    string
		mutate  func(b *Baseline)
		wantErr error
	}{
		{
			name:    "io_level_too_low",
			mutate:  func(b *Baseline) { b.MinIOLevel = IOFullDeviceIOAttested },
			wantErr: ErrIOLevelTooLow,
		},
		{
			name:    "cpu_kind",
			mutate:  func(b *Baseline) { b.RequiredCpuTeeKind = CpuTeeTdx },
			wantErr: ErrCpuTeeKindMismatch,
		},
		{
			name:    "gpu_kind",
			mutate:  func(b *Baseline) { b.RequiredGpuTeeKind = GpuTeeAmdMi300Cc },
			wantErr: ErrGpuTeeKindMismatch,
		},
		{
			name:    "quasar_hash",
			mutate:  func(b *Baseline) { b.ExpectedQuasarGpuBinaryHash = fillHash(0xAA) },
			wantErr: ErrQuasarHashMismatch,
		},
		{
			name:    "crypto_kernel",
			mutate:  func(b *Baseline) { b.ExpectedCryptoKernelHash = fillHash(0xBB) },
			wantErr: ErrCryptoHashMismatch,
		},
		{
			name:    "precompile",
			mutate:  func(b *Baseline) { b.ExpectedPrecompileBinaryHash = fillHash(0xCC) },
			wantErr: ErrPrecompileMismatch,
		},
		{
			name:    "policy",
			mutate:  func(b *Baseline) { b.ExpectedPolicyRoot = fillHash(0xDD) },
			wantErr: ErrPolicyMismatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &Baseline{}
			tc.mutate(b)
			err := a.VerifyBaseline(b)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// memRoots is an in-memory ApprovedRootStore for tests.
type memRoots struct {
	approved map[uint64]map[Hash]bool
}

func newMemRoots() *memRoots {
	return &memRoots{approved: map[uint64]map[Hash]bool{}}
}

func (m *memRoots) IsApproved(epoch uint64, root Hash) (bool, error) {
	return m.approved[epoch][root], nil
}

func (m *memRoots) Approve(epoch uint64, root Hash) error {
	if m.approved[epoch] == nil {
		m.approved[epoch] = map[Hash]bool{}
	}
	m.approved[epoch][root] = true
	return nil
}

// memKeys is an in-memory EpochKeyProvider for tests.
type memKeys struct {
	keys EpochKeys
}

func (m *memKeys) GetEpochKeys(epoch uint64) (EpochKeys, error) {
	if m.keys.Epoch != epoch {
		return EpochKeys{}, errors.New("no keys")
	}
	return m.keys, nil
}

func TestGate_ReleasesKeysOnApprovedRoot(t *testing.T) {
	a := canonical()
	roots := newMemRoots()
	if err := roots.Approve(a.Epoch, a.CompositeRoot()); err != nil {
		t.Fatal(err)
	}
	g := &Gate{
		Baseline: &Baseline{},
		Roots:    roots,
		Keys: &memKeys{keys: EpochKeys{
			Epoch:       a.Epoch,
			WrappedKeys: map[string][]byte{"k1": []byte("ciphertext")},
		}},
	}
	keys, err := g.ReleaseEpochKeys(a)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if keys.Epoch != a.Epoch {
		t.Fatalf("epoch mismatch")
	}
	if string(keys.WrappedKeys["k1"]) != "ciphertext" {
		t.Fatalf("key bundle missing")
	}
}

func TestGate_RefusesUnapprovedRoot(t *testing.T) {
	a := canonical()
	g := &Gate{
		Baseline: &Baseline{},
		Roots:    newMemRoots(), // empty -- no roots approved
		Keys:     &memKeys{},
	}
	_, err := g.ReleaseEpochKeys(a)
	if !errors.Is(err, ErrRootNotApproved) {
		t.Fatalf("got %v, want ErrRootNotApproved", err)
	}
}

func TestGate_RefusesBaselineMismatch(t *testing.T) {
	a := canonical()
	roots := newMemRoots()
	_ = roots.Approve(a.Epoch, a.CompositeRoot())
	g := &Gate{
		Baseline: &Baseline{RequiredCpuTeeKind: CpuTeeTdx}, // a is SEV-SNP
		Roots:    roots,
		Keys:     &memKeys{keys: EpochKeys{Epoch: a.Epoch}},
	}
	_, err := g.ReleaseEpochKeys(a)
	if !errors.Is(err, ErrCpuTeeKindMismatch) {
		t.Fatalf("got %v, want ErrCpuTeeKindMismatch", err)
	}
}
