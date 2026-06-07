// Package mpcrek bootstraps the KMS Root Encryption Key (REK) from a
// luxfi/mpc threshold cluster.
//
// # Threat model
//
// The KMS process must protect every per-secret DEK at rest in ZapDB. The
// existing envelope (pkg/store/crypto.go) wraps each DEK under a 32-byte
// AES-256-GCM key — call it the REK. Prior to this package the REK was
// read from `KMS_MASTER_KEY_B64`, an env var sourced from a long-lived
// K8s Secret. That gave any operator with `kubectl exec` access — or any
// process that could read the pod's env — the ability to decrypt every
// secret in the store. It also meant the REK rotated only by manual
// re-encryption of every record, with no audit trail beyond
// `kubectl edit`.
//
// # Construction (Architecture B)
//
// The REK is fetched from a t-of-n luxfi/mpc cluster ONCE at boot via
// ZAP. The KMS pod authenticates with its IAM JWT (org-scoped,
// `client_credentials` grant). MPC stores the REK as a sealed entry
// keyed by `kms/rek/<epoch>`; on `OpDecrypt` it cooperatively unwraps
// the entry under its own t-of-n share set and returns the plaintext
// REK over the AEAD-sealed ZAP wire (X25519+ML-KEM-768 handshake).
//
// The KMS process holds the REK in heap memory for its lifetime. On
// shutdown the slice is zeroed (best-effort; the Go GC offers no harder
// guarantees, but a deliberate zero closes the window for accidental
// dumps via core file or pprof memory profile).
//
// # Why not "decrypt every secret through MPC"?
//
// Architecture A — every secret read becomes an MPC round-trip — was
// rejected because:
//
//   1. Throughput: ATS/BD/TA hot paths fan out >100 KMS reads per
//      request. A 50ms ZAP RTT times 100 = 5s added latency.
//   2. Threat model parity: a compromised KMS process leaks plaintext
//      either way; per-secret round-trips do not improve the worst
//      case.
//   3. Auditability: one fetch-at-boot is a single, named event in the
//      MPC audit log. Per-secret reads dilute the signal.
//
// Architecture B keeps the existing envelope, which is well-built
// (AES-256-GCM, per-secret DEK, AAD binding path/name/env, version
// byte). It replaces only WHERE the master key comes from.
//
// # Re-key (REK rotation)
//
// Out of band: an operator invokes the MPC cluster's reshare / new-key
// ceremony to mint REK at epoch N+1. KMS replicas observe the new epoch
// (via a watch on `kms/rek/epoch`) and run the migration: for every
// secret in ZapDB, Open under epoch N, Seal under epoch N+1, Put. The
// re-key tool is `cmd/rek-rotate` (future; this PR ships only the boot
// fetch).
//
// # Fail-closed
//
// If `MPC_REK_ENDPOINT` is set but the bootstrap fetch fails, kmsd MUST
// refuse to start. There is no fallback to env-var REK. The whole point
// of this construction is that the REK is not derivable from anything
// on the KMS pod; degrading to a static fallback would re-open the
// vulnerability we are closing.
package mpcrek

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/luxfi/kms/pkg/mpc"
)

// Errors returned by Bootstrap.
var (
	// ErrUnconfigured indicates Bootstrap was called without a populated Config.
	ErrUnconfigured = errors.New("mpcrek: config not populated")

	// ErrBadREKLength indicates the MPC cluster returned a REK of the wrong size.
	ErrBadREKLength = errors.New("mpcrek: unwrapped REK is not 32 bytes")

	// ErrZeroREK indicates the MPC cluster returned an all-zero plaintext —
	// reject it; either MPC is misconfigured or the wrapped record is
	// corrupted. Either way, an all-zero AEAD key is unacceptable.
	ErrZeroREK = errors.New("mpcrek: unwrapped REK is all-zero")
)

// Config describes how to reach the MPC cluster and which key to fetch.
//
// Endpoint is a CSV of host:port (e.g. "mpc-0.lux-mpc.svc:9999,
// mpc-1.lux-mpc.svc:9999"). The KMS-side ZAP client tries each address
// in order; production deployments should pass all replicas so a
// restarting pod doesn't fail the boot probe.
//
// KeyID is the MPC-side identifier of the wrapped REK record. Convention:
// "kms/rek/v1" for the current epoch. Rotation publishes "kms/rek/v2"
// alongside v1; the operator rolls KMS pods with the new env after the
// migration tool runs.
//
// NodeID is the ZAP node identity used for this client. Default
// "kms-rek-bootstrap"; production deployments should set it to the pod
// name so the MPC audit log can attribute the fetch.
//
// Timeout caps the total bootstrap fetch. Recommended: 10s — long enough
// for ZAP handshake + MPC threshold round-trip, short enough that a
// pod restart doesn't hang behind a dead cluster.
type Config struct {
	Endpoint string
	KeyID    string
	NodeID   string
	Timeout  time.Duration
}

// Validate returns an error if any required field is unset.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("%w: Endpoint is required", ErrUnconfigured)
	}
	if strings.TrimSpace(c.KeyID) == "" {
		return fmt.Errorf("%w: KeyID is required", ErrUnconfigured)
	}
	return nil
}

// MPCDecrypter is the subset of mpc.ZapClient that Bootstrap needs.
// Defined as an interface so tests can supply a fake without dialing a
// real MPC cluster.
type MPCDecrypter interface {
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*mpc.DecryptResult, error)
	Close()
}

// dialer is overridable in tests. Production wires NewZapClient.
var dialer = func(nodeID, endpoint string) (MPCDecrypter, error) {
	c, err := mpc.NewZapClient(nodeID, endpoint)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Bootstrap fetches the REK from the MPC cluster and returns it. The
// returned slice is 32 bytes; the caller is responsible for zeroing it
// at shutdown (use Zero below for the discipline).
//
// On any error — network, auth, malformed response, wrong length, all
// zero — Bootstrap returns the error WITHOUT a partial REK. kmsd must
// then refuse to start.
func Bootstrap(ctx context.Context, cfg Config) ([]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	nodeID := cfg.NodeID
	if nodeID == "" {
		nodeID = "kms-rek-bootstrap"
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := dialer(nodeID, cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("mpcrek: dial %s: %w", cfg.Endpoint, err)
	}
	defer client.Close()

	// The MPC cluster's stored REK record is opaque to KMS — we pass
	// the keyID and let the cluster's t-of-n share set unwrap. The
	// "ciphertext" field is empty: there is no caller-supplied
	// ciphertext for a stored key fetch; the MPC side reads its own
	// record by keyID and threshold-decrypts.
	res, err := client.Decrypt(dialCtx, cfg.KeyID, nil)
	if err != nil {
		return nil, fmt.Errorf("mpcrek: threshold decrypt key=%s: %w", cfg.KeyID, err)
	}
	if res == nil {
		return nil, fmt.Errorf("mpcrek: threshold decrypt key=%s: nil result", cfg.KeyID)
	}

	rek := res.Plaintext
	if len(rek) != 32 {
		// Zero the returned slice before discarding it.
		Zero(rek)
		return nil, fmt.Errorf("%w: got %d bytes", ErrBadREKLength, len(rek))
	}

	// Reject an all-zero REK. An attacker who could induce the cluster
	// to emit one would gain a trivial AEAD key. Use constant-time
	// comparison.
	var zero [32]byte
	if subtle.ConstantTimeCompare(rek, zero[:]) == 1 {
		Zero(rek)
		return nil, ErrZeroREK
	}

	return rek, nil
}

// Zero overwrites every byte of b with 0 and includes a runtime.KeepAlive
// to discourage the compiler from eliding the writes. This is
// best-effort: a sufficiently aggressive optimizer or a swap to disk
// could still leak the value. The Go runtime offers no harder guarantee
// without cgo + mlock + sodium-style guarded pages, which we judge
// not worth the operational complexity at this layer. The REK does NOT
// live on disk; it exists only in this process's heap from
// Bootstrap-return to Zero-call.
func Zero(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
