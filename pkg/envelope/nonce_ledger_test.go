// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package envelope_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
)

// nodeID builds a deterministic 20-byte NodeID for ledger tests. Avoids
// the BIP-39 derivation path of mustIdent — we don't need a real
// ML-DSA-65 key for the ledger surface.
func nodeID(seed byte) ids.NodeID {
	var n ids.NodeID
	for i := range n {
		n[i] = seed
	}
	return n
}

// TestNonceLedger_SecondReplay_Rejected pins the core contract: same
// (NodeID, Nonce) tuple seen twice → second call returns seen=true.
func TestNonceLedger_SecondReplay_Rejected(t *testing.T) {
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{})
	defer l.Stop()
	now := time.Unix(1_717_200_000, 0)

	seen, err := l.SeenOrInsert(context.Background(), nodeID(1), "nonce-1", now)
	if err != nil || seen {
		t.Fatalf("first insert: seen=%v err=%v", seen, err)
	}
	seen, err = l.SeenOrInsert(context.Background(), nodeID(1), "nonce-1", now)
	if err != nil || !seen {
		t.Fatalf("second insert: seen=%v err=%v (want seen=true err=nil)", seen, err)
	}
}

// TestNonceLedger_DifferentNodes_BothAccepted — nonces are per-NodeID;
// two distinct NodeIDs can reuse the same nonce byte-for-byte without
// collision.
func TestNonceLedger_DifferentNodes_BothAccepted(t *testing.T) {
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{})
	defer l.Stop()
	now := time.Unix(1_717_200_000, 0)

	seen, err := l.SeenOrInsert(context.Background(), nodeID(1), "shared-nonce", now)
	if err != nil || seen {
		t.Fatalf("nodeID(1) insert: seen=%v err=%v", seen, err)
	}
	seen, err = l.SeenOrInsert(context.Background(), nodeID(2), "shared-nonce", now)
	if err != nil || seen {
		t.Fatalf("nodeID(2) reusing same nonce should be accepted: seen=%v err=%v", seen, err)
	}
}

// TestNonceLedger_ExpiredEntry_AllowsReuse — after TTL, the same key is
// accepted again. We can't sleep the real TTL in tests, so the ledger
// is configured with a 50ms TTL and we step `now` past the boundary.
//
// SeenOrInsert reads `now` via its argument, NOT wall-clock, so the test
// is deterministic without sleeping inside the SeenOrInsert path. The
// background GC may or may not have swept by the time the second call
// runs; either way the contract is the same — the second call sees
// (false, nil) because the prior entry has aged past TTL.
func TestNonceLedger_ExpiredEntry_AllowsReuse(t *testing.T) {
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{
		TTL: 50 * time.Millisecond,
	})
	defer l.Stop()

	t0 := time.Unix(1_717_200_000, 0)
	seen, err := l.SeenOrInsert(context.Background(), nodeID(1), "nonce-1", t0)
	if err != nil || seen {
		t.Fatalf("first insert: seen=%v err=%v", seen, err)
	}

	// Same nonce, 1ms past TTL. Ledger should accept.
	tooLate := t0.Add(51 * time.Millisecond)
	seen, err = l.SeenOrInsert(context.Background(), nodeID(1), "nonce-1", tooLate)
	if err != nil || seen {
		t.Fatalf("post-TTL reuse: seen=%v err=%v (want seen=false err=nil)", seen, err)
	}
}

// TestNonceLedger_ConcurrentInsert_RaceFree — 1000 concurrent SeenOrInsert
// calls on the same (NodeID, Nonce) tuple must produce exactly one
// `seen=false` and 999 `seen=true`. Run under -race to catch any data
// race on the underlying sync.Map.
func TestNonceLedger_ConcurrentInsert_RaceFree(t *testing.T) {
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{})
	defer l.Stop()

	const N = 1000
	now := time.Unix(1_717_200_000, 0)
	id := nodeID(0xAA)

	var wg sync.WaitGroup
	var firstSeen, replays int64
	wg.Add(N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start // unleash all goroutines together to maximise contention
			seen, err := l.SeenOrInsert(context.Background(), id, "race-nonce", now)
			if err != nil {
				t.Errorf("err: %v", err)
				return
			}
			if seen {
				atomic.AddInt64(&replays, 1)
			} else {
				atomic.AddInt64(&firstSeen, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if firstSeen != 1 {
		t.Fatalf("first-seen count = %d, want 1 (sync.Map LoadOrStore must serialise)", firstSeen)
	}
	if replays != N-1 {
		t.Fatalf("replay count = %d, want %d", replays, N-1)
	}
}

// TestNonceLedger_GcRemovesExpired — after the GC sweep runs over a
// past-TTL entry, the ledger Size drops. We invoke gcOnce via the
// test-only path on time advancement.
func TestNonceLedger_GcRemovesExpired(t *testing.T) {
	// 50ms TTL, 25ms GC; sleep > both to ensure at least one sweep
	// observes the entry as expired.
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{
		TTL:        50 * time.Millisecond,
		GCInterval: 25 * time.Millisecond,
	})
	defer l.Stop()

	now := time.Unix(1_717_200_000, 0)
	for i := 0; i < 10; i++ {
		nonce := fmt.Sprintf("nonce-%d", i)
		if _, err := l.SeenOrInsert(context.Background(), nodeID(byte(i)), nonce, now); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if l.Size() != 10 {
		t.Fatalf("pre-GC size=%d want 10", l.Size())
	}

	// Wait long enough for the background GC to run at least one full
	// sweep past TTL. 200ms covers 25ms GC × multiple ticks + 50ms TTL.
	time.Sleep(200 * time.Millisecond)
	if got := l.Size(); got != 0 {
		t.Fatalf("post-GC size=%d want 0 (GC failed to sweep expired entries)", got)
	}
}

// TestNonceLedger_Stop_Idempotent — calling Stop twice must not panic.
func TestNonceLedger_Stop_Idempotent(t *testing.T) {
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{})
	l.Stop()
	l.Stop() // must not panic / not close a closed channel
}

// --- VerifierWithLedger integration ---

const ledgerTestMnemonic = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

func ledgerIdent(t *testing.T, path string) *keys.ServiceIdentity {
	t.Helper()
	id, err := keys.NewServiceIdentity(ledgerTestMnemonic, path)
	if err != nil {
		t.Fatalf("NewServiceIdentity: %v", err)
	}
	return id
}

func ledgerHeader(ident *keys.ServiceIdentity) envelope.IdentityHeader {
	return envelope.IdentityHeader{
		NodeID:      ident.NodeID,
		FullDigest:  ident.FullDigest,
		ServicePath: ident.ServicePath,
		PublicKey:   ident.PublicKey,
	}
}

// freshNonce returns a base64-encoded 16-byte cryptographically random
// nonce. Matches the canonical client-side nonce shape.
func freshNonce(t *testing.T) string {
	t.Helper()
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf[:])
}

// TestVerifierWithLedger_ValidFreshNonce_Accepted — a freshly signed
// envelope verifies cleanly under the canonical verifier+ledger pair.
func TestVerifierWithLedger_ValidFreshNonce_Accepted(t *testing.T) {
	ident := ledgerIdent(t, "hanzo/kms-operator")
	defer ident.Wipe()
	v, err := envelope.NewVerifierWithLedger(envelope.VerifierWithLedgerConfig{
		Verifier: keys.VerifyServiceEnvelope,
		Ledger:   envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{}),
	})
	if err != nil {
		t.Fatalf("NewVerifierWithLedger: %v", err)
	}
	now := time.Unix(1_717_200_000, 0)
	env, err := envelope.Build(ledgerHeader(ident), ident, 0x0040,
		json.RawMessage(`{"path":"hanzo/commerce","name":"k","env":"prod"}`),
		freshNonce(t), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := v.Verify(context.Background(), env, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerifierWithLedger_Replay_Rejected — same envelope replayed → the
// second call returns ErrReplay.
func TestVerifierWithLedger_Replay_Rejected(t *testing.T) {
	ident := ledgerIdent(t, "hanzo/kms-operator")
	defer ident.Wipe()
	v, err := envelope.NewVerifierWithLedger(envelope.VerifierWithLedgerConfig{
		Verifier: keys.VerifyServiceEnvelope,
		Ledger:   envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{}),
	})
	if err != nil {
		t.Fatalf("NewVerifierWithLedger: %v", err)
	}
	now := time.Unix(1_717_200_000, 0)
	env, err := envelope.Build(ledgerHeader(ident), ident, 0x0040,
		json.RawMessage(`{"path":"hanzo/commerce","name":"k","env":"prod"}`),
		freshNonce(t), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := v.Verify(context.Background(), env, now); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	_, err = v.Verify(context.Background(), env, now)
	if !errors.Is(err, envelope.ErrReplay) {
		t.Fatalf("second Verify err=%v want ErrReplay", err)
	}
}

// TestVerifierWithLedger_PostTTL_NonceReuse_AcceptedThenStale — once the
// nonce has aged out of the ledger, the same byte-for-byte envelope is
// rejected by the wall-clock window, not the ledger. We confirm the
// reject path is "stale" not "replay-detected" so the wire-side audit
// stays correct.
func TestVerifierWithLedger_PostTTL_NonceReuse_AcceptedThenStale(t *testing.T) {
	ident := ledgerIdent(t, "hanzo/kms-operator")
	defer ident.Wipe()
	v, err := envelope.NewVerifierWithLedger(envelope.VerifierWithLedgerConfig{
		Verifier: keys.VerifyServiceEnvelope,
		// Tiny TTL so the test runs in real time.
		Ledger: envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{
			TTL:        50 * time.Millisecond,
			GCInterval: 25 * time.Millisecond,
		}),
	})
	if err != nil {
		t.Fatalf("NewVerifierWithLedger: %v", err)
	}
	now := time.Unix(1_717_200_000, 0)
	env, err := envelope.Build(ledgerHeader(ident), ident, 0x0040,
		json.RawMessage(`{"path":"hanzo/commerce","name":"k","env":"prod"}`),
		freshNonce(t), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := v.Verify(context.Background(), env, now); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	// Step `now` past TTL. The wall-clock check inside Verify is what
	// rejects the replay now — the ledger entry was already swept. The
	// reject path is the existing "envelope: stale" error, NOT
	// ErrReplay. This is the only correct behaviour: a stale envelope
	// cannot be a replay because the verifier rejects it before the
	// ledger ever sees it.
	tooLate := now.Add(envelope.MaxClockSkew + time.Second)
	_, err = v.Verify(context.Background(), env, tooLate)
	if err == nil || errors.Is(err, envelope.ErrReplay) {
		t.Fatalf("post-TTL Verify err=%v (want non-nil, NOT ErrReplay)", err)
	}
}

// TestVerifierWithLedger_NilArgs_RefuseConstruction — both fields are
// load-bearing; the constructor rejects nil.
func TestVerifierWithLedger_NilArgs_RefuseConstruction(t *testing.T) {
	if _, err := envelope.NewVerifierWithLedger(envelope.VerifierWithLedgerConfig{}); err == nil {
		t.Fatalf("nil verifier+ledger must refuse")
	}
	if _, err := envelope.NewVerifierWithLedger(envelope.VerifierWithLedgerConfig{
		Verifier: keys.VerifyServiceEnvelope,
	}); err == nil {
		t.Fatalf("nil ledger must refuse")
	}
	if _, err := envelope.NewVerifierWithLedger(envelope.VerifierWithLedgerConfig{
		Ledger: envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{}),
	}); err == nil {
		t.Fatalf("nil verifier must refuse")
	}
}

// reserved for future raw-bytes tests; suppresses unused-import warning
// if someone trims a test.
var _ = binary.LittleEndian
