// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// nonce_ledger_cap_test.go — coverage for the TTL invariant (RED HIGH) and
// the live-entry cap (RED MEDIUM) on the anti-replay ledger.

package envelope_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luxfi/kms/pkg/envelope"
)

// TestNonceLedgerTTL_ExceedsTwiceMaxClockSkew pins the security invariant
// the RED future-dated-replay proof depends on: a ledger entry must outlive
// the longest span a single (symmetrically-fresh) timestamp is acceptable,
// which is 2*MaxClockSkew. If a future edit drops the TTL back to
// MaxClockSkew+margin, the replay window reopens — this test fails first.
func TestNonceLedgerTTL_ExceedsTwiceMaxClockSkew(t *testing.T) {
	if envelope.DefaultNonceLedgerTTL <= 2*envelope.MaxClockSkew {
		t.Fatalf("DefaultNonceLedgerTTL=%s must strictly exceed 2*MaxClockSkew=%s "+
			"(else a future-dated envelope replays past the ledger TTL)",
			envelope.DefaultNonceLedgerTTL, 2*envelope.MaxClockSkew)
	}
	// The concrete value also carries a GC margin so the exact boundary
	// (entry-age == freshness-edge) rejects.
	if want := 2*envelope.MaxClockSkew + time.Minute; envelope.DefaultNonceLedgerTTL != want {
		t.Fatalf("DefaultNonceLedgerTTL=%s, want %s (2*MaxClockSkew + GC margin)",
			envelope.DefaultNonceLedgerTTL, want)
	}
}

// TestNonceLedger_Cap_FailsClosedAtLimit — at the MaxEntries cap a genuinely
// new (node, nonce) tuple is rejected with ErrLedgerFull (fail closed), not
// silently accepted without replay defence. The failed insert must not
// leave a phantom entry (count stays honest).
func TestNonceLedger_Cap_FailsClosedAtLimit(t *testing.T) {
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{
		MaxEntries: 2,
		// Large TTL/GC so nothing ages out mid-test.
		TTL:        time.Hour,
		GCInterval: time.Hour,
	})
	defer l.Stop()
	now := time.Unix(1_717_200_000, 0)
	ctx := context.Background()
	node := nodeID(1)

	if seen, err := l.SeenOrInsert(ctx, node, "n1", now); err != nil || seen {
		t.Fatalf("n1: seen=%v err=%v", seen, err)
	}
	if seen, err := l.SeenOrInsert(ctx, node, "n2", now); err != nil || seen {
		t.Fatalf("n2: seen=%v err=%v", seen, err)
	}
	// Third distinct tuple exceeds the cap → fail closed.
	if _, err := l.SeenOrInsert(ctx, node, "n3", now); !errors.Is(err, envelope.ErrLedgerFull) {
		t.Fatalf("n3 at cap: err=%v, want ErrLedgerFull", err)
	}
	// The rejected insert must not have grown the ledger.
	if got := l.Size(); got != 2 {
		t.Fatalf("ledger size after rejected insert = %d, want 2 (no phantom entry)", got)
	}
}

// TestNonceLedger_Cap_ReplayStillDetectedAtLimit — being at the cap must not
// blind the ledger to a replay of an ALREADY-recorded tuple. Only genuinely
// new tuples are rejected; a resubmission still returns seen=true.
func TestNonceLedger_Cap_ReplayStillDetectedAtLimit(t *testing.T) {
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{
		MaxEntries: 1,
		TTL:        time.Hour,
		GCInterval: time.Hour,
	})
	defer l.Stop()
	now := time.Unix(1_717_200_000, 0)
	ctx := context.Background()
	node := nodeID(7)

	if seen, err := l.SeenOrInsert(ctx, node, "only", now); err != nil || seen {
		t.Fatalf("first: seen=%v err=%v", seen, err)
	}
	// At cap, replay of the same tuple → detected (seen=true), not full.
	if seen, err := l.SeenOrInsert(ctx, node, "only", now); err != nil || !seen {
		t.Fatalf("replay at cap: seen=%v err=%v, want seen=true err=nil", seen, err)
	}
	// A different tuple at cap → fail closed.
	if _, err := l.SeenOrInsert(ctx, node, "other", now); !errors.Is(err, envelope.ErrLedgerFull) {
		t.Fatalf("new tuple at cap: err=%v, want ErrLedgerFull", err)
	}
}

// TestNonceLedger_Cap_CountReleasedByGC — after GC sweeps expired entries
// the freed slots are usable again. Entries are timestamped far in the past,
// so the background GC (real wall-clock) always sees them as expired; once
// swept, a formerly-capped insert succeeds — proving the counter tracked the
// deletions (else the cap would stay saturated forever).
func TestNonceLedger_Cap_CountReleasedByGC(t *testing.T) {
	l := envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{
		MaxEntries: 2,
		TTL:        50 * time.Millisecond,
		GCInterval: 25 * time.Millisecond,
	})
	defer l.Stop()
	past := time.Unix(1_717_200_000, 0) // far before real now → always expired
	ctx := context.Background()

	for _, n := range []string{"a", "b"} {
		if seen, err := l.SeenOrInsert(ctx, nodeID(9), n, past); err != nil || seen {
			t.Fatalf("insert %s: seen=%v err=%v", n, seen, err)
		}
	}
	// At cap now; a new tuple would fail closed before GC.
	if _, err := l.SeenOrInsert(ctx, nodeID(9), "c", past); !errors.Is(err, envelope.ErrLedgerFull) {
		t.Fatalf("pre-GC new tuple: err=%v, want ErrLedgerFull", err)
	}

	// Let the background GC sweep the past-dated entries.
	time.Sleep(200 * time.Millisecond)
	if got := l.Size(); got != 0 {
		t.Fatalf("post-GC size=%d, want 0", got)
	}
	// Slots are free again → the insert that was capped now succeeds.
	if seen, err := l.SeenOrInsert(ctx, nodeID(9), "c", past); err != nil || seen {
		t.Fatalf("post-GC insert: seen=%v err=%v, want seen=false err=nil "+
			"(counter failed to release GC'd slots)", seen, err)
	}
}
