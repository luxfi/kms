// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// nonce_ledger.go — anti-replay ledger for envelope nonces.
//
// The wall-clock freshness window (MaxClockSkew) caps how long a captured
// envelope is replayable, but within the window an attacker who observes
// one valid envelope can resubmit it verbatim. For OpSecretGet that
// produces audit-log churn the attacker controls; for OpSecretPut /
// OpSecretDelete it can be weaponised to obscure a parallel intrusion in
// audit noise or to cancel a legitimate in-flight delete. We close the
// window by ledgering (NodeID, Nonce) on the verifier side and rejecting
// any second sighting before the nonce ages out of the ledger.
//
// Design properties
//
//   - Per-node nonce space. Two distinct signers may reuse the same
//     nonce byte-for-byte without collision; the keying tuple is
//     (NodeID, Nonce). This matches the wire reality: nonces are
//     caller-fresh, not globally coordinated.
//
//   - TTL = 2*MaxClockSkew + 1m. An entry MUST outlive the longest time a
//     single timestamp stays fresh. Freshness is symmetric
//     (|now-ts| <= MaxClockSkew), so one ts is acceptable across a
//     2*MaxClockSkew real-time span (ts-MaxClockSkew .. ts+MaxClockSkew).
//     A ledger entry ages from FIRST-SEEN, so a maximally future-dated
//     envelope first seen at the earliest acceptable instant is still fresh
//     2*MaxClockSkew later. With the old TTL (MaxClockSkew+1m) the entry
//     GC'd while the envelope was still fresh and the SAME envelope
//     replayed (RED finding). The trailing minute is GC margin so the
//     boundary (entry-age == freshness-edge) still rejects.
//
//   - First-write-wins. SeenOrInsert returns true (duplicate) for every
//     call after the first within TTL. The first caller wins; the second
//     call sees `seen == true` and the verifier rejects.
//
//   - Race-clean. sync.Map handles the lookup/insert atomically via
//     LoadOrStore. No two goroutines can both observe `seen == false`
//     for the same key.
//
//   - GC budget. A background loop sweeps expired entries every
//     gcInterval (default = TTL/4 = 90s for the default 6m TTL). Inline
//     opportunistic GC is NOT performed in the hot path — the wall-clock
//     check happens earlier and the ledger Insert path stays O(1).
//
// Production sizing (informational, no enforcement)
//
//   100 services × 60 envelopes/min × 11m TTL ≈ 66 000 live entries.
//   sync.Map overhead per entry ≈ 80 bytes (key 36 + value 8 + Go map
//   overhead). Working set ≈ 5 MB. Well within budget for an in-process
//   ledger; no need to fall back to disk-backed storage at this scale.
//
// Bounded (enforcement, not informational)
//
//   An unbounded ledger is a memory-DoS surface: an attacker holding one
//   valid key can emit fresh-nonce envelopes to grow the map without limit.
//   MaxEntries caps live entries (default 1e6 ≈ 80 MB). At the cap
//   SeenOrInsert fails CLOSED (ErrLedgerFull) — a KMS that cannot ledger a
//   nonce cannot prove it isn't a replay, so it must reject, never accept
//   without replay defence. Availability-fail-closed on the secrets plane
//   is the correct trade: reject under flood, never OOM the daemon.

package envelope

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/ids"
)

// ErrLedgerFull is returned by SeenOrInsert when the ledger is at its
// MaxEntries cap and the (node, nonce) tuple is not already present. The
// verifier treats it as fail-closed: a nonce that cannot be ledgered
// cannot be proven fresh, so the request is rejected. Distinct from a
// replay so audit logs can tell a flood apart from a resubmission.
var ErrLedgerFull = errors.New("envelope: nonce ledger at capacity")

// NonceLedger is the contract the envelope verifier talks to. Production
// impls are typically the in-memory ledger; deployments that need
// cross-process replay defence (e.g. multi-replica kmsd behind a load
// balancer) supply a shared backend.
//
// The contract:
//
//   - SeenOrInsert returns (true, nil) iff (node, nonce) is already
//     recorded as live in the ledger. Returns (false, nil) and atomically
//     records the entry on the first call within TTL.
//
//   - SeenOrInsert MUST be safe for concurrent use. The verifier calls
//     it on every request; a serial impl would bottleneck the surface.
//
//   - SeenOrInsert MUST be deterministic per key: once a key returns
//     (false, nil), every subsequent call within TTL returns (true, nil)
//     until GC ages the entry out.
//
// Errors are reserved for transport failures in disk- or network-backed
// impls. The in-memory ledger never returns an error.
type NonceLedger interface {
	SeenOrInsert(ctx context.Context, node ids.NodeID, nonce string, now time.Time) (bool, error)
}

// DefaultNonceLedgerTTL is the per-entry lifetime. It MUST strictly exceed
// 2*MaxClockSkew — the longest real-time span over which a single
// (symmetrically-fresh) timestamp is acceptable — so a ledger entry, which
// ages from first-seen, can never GC while its envelope is still fresh.
// The trailing minute is GC margin against the exact boundary.
const DefaultNonceLedgerTTL = 2*MaxClockSkew + time.Minute

// DefaultNonceLedgerMaxEntries caps live entries in the in-memory ledger.
// ~66k live entries is the expected production working set (see sizing
// note above); 1e6 (≈ 80 MB) leaves generous headroom while bounding a
// nonce-flood memory DoS. At the cap SeenOrInsert fails closed.
const DefaultNonceLedgerMaxEntries = 1_000_000

// DefaultNonceLedgerGCInterval is the sweep cadence for the background
// GC goroutine. Smaller values reduce peak memory but burn CPU; the
// default trades 25% TTL granularity for low-cost sweeps.
const DefaultNonceLedgerGCInterval = DefaultNonceLedgerTTL / 4

// nonceKey is the composite map key. NodeID is 20 bytes; nonce string is
// caller-fresh (typically 16 bytes base64-encoded → 24 chars). Both are
// value types so the struct is map-key safe.
type nonceKey struct {
	node  ids.NodeID
	nonce string
}

// MemoryNonceLedger is the canonical in-process NonceLedger. Backed by
// sync.Map for low-contention concurrent SeenOrInsert.
type MemoryNonceLedger struct {
	ttl        time.Duration
	gcInterval time.Duration
	max        int64 // live-entry cap; <= 0 means unbounded

	entries sync.Map     // map[nonceKey]time.Time — first-seen wall-clock
	count   atomic.Int64 // live-entry counter, kept in step with entries

	stopCh chan struct{}
	stopMu sync.Mutex
}

// MemoryNonceLedgerConfig wires a MemoryNonceLedger. Zero values pick
// the package defaults (DefaultNonceLedgerTTL, DefaultNonceLedgerGCInterval).
type MemoryNonceLedgerConfig struct {
	// TTL is the per-entry lifetime. 0 → DefaultNonceLedgerTTL.
	TTL time.Duration
	// GCInterval is the background sweep cadence. 0 → DefaultNonceLedgerGCInterval.
	GCInterval time.Duration
	// MaxEntries caps live entries. 0 → DefaultNonceLedgerMaxEntries.
	// A negative value disables the cap (unbounded) — tests only; never
	// run a production ledger unbounded.
	MaxEntries int64
}

// NewMemoryNonceLedger returns a fresh in-memory ledger and starts its
// background GC goroutine. Call Stop() at process shutdown to release
// the goroutine. Production callers typically wire one ledger per kmsd
// process and never Stop until the daemon shuts down.
func NewMemoryNonceLedger(cfg MemoryNonceLedgerConfig) *MemoryNonceLedger {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultNonceLedgerTTL
	}
	gc := cfg.GCInterval
	if gc <= 0 {
		gc = DefaultNonceLedgerGCInterval
	}
	// 0 → default cap; negative → unbounded (tests only).
	max := cfg.MaxEntries
	if max == 0 {
		max = DefaultNonceLedgerMaxEntries
	}
	if max < 0 {
		max = 0 // unbounded sentinel
	}
	l := &MemoryNonceLedger{
		ttl:        ttl,
		gcInterval: gc,
		max:        max,
		stopCh:     make(chan struct{}),
	}
	go l.gcLoop()
	return l
}

// SeenOrInsert atomically checks and records (node, nonce). Returns true
// if the key was already present (replay), false if first sighting.
func (l *MemoryNonceLedger) SeenOrInsert(_ context.Context, node ids.NodeID, nonce string, now time.Time) (bool, error) {
	k := nonceKey{node: node, nonce: nonce}
	// LoadOrStore returns (existing, true) if the key was present, or
	// (stored, false) on first insert. Two concurrent inserts race
	// atomically — exactly one returns (_, false).
	prev, loaded := l.entries.LoadOrStore(k, now)
	if !loaded {
		// A brand-new entry. Charge it against the cap; if that pushes us
		// over, undo the insert and fail closed. We check AFTER inserting
		// (not before) so a concurrent replay of the SAME key is still
		// detected at the cap — only genuinely-new keys are rejected.
		if l.max > 0 && l.count.Add(1) > l.max {
			l.entries.Delete(k)
			l.count.Add(-1)
			return false, ErrLedgerFull
		}
		return false, nil
	}
	// A prior entry exists. If it has aged past TTL we treat the slot
	// as expired — the GC just hasn't swept it yet — and overwrite with
	// the new wall-clock. The key already exists, so the live-entry count
	// is unchanged. Concurrent overwrites collapse to last-write-wins;
	// either outcome leaves a fresh entry, which is what the caller would
	// have gotten from a clean ledger.
	if prevTS, ok := prev.(time.Time); ok && now.Sub(prevTS) >= l.ttl {
		l.entries.Store(k, now)
		return false, nil
	}
	return true, nil
}

// Size reports the live entry count. Useful for tests + observability.
// Walks the entire map; not a hot-path operation.
func (l *MemoryNonceLedger) Size() int {
	n := 0
	l.entries.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// Stop ends the background GC goroutine. Safe to call multiple times.
func (l *MemoryNonceLedger) Stop() {
	l.stopMu.Lock()
	defer l.stopMu.Unlock()
	select {
	case <-l.stopCh:
		// already stopped
	default:
		close(l.stopCh)
	}
}

// gcLoop sweeps expired entries every gcInterval. Runs until Stop() is
// called. Each sweep is O(n) over the entry map; at 36k entries this is
// microseconds — invisible to the request path.
func (l *MemoryNonceLedger) gcLoop() {
	t := time.NewTicker(l.gcInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case now := <-t.C:
			l.gcOnce(now)
		}
	}
}

// gcOnce is one sweep. Exported via test hook only — production callers
// rely on the background goroutine.
func (l *MemoryNonceLedger) gcOnce(now time.Time) {
	cutoff := now.Add(-l.ttl)
	l.entries.Range(func(k, v any) bool {
		if ts, ok := v.(time.Time); ok && ts.Before(cutoff) {
			// CompareAndDelete protects against a concurrent
			// SeenOrInsert that re-inserted a fresh entry at the
			// same key after we read it: only delete the exact
			// stale value. Decrement the live counter only on a
			// delete we actually performed, so count stays in step
			// with the map (and the cap stays honest).
			if l.entries.CompareAndDelete(k, ts) {
				l.count.Add(-1)
			}
		}
		return true
	})
}
