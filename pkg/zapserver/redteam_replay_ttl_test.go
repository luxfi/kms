// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// redteam_replay_ttl_test.go — RED TEAM adversarial proof.
//
// FINDING (HIGH): the nonce ledger TTL (DefaultNonceLedgerTTL = MaxClockSkew
// + 1m = 6m) is SHORTER than the maximum freshness lifetime of an envelope.
// The freshness check is SYMMETRIC (|now - ts| <= MaxClockSkew), so an
// envelope may be timestamped up to +MaxClockSkew in the FUTURE and still be
// accepted. Such an envelope stays fresh for up to 2*MaxClockSkew (10m) after
// it is first seen, but its ledger entry ages out after only 6m — leaving a
// window (up to 4m) in which the SAME envelope replays successfully because
// the ledger has GC'd/expired the nonce while the wall-clock check still
// passes.
//
// The nonce_ledger.go comment claims "Once an entry has aged past TTL, the
// clock-skew check would reject any envelope bearing the matching timestamp
// anyway." That reasoning is FALSE for future-dated envelopes: the entry ages
// relative to FIRST-SEEN wall-clock, not relative to ts.
//
// This test encodes the SECURE invariant: an envelope accepted once must not
// be accepted a second time while it is still within the freshness window. It
// FAILS on the current tree (TTL under-provisioned) and passes once
// DefaultNonceLedgerTTL >= 2*MaxClockSkew (+ GC margin), or the freshness
// window is made asymmetric with a tiny future allowance.
package zapserver

import (
	"context"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/log"
	badger "github.com/luxfi/zapdb"
)

func TestRedTeam_FutureDatedEnvelope_ReplayAfterTTL(t *testing.T) {
	victim := newIdentity(t, "hanzo/auto")
	defer victim.Wipe()

	// Server with a MUTABLE clock so we can advance past the nonce TTL while
	// keeping the (future-dated) envelope inside the freshness window.
	base := int64(1_717_200_000)
	var nowUnix int64 = base
	nowFn := func() time.Time { return time.Unix(atomic.LoadInt64(&nowUnix), 0) }

	opts := badger.DefaultOptions("").WithInMemory(true)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	authz, err := NewInProcessAuthorizer(InProcessAuthorizerConfig{
		Validators: NewStaticAuthorityProvider([]ids.NodeID{victim.NodeID}),
		Operator:   NewStaticAuthorityProvider(nil),
	})
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	// Default nonce ledger (TTL = MaxClockSkew + 1m = 6m).
	s := New(Config{
		Store:      store.NewSecretStore(db),
		MasterKey:  mk,
		Authorizer: authz,
		Logger:     log.NewNoOpLogger(),
		Now:        nowFn,
	})
	seed(t, s, "hanzo/auto", "api-key", "prod", "secret-1")

	skew := int64(EnvelopeMaxClockSkew / time.Second) // 300s
	ttl := int64((EnvelopeMaxClockSkew + time.Minute) / time.Second) // 360s

	// Envelope timestamped ~max-future (base + 290s, inside the +300s skew).
	ts := time.Unix(base+skew-10, 0)
	raw := signedEnvelopeBytes(t, victim, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/auto", Name: "api-key", Env: "prod",
	}), ts, "future-nonce")

	// First sighting at now == base. d = base - (base+290) = -290, |d| < 300 → fresh.
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet); err != nil {
		t.Fatalf("first (legit) delivery should be accepted: %v", err)
	}

	// Advance the clock PAST the nonce TTL but keep the envelope fresh.
	// now2 = base + 365s: ledger entry (stored at base) is now 365s old > 360s
	// TTL → treated as expired. Freshness: d = 365 - 290 = 75, |d| < 300 → still fresh.
	atomic.StoreInt64(&nowUnix, base+ttl+5)

	_, _, err = s.verifyAndAuthorize(context.Background(), raw, OpSecretGet)
	if err != nil {
		// SECURE: replay rejected even after the TTL boundary.
		t.Logf("GUARD HOLDS: future-dated replay rejected after TTL: %v", err)
		return
	}
	t.Errorf("HIGH REPLAY: a future-dated envelope (ts=base+%ds) accepted at "+
		"now=base was REPLAYED successfully at now=base+%ds — still inside the "+
		"freshness window (|now-ts|=%ds <= %ds) but past the nonce TTL (%ds). "+
		"Fix: DefaultNonceLedgerTTL must be >= 2*MaxClockSkew (+GC margin), or "+
		"make freshness asymmetric (tiny future allowance).",
		skew-10, ttl+5, (base+ttl+5)-(base+skew-10), skew, ttl)
}
