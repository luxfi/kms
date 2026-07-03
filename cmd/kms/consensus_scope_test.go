// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// consensus_scope_test.go — coverage for the kmsd's consumption of the
// least-privilege `scopes` overlay in the consensus snapshot
// (KMS_CONSENSUS_FILE). Proves the boot-time wiring turns a scoped snapshot
// into a scoped authorizer (straddle / parent / sibling / no-grant all
// deny), that a flat snapshot stays unconfined (back-compat), and that a
// malformed scope grant refuses to boot (fail closed on bad input).

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/kms/pkg/zapserver"
)

// scopeTestNode returns a deterministic non-zero NodeID whose String()
// round-trips through ids.NodeIDFromString (the parse path the snapshot
// loader uses).
func scopeTestNode(seed byte) ids.NodeID {
	var n ids.NodeID
	for i := range n {
		n[i] = seed
	}
	return n
}

// writeSnapshot marshals snap to a temp file and points KMS_CONSENSUS_FILE
// at it, clearing the env-var carriage so the file path is authoritative.
func writeSnapshot(t *testing.T, snap consensusSnapshot) {
	t.Helper()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	path := filepath.Join(t.TempDir(), "consensus-authority.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	t.Setenv(envValidators, "")
	t.Setenv(envOperators, "")
	t.Setenv(envTTL, "")
	t.Setenv(envFile, path)
}

func mustAuthz(t *testing.T) zapserver.ConsensusAuthorizer {
	t.Helper()
	az, err := buildConsensusAuthorizer()
	if err != nil {
		t.Fatalf("buildConsensusAuthorizer: %v", err)
	}
	return az
}

func allow(t *testing.T, az zapserver.ConsensusAuthorizer, node ids.NodeID, path string, op zapserver.Op) {
	t.Helper()
	d, err := az.Authorize(context.Background(), zapserver.Identity{NodeID: node}, path, op)
	if err != nil {
		t.Fatalf("Authorize(%s, %q) unexpected err: %v", op, path, err)
	}
	if !d.Allow {
		t.Fatalf("Authorize(%s, %q) must ALLOW, got deny(%s)", op, path, d.Reason)
	}
}

func deny(t *testing.T, az zapserver.ConsensusAuthorizer, node ids.NodeID, path string, op zapserver.Op) {
	t.Helper()
	d, err := az.Authorize(context.Background(), zapserver.Identity{NodeID: node}, path, op)
	if err != nil {
		t.Fatalf("Authorize(%s, %q) unexpected err: %v", op, path, err)
	}
	if d.Allow {
		t.Fatalf("Authorize(%s, %q) must DENY (scope), got allow", op, path)
	}
}

// TestConsensusScopes_ScopedSnapshot_Enforced — a snapshot carrying a
// scopes.validators grant confines the reader to its subtree; a co-member
// with no grant fails closed.
func TestConsensusScopes_ScopedSnapshot_Enforced(t *testing.T) {
	commerce := scopeTestNode(0x11)
	kms := scopeTestNode(0x22)

	writeSnapshot(t, consensusSnapshot{
		Validators: []string{commerce.String(), kms.String()},
		Operators:  []string{commerce.String()},
		Scopes: &consensusScopes{
			Validators: map[string]string{commerce.String(): "hanzo/commerce"},
			// kms is a member but carries no grant → fail closed.
			Operators: map[string]string{commerce.String(): "hanzo/commerce"},
		},
	})
	az := mustAuthz(t)

	// commerce reads its own subtree.
	allow(t, az, commerce, "hanzo/commerce", zapserver.OpAuthGet)
	allow(t, az, commerce, "hanzo/commerce/db", zapserver.OpAuthGet)

	// commerce cannot escape its subtree.
	deny(t, az, commerce, "hanzo", zapserver.OpAuthGet)               // parent
	deny(t, az, commerce, "hanzo/kms", zapserver.OpAuthGet)           // sibling
	deny(t, az, commerce, "hanzo/commerce-evil", zapserver.OpAuthGet) // straddle
	deny(t, az, commerce, "hanzo/commerce-evil/x", zapserver.OpAuthGet)

	// kms is a scoped member with NO grant → denied everything (fail closed).
	deny(t, az, kms, "hanzo/kms", zapserver.OpAuthGet)
	deny(t, az, kms, "hanzo/commerce", zapserver.OpAuthGet)

	// In-scope write for commerce (member of the operator authority too).
	allow(t, az, commerce, "hanzo/commerce/api-key", zapserver.OpAuthPut)
	deny(t, az, commerce, "hanzo/kms", zapserver.OpAuthPut)
}

// TestConsensusScopes_FlatSnapshot_Unconfined — a snapshot WITHOUT a scopes
// block leaves both authorities flat: every member reads/writes any path
// (the pre-existing role-based posture; back-compat).
func TestConsensusScopes_FlatSnapshot_Unconfined(t *testing.T) {
	a := scopeTestNode(0x33)

	writeSnapshot(t, consensusSnapshot{
		Validators: []string{a.String()},
		Operators:  []string{a.String()},
		// No Scopes.
	})
	az := mustAuthz(t)

	for _, p := range []string{"hanzo/commerce", "lux/bridge", "anything/at/all"} {
		allow(t, az, a, p, zapserver.OpAuthGet)
		allow(t, az, a, p, zapserver.OpAuthPut)
	}
}

// TestConsensusScopes_PartialScope_ReadScopedWriteFlat — the two authorities
// scope independently: scopes.validators present (read confined) while
// scopes.operators absent (write flat).
func TestConsensusScopes_PartialScope_ReadScopedWriteFlat(t *testing.T) {
	a := scopeTestNode(0x44)

	writeSnapshot(t, consensusSnapshot{
		Validators: []string{a.String()},
		Operators:  []string{a.String()},
		Scopes: &consensusScopes{
			Validators: map[string]string{a.String(): "hanzo/commerce"},
			// Operators nil → flat write authority.
		},
	})
	az := mustAuthz(t)

	// Read confined.
	allow(t, az, a, "hanzo/commerce/x", zapserver.OpAuthGet)
	deny(t, az, a, "hanzo/kms", zapserver.OpAuthGet)

	// Write flat (unconfined) — a is in the operator set with no operator
	// scope, so the write scope check is a no-op. It must still pass the
	// validator gate+scope first, so pick an in-read-scope path.
	allow(t, az, a, "hanzo/commerce/x", zapserver.OpAuthPut)
}

// TestConsensusScopes_MalformedScopeKey_RefusesToBoot — a scope grant keyed
// by a non-NodeID string is a hard failure. The kmsd refuses to construct
// the authorizer rather than silently drop the grant (which would fail-open
// a member to unconfined or drop it entirely).
func TestConsensusScopes_MalformedScopeKey_RefusesToBoot(t *testing.T) {
	a := scopeTestNode(0x55)

	writeSnapshot(t, consensusSnapshot{
		Validators: []string{a.String()},
		Operators:  []string{a.String()},
		Scopes: &consensusScopes{
			Validators: map[string]string{"not-a-valid-nodeid": "hanzo/commerce"},
		},
	})
	if _, err := buildConsensusAuthorizer(); err == nil {
		t.Fatalf("malformed scope key must refuse to boot, got nil error")
	}
}

// TestConsensusScopes_EmptyScopeMap_FailsClosed — a scopes.validators that
// is present but empty opts the authority into scoping with ZERO grants:
// every member is denied (fail closed), NOT defaulted to unconfined. Guards
// against a "present but empty" snapshot silently disabling confinement.
func TestConsensusScopes_EmptyScopeMap_FailsClosed(t *testing.T) {
	a := scopeTestNode(0x66)

	writeSnapshot(t, consensusSnapshot{
		Validators: []string{a.String()},
		Operators:  []string{a.String()},
		Scopes: &consensusScopes{
			Validators: map[string]string{}, // present, empty → scoped, no grants
		},
	})
	az := mustAuthz(t)
	deny(t, az, a, "hanzo/commerce", zapserver.OpAuthGet)
}
