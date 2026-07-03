// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// path_scope_test.go — coverage for authority-anchored path scoping on the
// InProcessAuthorizer (RED MEDIUM: least privilege / blast-radius). Scope is
// authority-side data keyed on the cryptographically-bound NodeID; it is
// never taken from the caller's self-declared ServicePath.

package zapserver

import (
	"context"
	"testing"

	"github.com/luxfi/ids"
)

// scopeNode builds a deterministic non-zero NodeID for authorizer tests.
func scopeNode(seed byte) ids.NodeID {
	var n ids.NodeID
	for i := range n {
		n[i] = seed
	}
	return n
}

func mustAuthorizer(t *testing.T, cfg InProcessAuthorizerConfig) *InProcessAuthorizer {
	t.Helper()
	a, err := NewInProcessAuthorizer(cfg)
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	return a
}

// TestScopedAuthz_ReadWithinScope_Allowed — a scoped validator may read at
// its scope root and any descendant.
func TestScopedAuthz_ReadWithinScope_Allowed(t *testing.T) {
	node := scopeNode(1)
	a := mustAuthorizer(t, InProcessAuthorizerConfig{
		Validators: NewScopedAuthorityProvider([]ids.NodeID{node}, map[ids.NodeID]string{node: "hanzo/commerce"}),
		Operator:   NewStaticAuthorityProvider(nil),
	})
	for _, p := range []string{"hanzo/commerce", "hanzo/commerce/db", "hanzo/commerce/db/replica"} {
		d, err := a.Authorize(context.Background(), Identity{NodeID: node}, p, OpAuthGet)
		if err != nil || !d.Allow {
			t.Fatalf("read %q: allow=%v reason=%q err=%v", p, d.Allow, d.Reason, err)
		}
	}
}

// TestScopedAuthz_ReadOutsideScope_Denied — a scoped validator cannot read a
// sibling subtree, the parent, or a straddling prefix.
func TestScopedAuthz_ReadOutsideScope_Denied(t *testing.T) {
	node := scopeNode(2)
	a := mustAuthorizer(t, InProcessAuthorizerConfig{
		Validators: NewScopedAuthorityProvider([]ids.NodeID{node}, map[ids.NodeID]string{node: "hanzo/commerce"}),
		Operator:   NewStaticAuthorityProvider(nil),
	})
	for _, p := range []string{
		"hanzo/kms-operator",  // sibling subtree
		"hanzo",               // parent
		"hanzo/commerce-evil", // straddling prefix — must NOT match "hanzo/commerce"
		"lux/bridge",
	} {
		d, err := a.Authorize(context.Background(), Identity{NodeID: node}, p, OpAuthGet)
		if err != nil {
			t.Fatalf("read %q: unexpected err=%v", p, err)
		}
		if d.Allow {
			t.Fatalf("read %q must be denied (outside scope), got allow", p)
		}
	}
}

// TestScopedAuthz_WriteConfinedByOperatorScope — writes are confined by the
// OPERATOR (write) authority's scope; in-scope allowed, out-of-scope denied.
func TestScopedAuthz_WriteConfinedByOperatorScope(t *testing.T) {
	node := scopeNode(3)
	a := mustAuthorizer(t, InProcessAuthorizerConfig{
		Validators: NewScopedAuthorityProvider([]ids.NodeID{node}, map[ids.NodeID]string{node: "hanzo/commerce"}),
		Operator:   NewScopedAuthorityProvider([]ids.NodeID{node}, map[ids.NodeID]string{node: "hanzo/commerce"}),
	})
	if d, err := a.Authorize(context.Background(), Identity{NodeID: node}, "hanzo/commerce/api-key", OpAuthPut); err != nil || !d.Allow {
		t.Fatalf("in-scope write: allow=%v reason=%q err=%v", d.Allow, d.Reason, err)
	}
	if d, _ := a.Authorize(context.Background(), Identity{NodeID: node}, "hanzo/kms-operator", OpAuthPut); d.Allow {
		t.Fatalf("out-of-scope write must be denied, got allow")
	}
	// OpSign is a privileged write and must be confined the same way.
	if d, _ := a.Authorize(context.Background(), Identity{NodeID: node}, "lux/bridge", OpAuthSign); d.Allow {
		t.Fatalf("out-of-scope sign must be denied, got allow")
	}
}

// TestScopedAuthz_UnscopedProvider_Unconfined — a flat provider preserves the
// pre-existing role-based posture: members are unconfined (back-compat).
func TestScopedAuthz_UnscopedProvider_Unconfined(t *testing.T) {
	node := scopeNode(4)
	a := mustAuthorizer(t, InProcessAuthorizerConfig{
		Validators: NewStaticAuthorityProvider([]ids.NodeID{node}),
		Operator:   NewStaticAuthorityProvider([]ids.NodeID{node}),
	})
	for _, p := range []string{"hanzo/commerce", "lux/bridge", "anything/at/all"} {
		if d, err := a.Authorize(context.Background(), Identity{NodeID: node}, p, OpAuthGet); err != nil || !d.Allow {
			t.Fatalf("flat read %q: allow=%v err=%v", p, d.Allow, err)
		}
		if d, err := a.Authorize(context.Background(), Identity{NodeID: node}, p, OpAuthPut); err != nil || !d.Allow {
			t.Fatalf("flat write %q: allow=%v err=%v", p, d.Allow, err)
		}
	}
}

// TestScopedAuthz_ScopedMemberWithoutGrant_Denied — opting a provider into
// scoping makes an explicit grant mandatory: a member with no scope entry is
// denied every path (fail closed), not defaulted to unconfined.
func TestScopedAuthz_ScopedMemberWithoutGrant_Denied(t *testing.T) {
	node := scopeNode(5)
	a := mustAuthorizer(t, InProcessAuthorizerConfig{
		// node is a member, but the scope map grants it nothing.
		Validators: NewScopedAuthorityProvider([]ids.NodeID{node}, map[ids.NodeID]string{}),
		Operator:   NewStaticAuthorityProvider(nil),
	})
	if d, _ := a.Authorize(context.Background(), Identity{NodeID: node}, "hanzo/commerce", OpAuthGet); d.Allow {
		t.Fatalf("scoped member without a grant must be denied, got allow")
	}
}
