// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// path_scope_e2e_test.go — END-TO-END proof that authority-anchored path
// scoping holds through the FULL request path (verifyAndAuthorize: parse
// envelope → verify ML-DSA-65 signature + binding + freshness + replay →
// extract addressed path → consensus authorize), not just the unit
// Authorize entry point.
//
// This is the RED re-review gate for task #53 (KMS path-scope activation):
// a scoped authority snapshot must confine a cryptographically-bound NodeID
// to its granted subtree even when the caller signs a perfectly valid
// envelope addressing a DIFFERENT subtree. The scope is authority-side data
// keyed by the bound NodeID; the caller cannot widen it by setting the
// envelope's inner `path` to anything it likes — that path is exactly what
// gets confinement-checked.
//
// Coverage (all driven with a real signed envelope):
//
//   - in-scope read of the service's OWN secret → allowed end-to-end
//     (verifyAndAuthorize + handleGet returns the sealed value);
//   - sibling subtree, straddling prefix (commerce vs commerce-evil),
//     parent escape → denied;
//   - a scoped member with NO grant → denied every path (fail closed);
//   - write confinement by the OPERATOR authority's (tighter) scope,
//     isolated from the read (validator) scope;
//   - flat (unscoped) authority stays unconfined (back-compat — covered
//     additionally by server_auth_test.go's role tests).

package zapserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/log"
	badger "github.com/luxfi/zapdb"
)

// newScopedTestServer mirrors newTestServer but wires per-authority scope
// maps. A nil scope map yields a flat (unconfined) provider; a non-nil map
// yields a least-privilege scoped provider (un-granted members fail closed).
func newScopedTestServer(t *testing.T, validators, operators []ids.NodeID, valScopes, opScopes map[ids.NodeID]string) *Server {
	t.Helper()
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
		Validators: scopedOrFlat(validators, valScopes),
		Operator:   scopedOrFlat(operators, opScopes),
	})
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	return New(Config{
		Store:      store.NewSecretStore(db),
		MasterKey:  mk,
		Authorizer: authz,
		Logger:     log.NewNoOpLogger(),
		Now:        func() time.Time { return time.Unix(1_717_200_000, 0) },
	})
}

// scopedOrFlat picks the provider constructor matching the intended posture:
// nil scopes → flat, non-nil → scoped.
func scopedOrFlat(members []ids.NodeID, scopes map[ids.NodeID]string) AuthorityProvider {
	if scopes == nil {
		return NewStaticAuthorityProvider(members)
	}
	return NewScopedAuthorityProvider(members, scopes)
}

// TestScopedE2E_ReadOwnSubtree_Allowed proves a scoped validator reads its
// OWN secret end-to-end: signed envelope → verify → authorize → handleGet
// returns the sealed plaintext. This is the "service reads its own subtree"
// happy path the least-privilege boundary must preserve.
func TestScopedE2E_ReadOwnSubtree_Allowed(t *testing.T) {
	ident := newIdentity(t, "hanzo/commerce")
	defer ident.Wipe()

	s := newScopedTestServer(t,
		[]ids.NodeID{ident.NodeID}, nil,
		map[ids.NodeID]string{ident.NodeID: "hanzo/commerce"}, nil,
	)
	seed(t, s, "hanzo/commerce", "api-key", "prod", "sk_live_own")
	now := time.Unix(1_717_200_000, 0)

	// Scope root itself.
	raw := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/commerce", Name: "api-key", Env: "prod",
	}), now, "scope-root-nonce")
	vident, payload, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet)
	if err != nil {
		t.Fatalf("in-scope read must be allowed end-to-end: %v", err)
	}
	st, body, herr := s.handleGet(context.Background(), vident, payload)
	if herr != nil || st != statusOK {
		t.Fatalf("handleGet own secret: status=0x%02X err=%v", st, herr)
	}
	var gr getResp
	if err := json.Unmarshal(body, &gr); err != nil {
		t.Fatalf("decode getResp: %v", err)
	}
	if dec, _ := base64.StdEncoding.DecodeString(gr.Value); string(dec) != "sk_live_own" {
		t.Fatalf("own-secret value mismatch: got %q want sk_live_own", string(dec))
	}

	// A descendant path is inside the scope too.
	rawDesc := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/commerce/db", Name: "x", Env: "prod",
	}), now, "scope-desc-nonce")
	if _, _, err := s.verifyAndAuthorize(context.Background(), rawDesc, OpSecretGet); err != nil {
		t.Fatalf("descendant read must be allowed: %v", err)
	}
}

// TestScopedE2E_ReadOutsideScope_Denied drives the three escape shapes RED
// cares about through the full envelope path: sibling subtree, straddling
// prefix (commerce vs commerce-evil), and parent escape. Each is a
// signature-valid envelope from the correct NodeID — only the scope check
// stops it.
func TestScopedE2E_ReadOutsideScope_Denied(t *testing.T) {
	ident := newIdentity(t, "hanzo/commerce")
	defer ident.Wipe()

	s := newScopedTestServer(t,
		[]ids.NodeID{ident.NodeID}, nil,
		map[ids.NodeID]string{ident.NodeID: "hanzo/commerce"}, nil,
	)
	now := time.Unix(1_717_200_000, 0)

	cases := []struct {
		name string
		path string
	}{
		{"sibling-subtree", "hanzo/kms"},
		{"sibling-secret", "hanzo/kms/master"},
		{"straddling-prefix", "hanzo/commerce-evil"},
		{"straddling-secret", "hanzo/commerce-evil/exfil"},
		{"parent-escape", "hanzo"},
		{"unrelated-root", "lux/bridge"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
				Path: c.path, Name: "api-key", Env: "prod",
			}), now, "outside-"+c.name+"-nonce")
			if _, _, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet); err == nil {
				t.Fatalf("read of %q (outside scope hanzo/commerce) MUST be denied end-to-end, got allow", c.path)
			}
		})
	}
}

// TestScopedE2E_ScopedMemberNoGrant_Denied — opting the validator authority
// into scoping makes an explicit grant mandatory. A NodeID that is a MEMBER
// but carries no scope entry is denied every path (fail closed), proven
// through the full envelope path.
func TestScopedE2E_ScopedMemberNoGrant_Denied(t *testing.T) {
	ident := newIdentity(t, "hanzo/commerce")
	defer ident.Wipe()

	// Non-nil (scoped) validator authority, but the grant map is empty:
	// ident is a member with NO grant.
	s := newScopedTestServer(t,
		[]ids.NodeID{ident.NodeID}, nil,
		map[ids.NodeID]string{}, nil,
	)
	now := time.Unix(1_717_200_000, 0)

	raw := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/commerce", Name: "api-key", Env: "prod",
	}), now, "no-grant-nonce")
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet); err == nil {
		t.Fatalf("scoped member with no grant MUST be denied (fail closed), got allow")
	}
}

// TestScopedE2E_WriteConfinedByOperatorScope isolates the OPERATOR (write)
// authority's scope from the validator (read) scope. The identity may READ
// broadly across "hanzo" but WRITE only within "hanzo/commerce": a Put to
// "hanzo/kms/x" passes the validator gate+scope yet is stopped by the
// tighter operator scope. This proves the write grant is independently
// enforced end-to-end.
func TestScopedE2E_WriteConfinedByOperatorScope(t *testing.T) {
	ident := newIdentity(t, "hanzo/commerce")
	defer ident.Wipe()

	s := newScopedTestServer(t,
		[]ids.NodeID{ident.NodeID}, []ids.NodeID{ident.NodeID},
		map[ids.NodeID]string{ident.NodeID: "hanzo"},          // broad READ
		map[ids.NodeID]string{ident.NodeID: "hanzo/commerce"}, // tight WRITE
	)
	now := time.Unix(1_717_200_000, 0)

	// In-scope write.
	putIn := signedEnvelopeBytes(t, ident, OpSecretPut, buildInner(t, putReq{
		Path: "hanzo/commerce", Name: "rotation-key", Env: "prod",
		Value: base64.StdEncoding.EncodeToString([]byte("newSecret")),
	}), now, "write-in-nonce")
	vident, payload, err := s.verifyAndAuthorize(context.Background(), putIn, OpSecretPut)
	if err != nil {
		t.Fatalf("in-scope write must be allowed: %v", err)
	}
	if st, _, herr := s.handlePut(context.Background(), vident, payload); herr != nil || st != statusOK {
		t.Fatalf("handlePut in-scope: status=0x%02X err=%v", st, herr)
	}

	// Out-of-write-scope Put (still inside the broad READ scope "hanzo",
	// so the denial is unambiguously the OPERATOR scope).
	putOut := signedEnvelopeBytes(t, ident, OpSecretPut, buildInner(t, putReq{
		Path: "hanzo/kms", Name: "master", Env: "prod",
		Value: base64.StdEncoding.EncodeToString([]byte("evil")),
	}), now, "write-out-nonce")
	if _, _, err := s.verifyAndAuthorize(context.Background(), putOut, OpSecretPut); err == nil {
		t.Fatalf("write to hanzo/kms (inside read scope, outside write scope) MUST be denied, got allow")
	}

	// A read of the same out-of-write-scope path IS allowed — the read scope
	// is broader. This pins that read and write scopes are enforced
	// independently, not conflated.
	readOut := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/kms", Name: "master", Env: "prod",
	}), now, "read-broad-nonce")
	if _, _, err := s.verifyAndAuthorize(context.Background(), readOut, OpSecretGet); err != nil {
		t.Fatalf("read within the broad read scope must be allowed: %v", err)
	}
}
