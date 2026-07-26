// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// authz_mode_test.go — the three properties this gate must hold:
//
//	(a) unset mode is UNCHANGED — not "equivalent", literally the same
//	    authorizer value, so the request path cannot have drifted;
//	(b) audit mode denies NOTHING while logging every would-deny;
//	(c) the grant SET is honoured — a many-to-many identity matches on
//	    every path it holds, and a sibling path is not silently allowed.

package zapserver

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// fakeAuthorizer records what it was asked and returns a fixed decision.
type fakeAuthorizer struct {
	decision Decision
	err      error

	mu    sync.Mutex
	calls int
}

func (f *fakeAuthorizer) Authorize(context.Context, Identity, string, Op) (Decision, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.decision, f.err
}

// capturingLogger records Warn lines so the test can assert the
// would-deny stream without parsing stderr.
type capturingLogger struct {
	log.Logger
	mu    sync.Mutex
	warns []string
}

func (c *capturingLogger) Warn(msg string, ctx ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := strings.Builder{}
	b.WriteString(msg)
	for i := 0; i+1 < len(ctx); i += 2 {
		b.WriteString(" ")
		b.WriteString(toStr(ctx[i]))
		b.WriteString("=")
		b.WriteString(toStr(ctx[i+1]))
	}
	c.warns = append(c.warns, b.String())
}

func (c *capturingLogger) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.warns))
	copy(out, c.warns)
	return out
}

func toStr(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func newCapturingLogger() *capturingLogger {
	return &capturingLogger{Logger: log.NewNoOpLogger()}
}

func testNodeID(t *testing.T, seed byte) ids.NodeID {
	t.Helper()
	var n ids.NodeID
	for i := range n {
		n[i] = seed
	}
	return n
}

// --- (a) unset mode is byte-identical ---------------------------------

func TestParseAuthzMode(t *testing.T) {
	for _, c := range []struct {
		in      string
		want    AuthzMode
		wantErr bool
	}{
		{"", AuthzModeOff, false},
		{"off", AuthzModeOff, false},
		{"OFF", AuthzModeOff, false},
		{"  ", AuthzModeOff, false},
		{"audit", AuthzModeAudit, false},
		{" Audit ", AuthzModeAudit, false},
		{"enforce", AuthzModeOff, true},
		{"ENFORCE", AuthzModeOff, true},
		{"enforcee", AuthzModeOff, true},
		{"true", AuthzModeOff, true},
	} {
		got, err := ParseAuthzMode(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseAuthzMode(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
		}
		if got != c.want {
			t.Errorf("ParseAuthzMode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestParseAuthzMode_EnforceIsNotAModeInThisBuild — enforcement is a
// later gate. A Deployment that sets it must fail loudly at boot rather
// than start denying.
func TestParseAuthzMode_EnforceIsNotAModeInThisBuild(t *testing.T) {
	_, err := ParseAuthzMode("enforce")
	if err == nil {
		t.Fatal("enforce must be rejected — it has no code path in this build")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("error must say enforcement is unimplemented, got: %v", err)
	}
}

// TestWrapScopeAuthorizer_UnsetReturnsInnerVerbatim is the strongest form
// of "unchanged": the returned value IS the inner authorizer, so an unset
// KMS_AUTHZ_MODE cannot have altered a single decision, allocation, or
// branch on the request path.
func TestWrapScopeAuthorizer_UnsetReturnsInnerVerbatim(t *testing.T) {
	inner := &fakeAuthorizer{decision: Allow("validator-read")}
	got, err := WrapScopeAuthorizer(inner, ScopeAuthorizerConfig{Mode: AuthzModeOff})
	if err != nil {
		t.Fatalf("WrapScopeAuthorizer: %v", err)
	}
	if got != ConsensusAuthorizer(inner) {
		t.Fatalf("off mode returned a wrapper (%T), want the inner authorizer verbatim", got)
	}
	// And it works with no scope provider at all — off mode must not
	// require any overlay to exist.
	if _, err := WrapScopeAuthorizer(inner, ScopeAuthorizerConfig{Mode: AuthzModeOff, Scopes: nil}); err != nil {
		t.Fatalf("off mode must not require a scope provider: %v", err)
	}
}

// TestWrapScopeAuthorizer_AuditRequiresScopes — audit without an overlay
// source is a configuration error, not a silent no-op.
func TestWrapScopeAuthorizer_AuditRequiresScopes(t *testing.T) {
	inner := &fakeAuthorizer{decision: Allow("validator-read")}
	if _, err := WrapScopeAuthorizer(inner, ScopeAuthorizerConfig{Mode: AuthzModeAudit}); err == nil {
		t.Fatal("audit mode without a scope provider must error")
	}
}

// --- (b) audit denies nothing ------------------------------------------

// TestAudit_DeniesNothing_ButLogsWouldDenies is the core safety property.
// An identity with NO grant entry — the worst case, the one enforcement
// would reject outright — still gets the inner authorizer's Allow.
func TestAudit_DeniesNothing_ButLogsWouldDenies(t *testing.T) {
	node := testNodeID(t, 0x11)
	inner := &fakeAuthorizer{decision: Allow("validator-read")}
	lg := newCapturingLogger()

	az, err := WrapScopeAuthorizer(inner, ScopeAuthorizerConfig{
		Mode:   AuthzModeAudit,
		Scopes: NewStaticScopeProvider(map[ids.NodeID]Grants{}), // nobody granted anything
		Logger: lg,
	})
	if err != nil {
		t.Fatalf("WrapScopeAuthorizer: %v", err)
	}

	for _, path := range []string{"llm-secrets", "bootnode", "anything/at/all"} {
		got, err := az.Authorize(context.Background(), Identity{NodeID: node, ServicePath: "hanzo/enso-secrets"}, path, OpAuthGet)
		if err != nil {
			t.Fatalf("audit mode returned an error: %v", err)
		}
		if !got.Allow {
			t.Fatalf("audit mode DENIED %q — audit must never change a decision: %+v", path, got)
		}
		if got.Reason != "validator-read" {
			t.Fatalf("audit mode rewrote the reason: %q", got.Reason)
		}
	}

	lines := lg.lines()
	if len(lines) != 3 {
		t.Fatalf("expected 3 would-deny lines, got %d: %v", len(lines), lines)
	}
	for _, l := range lines {
		if !strings.Contains(l, "kms.authz would-deny") {
			t.Errorf("unexpected log line: %s", l)
		}
		if !strings.Contains(l, "enforced=false") {
			t.Errorf("audit line must state enforced=false: %s", l)
		}
		if !strings.Contains(l, "reason=no-scope-entry") {
			t.Errorf("missing structured reason: %s", l)
		}
		if !strings.Contains(l, "dimensions=path-only") {
			t.Errorf("audit line must disclose that it compares path only: %s", l)
		}
	}
}

// TestAudit_DoesNotSecondGuessAnInnerDeny — a request the role model
// already denies carries no scope signal. Logging it would bury the
// signal that matters (requests that pass today and would stop passing).
func TestAudit_DoesNotSecondGuessAnInnerDeny(t *testing.T) {
	inner := &fakeAuthorizer{decision: Deny("not-a-validator")}
	lg := newCapturingLogger()
	az, err := WrapScopeAuthorizer(inner, ScopeAuthorizerConfig{
		Mode:   AuthzModeAudit,
		Scopes: NewStaticScopeProvider(map[ids.NodeID]Grants{}),
		Logger: lg,
	})
	if err != nil {
		t.Fatalf("WrapScopeAuthorizer: %v", err)
	}
	got, err := az.Authorize(context.Background(), Identity{NodeID: testNodeID(t, 0x22)}, "x", OpAuthGet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Allow {
		t.Fatal("audit mode must not upgrade an inner Deny to Allow")
	}
	if got.Reason != "not-a-validator" {
		t.Fatalf("inner deny reason rewritten: %q", got.Reason)
	}
	if n := len(lg.lines()); n != 0 {
		t.Fatalf("audit logged %d lines for an already-denied request: %v", n, lg.lines())
	}
}

// TestAudit_PropagatesInnerError — a provider outage must surface
// unchanged; audit must not swallow it into an Allow.
func TestAudit_PropagatesInnerError(t *testing.T) {
	inner := &fakeAuthorizer{decision: Deny("validator-authority-unreachable"), err: context.DeadlineExceeded}
	lg := newCapturingLogger()
	az, _ := WrapScopeAuthorizer(inner, ScopeAuthorizerConfig{
		Mode:   AuthzModeAudit,
		Scopes: NewStaticScopeProvider(map[ids.NodeID]Grants{}),
		Logger: lg,
	})
	got, err := az.Authorize(context.Background(), Identity{NodeID: testNodeID(t, 0x33)}, "x", OpAuthGet)
	if err == nil {
		t.Fatal("inner error must propagate")
	}
	if got.Allow {
		t.Fatal("audit mode must not turn a fail-closed deny into an allow")
	}
}

// --- (c) the grant SET is honoured -------------------------------------

// TestAudit_ManyToManyIdentity_NoWouldDenyOnAnyGrantedPath — the
// hanzo-platform shape. An identity holding many unrelated paths must
// produce ZERO would-denies across all of them. A scalar scope would flag
// all but one, which is exactly the lockout preview this gate exists to
// avoid mispredicting.
func TestAudit_ManyToManyIdentity_NoWouldDenyOnAnyGrantedPath(t *testing.T) {
	node := testNodeID(t, 0x44)
	paths := []string{
		"admin-guard-secrets", "adnexus", "argocd/repo-ssh", "auth",
		"bootnode", "bootnode-secrets", "bot", "bot-browser",
		"buildx-ghcr-auth", "chat-guest-key", "platform", "storage",
	}
	grants := make([]Grant, 0, len(paths))
	for _, p := range paths {
		grants = append(grants, Grant{Org: "hanzo", Env: "prod", Path: p})
	}

	lg := newCapturingLogger()
	az, err := WrapScopeAuthorizer(&fakeAuthorizer{decision: Allow("validator-read")}, ScopeAuthorizerConfig{
		Mode:   AuthzModeAudit,
		Scopes: NewStaticScopeProvider(map[ids.NodeID]Grants{node: {Grants: grants}}),
		Logger: lg,
	})
	if err != nil {
		t.Fatalf("WrapScopeAuthorizer: %v", err)
	}

	for _, p := range paths {
		if _, err := az.Authorize(context.Background(), Identity{NodeID: node}, "/"+p+"/", OpAuthGet); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if lines := lg.lines(); len(lines) != 0 {
		t.Fatalf("granted paths produced %d would-denies (a scalar scope would produce %d): %v",
			len(lines), len(paths)-1, lines)
	}

	// A path outside the set IS flagged — the overlay is doing real work.
	if _, err := az.Authorize(context.Background(), Identity{NodeID: node}, "iam", OpAuthGet); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := lg.lines()
	if len(lines) != 1 || !strings.Contains(lines[0], "reason=path-outside-grant-set") {
		t.Fatalf("ungranted path was not flagged: %v", lines)
	}
}

// TestPathWithinGrant_SegmentBoundary — prefix matching without a
// segment-boundary check silently authorizes a SIBLING. Both of these
// are live production paths, so this is not a synthetic edge case.
func TestPathWithinGrant_SegmentBoundary(t *testing.T) {
	for _, c := range []struct {
		want, grant string
		ok          bool
	}{
		{"bootnode", "bootnode", true},
		{"bootnode/sub", "bootnode", true},
		{"bootnode-secrets", "bootnode", false}, // sibling, NOT a descendant
		{"bootnodex", "bootnode", false},
		{"argocd/repo-ssh", "argocd", true},
		{"anything", "", true}, // org root grant covers everything beneath it
		{"", "", true},
		{"", "bootnode", false},
	} {
		if got := pathWithinGrant(c.want, c.grant); got != c.ok {
			t.Errorf("pathWithinGrant(%q, %q) = %v, want %v", c.want, c.grant, got, c.ok)
		}
	}
}

// TestAudit_UnconfinedIdentityIsNeverFlagged — the kms-operator writes on
// every service's behalf; confining it would confine everything.
func TestAudit_UnconfinedIdentityIsNeverFlagged(t *testing.T) {
	node := testNodeID(t, 0x55)
	lg := newCapturingLogger()
	az, _ := WrapScopeAuthorizer(&fakeAuthorizer{decision: Allow("operator-write")}, ScopeAuthorizerConfig{
		Mode:   AuthzModeAudit,
		Scopes: NewStaticScopeProvider(map[ids.NodeID]Grants{node: {Unconfined: true}}),
		Logger: lg,
	})
	for _, p := range []string{"a", "b/c", ""} {
		if _, err := az.Authorize(context.Background(), Identity{NodeID: node}, p, OpAuthPut); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if lines := lg.lines(); len(lines) != 0 {
		t.Fatalf("unconfined identity flagged: %v", lines)
	}
}

// TestAudit_ScopedZeroGrantsIsDenyAll — an EXPLICIT empty grant set must
// read as "granted nothing", never as "granted everything". The
// distinction between this and Unconfined is the whole fail-closed
// design.
func TestAudit_ScopedZeroGrantsIsDenyAll(t *testing.T) {
	node := testNodeID(t, 0x66)
	lg := newCapturingLogger()
	az, _ := WrapScopeAuthorizer(&fakeAuthorizer{decision: Allow("validator-read")}, ScopeAuthorizerConfig{
		Mode:   AuthzModeAudit,
		Scopes: NewStaticScopeProvider(map[ids.NodeID]Grants{node: {Grants: []Grant{}}}),
		Logger: lg,
	})
	got, _ := az.Authorize(context.Background(), Identity{NodeID: node}, "anything", OpAuthGet)
	if !got.Allow {
		t.Fatal("audit must still allow")
	}
	lines := lg.lines()
	if len(lines) != 1 || !strings.Contains(lines[0], "reason=scoped-zero-grants") {
		t.Fatalf("empty grant set not reported as deny-all: %v", lines)
	}
}

// TestGrants_WireShapeMatchesOperator pins the cross-repo contract. These
// bytes are exactly what hanzoai/kms-operator's bootstrap.Snapshot
// marshals (see its scopes_test.go golden assertions). If either side
// drifts, this fails rather than silently producing an overlay the other
// side reads as empty — which under enforcement is a lockout.
func TestGrants_WireShapeMatchesOperator(t *testing.T) {
	const golden = `{"unconfined":true,"grants":[]}`
	var unconfined Grants
	if err := json.Unmarshal([]byte(golden), &unconfined); err != nil {
		t.Fatalf("unmarshal operator wire form: %v", err)
	}
	if !unconfined.Unconfined || len(unconfined.Grants) != 0 {
		t.Fatalf("operator unconfined form misread: %+v", unconfined)
	}

	const goldenScoped = `{"grants":[{"org":"hanzo","env":"prod","path":"bootnode"},{"org":"hanzo","env":"prod","path":"bootnode-secrets"}]}`
	var scoped Grants
	if err := json.Unmarshal([]byte(goldenScoped), &scoped); err != nil {
		t.Fatalf("unmarshal operator scoped form: %v", err)
	}
	if scoped.Unconfined {
		t.Fatal("scoped form must not decode as unconfined")
	}
	if len(scoped.Grants) != 2 {
		t.Fatalf("grant set lost entries: %+v", scoped.Grants)
	}
	if scoped.Grants[0] != (Grant{Org: "hanzo", Env: "prod", Path: "bootnode"}) {
		t.Fatalf("grant fields misaligned: %+v", scoped.Grants[0])
	}

	// The deny-all form must NOT decode as unconfined.
	const goldenEmpty = `{"grants":[]}`
	var empty Grants
	if err := json.Unmarshal([]byte(goldenEmpty), &empty); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if empty.Unconfined {
		t.Fatal("deny-all form decoded as unconfined — fail-open")
	}
}
