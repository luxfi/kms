// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// consensus_auth.go — consensus-native authorization for ZAP secret opcodes.
//
// The CSV ACL approach is dead. Authority lives in Lux consensus:
//
//  - Identity: every caller signs its envelope with a mnemonic-derived
//    ML-DSA-65 key whose NodeID is the canonical SHAKE256-384 digest
//    (luxfi/keys.ServiceIdentity + luxfi/ids.NodeIDSchemeMLDSA65).
//
//  - Authority: consensus says which NodeIDs are currently authorized
//    for which path under which cert profile. The Polaris cert
//    (quasar.ComposePolaris) is the threshold attestation that binds a
//    validator set to a round; an authorizer asks "is this NodeID a
//    member of a current Polaris-attested authority?" before releasing
//    a secret.
//
//  - Capability: writes require an admin overlay. The overlay is a
//    pure-function predicate the operator wires at boot — it is NOT a
//    CSV the kmsd maintains. The canonical implementation reads its
//    admin set from the same consensus authority, scoped to the
//    "operator" path prefix.
//
// kmsd boot wires a single ConsensusAuthorizer; tests pass a Fake.
// There is no fallback ACL. If consensus is unreachable the server
// fails closed (Authorize returns false + a structured reason).

package zapserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/ids"
)

// Op is the wire opcode under authorization. Re-exported as a typed
// value so the authorizer surface is independent of the package-level
// opcode constants (handlers still use the raw uint16 — this is the
// boundary type).
type Op uint16

// Authorized opcodes mirror the four exported in server.go. Kept as
// typed aliases so a refactor of the wire constants does not silently
// widen the authorizer's contract.
const (
	OpAuthGet    Op = Op(OpSecretGet)
	OpAuthPut    Op = Op(OpSecretPut)
	OpAuthList   Op = Op(OpSecretList)
	OpAuthDelete Op = Op(OpSecretDelete)
	// Threshold key ops. Deliberate, documented widening of the
	// authorizer contract (not a silent one): OpSign is a privileged
	// key operation gated behind the operator (write) authority;
	// OpVerify is a public-key check gated behind the validator (read)
	// authority.
	OpAuthSign   Op = Op(OpSign)
	OpAuthVerify Op = Op(OpVerify)
)

// IsWrite reports whether the opcode is a mutation (or, for OpSign, a
// privileged key operation). Used by the in-process authorizer to gate
// these behind the operator authority.
func (o Op) IsWrite() bool {
	switch o {
	case OpAuthPut, OpAuthDelete, OpAuthSign:
		return true
	default:
		return false
	}
}

// String returns "OpSecretGet" / "OpSecretPut" / etc. so audit logs
// stay readable without leaking opcode bytes.
func (o Op) String() string {
	switch o {
	case OpAuthGet:
		return "OpSecretGet"
	case OpAuthPut:
		return "OpSecretPut"
	case OpAuthList:
		return "OpSecretList"
	case OpAuthDelete:
		return "OpSecretDelete"
	case OpAuthSign:
		return "OpSign"
	case OpAuthVerify:
		return "OpVerify"
	}
	return fmt.Sprintf("Op_0x%04X", uint16(o))
}

// Identity is the verified service identity carried by a request. The
// envelope-signature verifier populates this before invoking the
// authorizer — the authorizer does not re-verify the signature; it
// asks "is this verified NodeID authorized for this op on this path?"
type Identity struct {
	// NodeID is the 20-byte canonical NodeID derived from the service
	// mnemonic + path via luxfi/keys.NewServiceIdentity. Map-key safe.
	NodeID ids.NodeID

	// FullDigest is the 48-byte SHAKE256-384 commitment to the
	// identity. Bound into the envelope signature; carried here so an
	// audit log row can record the strong commitment instead of the
	// 20-byte prefix alone.
	FullDigest ids.FullDigest

	// ServicePath is the canonical path string the identity was
	// derived from, as declared by the caller. Verified by the
	// envelope-signature path before this struct is constructed.
	ServicePath string
}

// String returns a stable diagnostic string. Not a wire form.
func (i Identity) String() string {
	if i.ServicePath != "" {
		return fmt.Sprintf("%s@%s", i.ServicePath, i.NodeID.String())
	}
	return i.NodeID.String()
}

// Decision is the structured authorizer outcome. A `false` decision
// always carries a Reason so audit logs and client error responses
// can attribute the deny without leaking authorizer internals.
type Decision struct {
	Allow  bool
	Reason string
}

// Allow returns an Allow decision with the given reason.
func Allow(reason string) Decision { return Decision{Allow: true, Reason: reason} }

// Deny returns a Deny decision with the given reason.
func Deny(reason string) Decision { return Decision{Allow: false, Reason: reason} }

// ConsensusAuthorizer is the contract the kmsd talks to. Production
// impls dial Lux consensus and return whatever it says; tests pass a
// Fake. There is no "fall back to a local ACL" branch.
//
// Authorize MUST be safe for concurrent use. The kmsd calls it on
// every request; a serial impl would bottleneck the secret surface.
type ConsensusAuthorizer interface {
	// Authorize returns Allow if the identity may invoke op on path.
	// Path is the canonical "/"-joined string the caller addresses
	// (e.g. "hanzo/kms-operator") with no leading or trailing slash.
	//
	// On consensus unreachable / transient error the impl returns
	// (Deny, err). The kmsd treats this as fail-closed and surfaces
	// statusForbid on the wire.
	Authorize(ctx context.Context, ident Identity, path string, op Op) (Decision, error)
}

// AuthorityProvider returns the set of NodeIDs the consensus layer
// currently attests as members of the named authority. The kmsd holds
// one AuthorityProvider per authority name (typically "validators" and
// "operator"); the in-process authorizer composes them.
//
// Implementations MUST be cheap to call (the kmsd may invoke them on
// every request). The InProcessAuthorizer caches per-authority results
// for a short TTL; that cache is the only ambient state in the auth
// surface.
type AuthorityProvider interface {
	// Members returns the current authority set. The returned slice
	// MUST NOT be mutated by the caller; the provider may share the
	// underlying array.
	Members(ctx context.Context) ([]ids.NodeID, error)
}

// AuthorityProviderFunc is a function adapter for AuthorityProvider.
type AuthorityProviderFunc func(ctx context.Context) ([]ids.NodeID, error)

// Members runs the wrapped function.
func (f AuthorityProviderFunc) Members(ctx context.Context) ([]ids.NodeID, error) {
	return f(ctx)
}

// ScopedAuthorityProvider is an AuthorityProvider that additionally
// confines each member NodeID to a path prefix. When a provider implements
// it, the authorizer enforces least privilege: the addressed secret path
// MUST fall within the member's granted scope, so a single compromised
// service key cannot reach the entire secret tree.
//
// Soundness: the scope is AUTHORITY-side data — it rides the same
// consensus snapshot that lists membership, keyed by the cryptographically
// bound NodeID. It is NEVER derived from the envelope's self-declared
// ServicePath, which a key-holder can set to anything. A flat
// (non-scope-aware) provider leaves members unconfined, preserving the
// pre-existing role-based posture.
type ScopedAuthorityProvider interface {
	AuthorityProvider
	// Scope returns the path prefix NodeID is confined to and ok=true iff
	// NodeID is a member. An empty prefix means "unconfined" (root). A
	// non-member returns ("", false).
	Scope(ctx context.Context, node ids.NodeID) (prefix string, ok bool)
}

// InProcessAuthorizerConfig wires the in-process ConsensusAuthorizer
// from two authority providers and an optional cache TTL.
//
// Validators is the broad read authority — every member may Get and
// List under any path. Operator is the write authority — only its
// members may Put and Delete. Both providers are interrogated on
// every request; results are cached per-authority for CacheTTL (0 =
// no cache, every call dials the provider).
type InProcessAuthorizerConfig struct {
	// Validators is the broad read authority. Required.
	Validators AuthorityProvider

	// Operator is the write authority. Required.
	Operator AuthorityProvider

	// CacheTTL is the per-authority result TTL. 0 disables caching
	// (every request dials both providers). 30s is the production
	// default — the kmsd reconfigures the cache via the operator's
	// reconciliation interval, not by mutating this field after boot.
	CacheTTL time.Duration
}

// NewInProcessAuthorizer wires an authorizer over two AuthorityProviders.
// Returns an error if either provider is nil.
func NewInProcessAuthorizer(cfg InProcessAuthorizerConfig) (*InProcessAuthorizer, error) {
	if cfg.Validators == nil {
		return nil, errors.New("zapserver: validator authority provider is required")
	}
	if cfg.Operator == nil {
		return nil, errors.New("zapserver: operator authority provider is required")
	}
	return &InProcessAuthorizer{
		validators: cfg.Validators,
		operator:   cfg.Operator,
		cacheTTL:   cfg.CacheTTL,
	}, nil
}

// InProcessAuthorizer is the canonical ConsensusAuthorizer. The "in
// process" name means the policy composition runs in the kmsd process;
// the AUTHORITY data still comes from consensus (via the providers).
type InProcessAuthorizer struct {
	validators AuthorityProvider
	operator   AuthorityProvider
	cacheTTL   time.Duration

	mu             sync.RWMutex
	validatorsSet  map[ids.NodeID]struct{}
	validatorsRead time.Time
	operatorSet    map[ids.NodeID]struct{}
	operatorRead   time.Time
}

// Authorize is the entry point. Decision order:
//
//  1. Reject ops outside the four secret opcodes.
//  2. Look up the identity's NodeID in the validator authority. Miss
//     → Deny("not-a-validator").
//  3. For writes: additionally look up the NodeID in the operator
//     authority. Miss → Deny("not-an-operator").
//  4. Allow.
//
// On provider error: Deny + error so the caller can log the transient
// failure while the wire still sees a clean forbid.
func (a *InProcessAuthorizer) Authorize(ctx context.Context, ident Identity, path string, op Op) (Decision, error) {
	switch op {
	case OpAuthGet, OpAuthPut, OpAuthList, OpAuthDelete, OpAuthSign, OpAuthVerify:
	default:
		return Deny(fmt.Sprintf("unknown-opcode-%s", op.String())), nil
	}

	if isEmptyNodeID(ident.NodeID) {
		return Deny("missing-identity"), nil
	}

	validators, err := a.snapshotValidators(ctx)
	if err != nil {
		return Deny("validator-authority-unreachable"), err
	}
	if _, ok := validators[ident.NodeID]; !ok {
		return Deny("not-a-validator"), nil
	}

	addressed := normalizePath(path)

	if !op.IsWrite() {
		// Read: confine to the validator authority's granted scope. A
		// flat (unscoped) validator authority leaves the member
		// unconfined (root) — the pre-existing broad-read posture.
		if !a.withinAuthorityScope(ctx, a.validators, ident.NodeID, addressed) {
			return Deny("path-outside-scope"), nil
		}
		return Allow("validator-read"), nil
	}

	operators, err := a.snapshotOperator(ctx)
	if err != nil {
		return Deny("operator-authority-unreachable"), err
	}
	if _, ok := operators[ident.NodeID]; !ok {
		return Deny("not-an-operator"), nil
	}
	// Write: confine to the OPERATOR authority's granted (write) scope —
	// that is the write grant, tighter than the read grant. Unscoped
	// operator authority → unconfined write (pre-existing posture).
	if !a.withinAuthorityScope(ctx, a.operator, ident.NodeID, addressed) {
		return Deny("path-outside-scope"), nil
	}
	return Allow("operator-write"), nil
}

// withinAuthorityScope reports whether addressed is inside the path scope
// the given authority grants node. A flat (non-scope-aware) provider
// leaves the member unconfined (returns true) — back-compat with the
// role-based authorities. A scope-aware provider that no longer lists the
// node (snapshot/scope race) fails closed (returns false).
func (a *InProcessAuthorizer) withinAuthorityScope(ctx context.Context, p AuthorityProvider, node ids.NodeID, addressed string) bool {
	sp, ok := p.(ScopedAuthorityProvider)
	if !ok {
		return true // flat authority → unconfined
	}
	scope, member := sp.Scope(ctx, node)
	if !member {
		return false // scope-aware authority dropped this node → fail closed
	}
	return pathWithinScope(addressed, scope)
}

// normalizePath trims surrounding whitespace and slashes so scope
// containment compares canonical "/"-joined paths.
func normalizePath(p string) string {
	return strings.Trim(strings.TrimSpace(p), "/")
}

// pathWithinScope reports whether the addressed path is at or under the
// scope prefix. An empty scope is unconfined (root). The boundary is a
// full path segment: scope "hanzo/commerce" admits "hanzo/commerce" and
// "hanzo/commerce/db" but NOT "hanzo/commerce-evil" (no sibling straddle)
// and NOT the parent "hanzo".
func pathWithinScope(addressed, scope string) bool {
	scope = normalizePath(scope)
	if scope == "" {
		return true
	}
	return addressed == scope || strings.HasPrefix(addressed, scope+"/")
}

// snapshotValidators returns the current validator authority. Cached
// up to a.cacheTTL.
func (a *InProcessAuthorizer) snapshotValidators(ctx context.Context) (map[ids.NodeID]struct{}, error) {
	a.mu.RLock()
	if a.cacheTTL > 0 && a.validatorsSet != nil && time.Since(a.validatorsRead) < a.cacheTTL {
		set := a.validatorsSet
		a.mu.RUnlock()
		return set, nil
	}
	a.mu.RUnlock()

	members, err := a.validators.Members(ctx)
	if err != nil {
		return nil, fmt.Errorf("validators: %w", err)
	}
	set := toNodeIDSet(members)
	a.mu.Lock()
	a.validatorsSet = set
	a.validatorsRead = time.Now()
	a.mu.Unlock()
	return set, nil
}

// snapshotOperator returns the current operator authority. Cached up
// to a.cacheTTL.
func (a *InProcessAuthorizer) snapshotOperator(ctx context.Context) (map[ids.NodeID]struct{}, error) {
	a.mu.RLock()
	if a.cacheTTL > 0 && a.operatorSet != nil && time.Since(a.operatorRead) < a.cacheTTL {
		set := a.operatorSet
		a.mu.RUnlock()
		return set, nil
	}
	a.mu.RUnlock()

	members, err := a.operator.Members(ctx)
	if err != nil {
		return nil, fmt.Errorf("operator: %w", err)
	}
	set := toNodeIDSet(members)
	a.mu.Lock()
	a.operatorSet = set
	a.operatorRead = time.Now()
	a.mu.Unlock()
	return set, nil
}

// toNodeIDSet builds a constant-time-lookup set from a slice. The
// returned map is internal; callers receive a read-only view via
// snapshot*.
func toNodeIDSet(members []ids.NodeID) map[ids.NodeID]struct{} {
	out := make(map[ids.NodeID]struct{}, len(members))
	for _, id := range members {
		out[id] = struct{}{}
	}
	return out
}

// isEmptyNodeID reports whether the NodeID is the all-zero value. The
// envelope verifier sets ident.NodeID from the signer's pubkey; an
// empty value here means the wire path skipped the verification
// (forward-compat bridge) and we MUST deny.
func isEmptyNodeID(n ids.NodeID) bool {
	for _, b := range n {
		if b != 0 {
			return false
		}
	}
	return true
}

// StaticAuthorityProvider returns the supplied NodeID set on every
// call. Used at boot when the operator hands the kmsd a consensus
// snapshot via env / file; the snapshot is refreshed by re-applying
// the operator manifest, not by the kmsd polling.
//
// Note: this is NOT a CSV ACL. The static set is a consensus snapshot;
// the snapshot's authority is "consensus said these NodeIDs were the
// authority members at time T". Refresh = re-apply.
type StaticAuthorityProvider struct {
	members []ids.NodeID
	// scopes optionally confines each member NodeID to a path prefix. nil
	// means the provider is flat (every member unconfined); non-nil opts
	// the whole provider into least-privilege scoping, and a member absent
	// from the map is denied (explicit grant required — fail closed).
	scopes map[ids.NodeID]string
}

// NewStaticAuthorityProvider returns a flat provider over the given NodeID
// set (every member unconfined). Defensive copy: the caller may mutate the
// slice after this returns without affecting the provider.
func NewStaticAuthorityProvider(members []ids.NodeID) *StaticAuthorityProvider {
	c := make([]ids.NodeID, len(members))
	copy(c, members)
	return &StaticAuthorityProvider{members: c}
}

// NewScopedAuthorityProvider returns a least-privilege provider: it lists
// members AND confines each to a path prefix. scopes maps NodeID → allowed
// prefix (empty prefix = unconfined root for that member). A NodeID in
// members but absent from scopes is denied every path (explicit grant
// required); a NodeID in scopes but not members is ignored.
//
// The scope data is a consensus-snapshot fact — the operator knows each
// service's derived path when it builds the authority — so it is
// authoritative and cannot be spoofed by the caller's envelope.
func NewScopedAuthorityProvider(members []ids.NodeID, scopes map[ids.NodeID]string) *StaticAuthorityProvider {
	c := make([]ids.NodeID, len(members))
	copy(c, members)
	sc := make(map[ids.NodeID]string, len(scopes))
	for k, v := range scopes {
		sc[k] = v
	}
	return &StaticAuthorityProvider{members: c, scopes: sc}
}

// Members returns the static snapshot.
func (s *StaticAuthorityProvider) Members(_ context.Context) ([]ids.NodeID, error) {
	return s.members, nil
}

// Scope implements ScopedAuthorityProvider. Membership is answered from the
// member set; the confinement prefix comes from the scope map. A flat
// provider (nil scopes) reports every member as unconfined (""). A scoped
// provider denies (ok=false) any member lacking an explicit grant.
func (s *StaticAuthorityProvider) Scope(_ context.Context, node ids.NodeID) (string, bool) {
	member := false
	for _, m := range s.members {
		if m == node {
			member = true
			break
		}
	}
	if !member {
		return "", false
	}
	if s.scopes == nil {
		return "", true // flat provider → unconfined
	}
	scope, granted := s.scopes[node]
	if !granted {
		return "", false // scoped provider requires an explicit grant
	}
	return scope, true
}
