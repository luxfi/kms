// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// authz_mode.go — the scope overlay's OBSERVATION stage.
//
// Consensus membership answers "who are you". A scope grant answers "what
// may you address". Those are orthogonal, and this file adds only the
// second one's *observation*, never its enforcement.
//
// # Why observation comes first, as its own gate
//
// Turning path scoping on in one step is a total KMS lockout. Measured
// against the live fleet, 127 of 129 KMSSecret consumers read a path that
// shares no prefix with the service path their identity is derived from.
// Any authorizer that starts denying on a scope mismatch denies almost
// every real request on its first tick. There is no safe way to discover
// that from a changelog — it has to be MEASURED against production
// traffic before anything denies. That is what audit mode is for.
//
// # The three states, and the one that is the default
//
//	unset / ""  → AuthzModeOff.   No scope evaluation happens at all.
//	              WrapScopeAuthorizer returns the inner authorizer
//	              UNWRAPPED, so there is not one extra branch on the
//	              request path. Byte-identical to a build without this
//	              file.
//	"audit"     → AuthzModeAudit. Every request is evaluated against the
//	              scope overlay and every would-deny is LOGGED. The
//	              decision returned to the caller is the inner
//	              authorizer's, unchanged. Nothing is denied that would
//	              not already have been denied.
//	"enforce"   → REJECTED with an error. Enforcement is a later gate and
//	              deliberately has no code path here: a typo in a
//	              Deployment env var must not be able to switch on
//	              denial.
//
// Any other value is a hard error, so a misspelled mode fails loudly at
// boot instead of silently degrading to "off".
//
// # What audit mode can and cannot see
//
// A Grant carries three dimensions (org, env, path) because all three are
// real. The ZAP authorizer contract carries ONE: the opcode's `path`.
// Env is a genuine dimension of the store key
// (kms/secrets/{path}/{env}/{name}) that verifyAndAuthorize does not
// forward; org is a REST-plane concept the ZAP store does not model at
// all. So a scope match here is a PATH match, and it is therefore
// OVER-permissive: audit UNDER-reports the denials real enforcement would
// produce. Every audit line says so explicitly (`dimensions=path-only`)
// and the boot line warns once. Widening the contract to the full
// resource address is a prerequisite for enforcement, not for this gate.

package zapserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// AuthzMode selects how scope decisions are applied. The zero value is
// AuthzModeOff, which is what an unset env var resolves to.
type AuthzMode uint8

const (
	// AuthzModeOff performs no scope evaluation. The default.
	AuthzModeOff AuthzMode = iota

	// AuthzModeAudit evaluates scopes and logs would-denies without
	// changing any decision.
	AuthzModeAudit
)

// EnvAuthzMode is the environment variable that selects the mode.
const EnvAuthzMode = "KMS_AUTHZ_MODE"

// String returns the canonical wire spelling.
func (m AuthzMode) String() string {
	switch m {
	case AuthzModeOff:
		return "off"
	case AuthzModeAudit:
		return "audit"
	}
	return fmt.Sprintf("AuthzMode(%d)", uint8(m))
}

// ParseAuthzMode resolves the KMS_AUTHZ_MODE value. Pure function.
//
//	""/"off" → AuthzModeOff (today's behaviour, exactly)
//	"audit"  → AuthzModeAudit
//	"enforce"→ error: enforcement is a later gate with no code path here
//	anything else → error
func ParseAuthzMode(raw string) (AuthzMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return AuthzModeOff, nil
	case "audit":
		return AuthzModeAudit, nil
	case "enforce":
		return AuthzModeOff, fmt.Errorf(
			"%s=enforce: scope enforcement is not implemented in this build; "+
				"run %s=audit and confirm the would-deny stream is empty first", EnvAuthzMode, EnvAuthzMode)
	default:
		return AuthzModeOff, fmt.Errorf("%s=%q: unknown mode (want \"\", \"off\", or \"audit\")", EnvAuthzMode, raw)
	}
}

// Grant is one exact secret address an identity may reach. Wire-identical
// to the kms-operator's bootstrap.Grant — this is the consuming half of
// that contract, pinned by a shared golden fixture in the tests.
type Grant struct {
	Org  string `json:"org"`
	Env  string `json:"env"`
	Path string `json:"path"`
}

// Grants is the scope SET for one identity.
//
// Unconfined is an EXPLICIT flag, never inferred from an empty set: an
// identity with zero grants is granted nothing. "Empty means everything"
// is the classic fail-open reading and this shape makes it
// unrepresentable.
type Grants struct {
	Unconfined bool    `json:"unconfined,omitempty"`
	Grants     []Grant `json:"grants"`
}

// ScopeProvider returns the grant set consensus currently attests for a
// NodeID. The bool reports whether the identity has an ENTRY at all — an
// absent entry is not the same as an empty one, and only an explicit
// empty set means "granted nothing".
type ScopeProvider interface {
	GrantsFor(ctx context.Context, node ids.NodeID) (Grants, bool)
}

// StaticScopeProvider serves a snapshot handed over at boot — the same
// consensus-snapshot delivery the authority sets use. Not an ACL: the
// snapshot's authority is "consensus said these grants held at time T".
type StaticScopeProvider struct {
	byNode map[ids.NodeID]Grants
}

// NewStaticScopeProvider copies the supplied map so later mutation by the
// caller cannot change what the server enforces.
func NewStaticScopeProvider(m map[ids.NodeID]Grants) *StaticScopeProvider {
	c := make(map[ids.NodeID]Grants, len(m))
	for k, v := range m {
		c[k] = v
	}
	return &StaticScopeProvider{byNode: c}
}

// GrantsFor implements ScopeProvider.
func (s *StaticScopeProvider) GrantsFor(_ context.Context, node ids.NodeID) (Grants, bool) {
	g, ok := s.byNode[node]
	return g, ok
}

// Len reports the number of identities carrying a grant entry. Boot-log
// only.
func (s *StaticScopeProvider) Len() int { return len(s.byNode) }

// ScopeAuthorizerConfig wires the observation stage.
type ScopeAuthorizerConfig struct {
	// Mode selects off / audit. Required — AuthzModeOff means the
	// wrapper is not installed at all.
	Mode AuthzMode

	// Scopes supplies the grant sets. Required in audit mode.
	Scopes ScopeProvider

	// Logger receives the would-deny stream. nil → log.Root().
	Logger log.Logger
}

// WrapScopeAuthorizer returns the authorizer the kmsd should install.
//
// In AuthzModeOff it returns `inner` VERBATIM. Not a pass-through
// wrapper — the actual inner value, so an unset KMS_AUTHZ_MODE leaves
// the request path with the same call graph, the same allocations and the
// same decisions as a build that never had this file.
func WrapScopeAuthorizer(inner ConsensusAuthorizer, cfg ScopeAuthorizerConfig) (ConsensusAuthorizer, error) {
	if inner == nil {
		return nil, fmt.Errorf("zapserver: inner authorizer is required")
	}
	if cfg.Mode == AuthzModeOff {
		return inner, nil
	}
	if cfg.Scopes == nil {
		return nil, fmt.Errorf("zapserver: %s=%s requires a scope provider", EnvAuthzMode, cfg.Mode)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Root()
	}
	return &ScopeAuthorizer{inner: inner, mode: cfg.Mode, scopes: cfg.Scopes, log: cfg.Logger}, nil
}

// ScopeAuthorizer decorates a ConsensusAuthorizer with scope observation.
// Installed only in audit mode.
type ScopeAuthorizer struct {
	inner  ConsensusAuthorizer
	mode   AuthzMode
	scopes ScopeProvider
	log    log.Logger
}

// Authorize delegates to the inner authorizer and returns its decision
// UNCHANGED. In audit mode it additionally evaluates the scope overlay
// and logs any would-deny.
//
// Ordering matters: the scope check runs only on requests the inner
// authorizer ALLOWED. A request the role model already denies tells us
// nothing about scoping, and logging it would bury the signal that
// matters — the requests that pass today and would stop passing under
// enforcement.
func (s *ScopeAuthorizer) Authorize(ctx context.Context, ident Identity, path string, op Op) (Decision, error) {
	decision, err := s.inner.Authorize(ctx, ident, path, op)
	if err != nil || !decision.Allow {
		return decision, err
	}

	if reason, would := s.wouldDeny(ctx, ident, path); would {
		s.log.Warn("kms.authz would-deny",
			"mode", s.mode.String(),
			"enforced", false,
			"ident", ident.String(),
			"node", ident.NodeID.String(),
			"op", op.String(),
			"path", canonicalScopePath(path),
			"reason", reason,
			// The audit preview compares PATH only: the authorizer
			// contract carries neither env nor org, so real enforcement
			// would deny at least this set and probably more.
			"dimensions", "path-only",
		)
	}

	// Audit changes nothing. The inner decision is returned verbatim.
	return decision, err
}

// wouldDeny reports whether scope enforcement would reject this request,
// with a structured reason. Never mutates state.
func (s *ScopeAuthorizer) wouldDeny(ctx context.Context, ident Identity, path string) (string, bool) {
	grants, ok := s.scopes.GrantsFor(ctx, ident.NodeID)
	if !ok {
		// No entry at all. Under enforcement this is fail-closed: an
		// identity consensus has said nothing about is granted nothing.
		return "no-scope-entry", true
	}
	if grants.Unconfined {
		return "", false
	}
	want := canonicalScopePath(path)
	for _, g := range grants.Grants {
		if pathWithinGrant(want, canonicalScopePath(g.Path)) {
			return "", false
		}
	}
	if len(grants.Grants) == 0 {
		return "scoped-zero-grants", true
	}
	return "path-outside-grant-set", true
}

// pathWithinGrant reports whether `want` is the granted path or a
// descendant of it. An empty grant path is the org root and covers
// everything beneath it — that is a real, live grant shape
// (cloud-widget-kms-sync holds "/"), not a wildcard bug.
//
// Segment-boundary aware on purpose: "bootnode-secrets" must NOT match a
// grant on "bootnode". Prefix matching without the boundary check is how
// a sibling path gets silently authorized.
func pathWithinGrant(want, grant string) bool {
	if grant == "" {
		return true
	}
	if want == grant {
		return true
	}
	return strings.HasPrefix(want, grant+"/")
}

// canonicalScopePath trims whitespace and surrounding slashes so the
// operator's emitted form and the wire's requested form compare equal.
func canonicalScopePath(p string) string {
	return strings.Trim(strings.TrimSpace(p), "/")
}
