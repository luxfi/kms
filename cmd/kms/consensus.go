// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// consensus.go — wires the kmsd to its consensus authority.
//
// The kmsd asks consensus "is NodeID X a member of authority Y?" on
// every request. Authority data lives upstream (luxd); the kmsd never
// runs its own ACL. This file holds the boot-time wiring.
//
// Today the wiring reads a consensus snapshot from env / file. The
// snapshot is produced by the kms-operator, which is the component
// that talks to luxd directly. When luxd later exposes a wire-level
// authorization RPC, this file gains a second wiring (push-style:
// kmsd dials luxd, pulls the current validator + operator sets at the
// configured TTL). The ConsensusAuthorizer interface does not change.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/kms/pkg/zapserver"
)

const (
	envValidators = "KMS_CONSENSUS_VALIDATORS"
	envOperators  = "KMS_CONSENSUS_OPERATORS"
	envFile       = "KMS_CONSENSUS_FILE"
	envTTL        = "KMS_CONSENSUS_TTL"

	// Nonce ledger knobs. Both have package-default fallbacks; the env
	// vars exist so the kms-operator can tune memory pressure in
	// high-cardinality deployments without a rebuild.
	envNonceLedgerTTL = "KMS_NONCE_LEDGER_TTL"
	envNonceLedgerGC  = "KMS_NONCE_LEDGER_GC"

	defaultConsensusTTL = 30 * time.Second
)

// buildNonceLedger returns the canonical in-process anti-replay ledger.
// Honours KMS_NONCE_LEDGER_TTL and KMS_NONCE_LEDGER_GC env vars; zero /
// missing values fall back to the package defaults (TTL = MaxClockSkew +
// 1m = 6m, GC = TTL/4 = 90s).
//
// The ledger is wired into zapserver.Server at boot. The kms-operator
// owns the values in production: services with high envelope volume
// (e.g. paas/platform) typically run with KMS_NONCE_LEDGER_GC=30s for
// tighter memory bounds.
func buildNonceLedger() (zapserver.NonceLedger, error) {
	cfg := zapserver.MemoryNonceLedgerConfig{}
	if v := strings.TrimSpace(os.Getenv(envNonceLedgerTTL)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envNonceLedgerTTL, err)
		}
		cfg.TTL = d
	}
	if v := strings.TrimSpace(os.Getenv(envNonceLedgerGC)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envNonceLedgerGC, err)
		}
		cfg.GCInterval = d
	}
	return zapserver.NewMemoryNonceLedger(cfg), nil
}

// consensusSnapshot is the wire shape of the JSON file the operator
// drops into the kmsd container. Same shape as the env vars (one
// authority per slice) so the operator can pick either delivery.
//
// Scopes is the OPTIONAL least-privilege overlay. When present it confines
// each member NodeID of an authority to a path prefix, so a single
// compromised service key cannot reach the entire secret tree. Absent (nil)
// leaves both authorities flat (unconfined) — the pre-existing role-based
// posture and the only posture the env-var carriage can express. The scope
// is AUTHORITY-side data keyed by the cryptographically-bound NodeID; it is
// never taken from the caller's self-declared envelope path.
type consensusSnapshot struct {
	Validators []string         `json:"validators"`
	Operators  []string         `json:"operators"`
	Scopes     *consensusScopes `json:"scopes,omitempty"`
}

// consensusScopes carries the per-authority NodeID→path-prefix grants. A
// non-nil authority map opts that authority into least-privilege scoping:
// a member absent from the map is DENIED every path (explicit grant
// required — fail closed). A nil authority map leaves that authority flat
// (every member unconfined). The two authorities are independent: the read
// (validator) authority can be scoped while the write (operator) authority
// stays flat, or vice-versa.
//
// The map fields deliberately carry NO omitempty: a present-but-empty map
// ("scoped, zero grants" → deny every member) must survive the JSON round
// trip as `{}` and NOT be silently dropped to null/nil (which would fail
// OPEN to flat). nil marshals to `null` (flat); `{}` stays `{}` (scoped).
type consensusScopes struct {
	Validators map[string]string `json:"validators"`
	Operators  map[string]string `json:"operators"`
}

// parsedSnapshot is the fully-parsed authority data: the two NodeID member
// sets plus the optional per-authority scope maps, keyed by the parsed
// NodeID so the provider constructors can consume them directly. A nil
// scope map means the authority is flat (unconfined); a non-nil map (even
// empty) means the authority is scoped and fail-closed for un-granted
// members.
type parsedSnapshot struct {
	validators      []ids.NodeID
	operators       []ids.NodeID
	validatorScopes map[ids.NodeID]string
	operatorScopes  map[ids.NodeID]string
}

// buildConsensusAuthorizer constructs the ConsensusAuthorizer wired
// at boot. Reads either KMS_CONSENSUS_FILE or the two NodeID env
// vars; refuses to boot if neither is present, since the ZAP server
// is fail-closed by construction.
func buildConsensusAuthorizer() (zapserver.ConsensusAuthorizer, error) {
	snap, err := loadConsensusSnapshot()
	if err != nil {
		return nil, err
	}
	if len(snap.validators) == 0 {
		return nil, errors.New("consensus validator authority is empty (refusing to boot fail-open)")
	}
	if len(snap.operators) == 0 {
		return nil, errors.New("consensus operator authority is empty (refusing to boot fail-open)")
	}
	ttl := defaultConsensusTTL
	if v := strings.TrimSpace(os.Getenv(envTTL)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envTTL, err)
		}
		ttl = d
	}
	az, err := zapserver.NewInProcessAuthorizer(zapserver.InProcessAuthorizerConfig{
		Validators: newAuthorityProvider(snap.validators, snap.validatorScopes, "validator/read"),
		Operator:   newAuthorityProvider(snap.operators, snap.operatorScopes, "operator/write"),
		CacheTTL:   ttl,
	})
	if err != nil {
		return nil, err
	}
	// Probe the authorizer once so a malformed snapshot surfaces here (in
	// the fatal path) rather than on the first inbound request. A scoped
	// authority may legitimately DENY the probe path — that is not a
	// construction failure, so we only reject a non-nil transient error
	// (nil map, provider dial failure), never a clean Deny.
	if _, err := az.Authorize(context.Background(), zapserver.Identity{
		NodeID: snap.validators[0],
	}, "self-test", zapserver.OpAuthGet); err != nil {
		return nil, fmt.Errorf("authorizer self-test: %w", err)
	}
	return az, nil
}

// newAuthorityProvider builds the AuthorityProvider for one authority. A
// nil scope map yields a flat (unconfined) provider and logs a WARN — a
// compromised member key of a flat authority can reach the entire secret
// tree, so an unscoped production authority is a blast-radius liability the
// operator should close by emitting scopes.<authority>. A non-nil scope map
// yields a least-privilege scoped provider (members confined to their
// granted prefix; un-granted members fail closed).
func newAuthorityProvider(members []ids.NodeID, scopes map[ids.NodeID]string, name string) zapserver.AuthorityProvider {
	if scopes == nil {
		log.Printf("kms: WARNING: consensus %s authority is UNCONFINED (%d members, no scopes) — "+
			"a compromised member key can reach the ENTIRE secret tree; emit scopes to enable least-privilege",
			name, len(members))
		return zapserver.NewStaticAuthorityProvider(members)
	}
	log.Printf("kms: consensus %s authority scoped (%d members, %d grants) — least-privilege enforced",
		name, len(members), len(scopes))
	return zapserver.NewScopedAuthorityProvider(members, scopes)
}

// loadConsensusSnapshot returns the fully-parsed authority data
// (validators + operators NodeID sets, plus optional per-authority scope
// maps), sourcing from KMS_CONSENSUS_FILE first then falling back to
// KMS_CONSENSUS_VALIDATORS + KMS_CONSENSUS_OPERATORS env vars. The env-var
// carriage has no scope channel, so it always yields flat authorities.
func loadConsensusSnapshot() (parsedSnapshot, error) {
	if path := strings.TrimSpace(os.Getenv(envFile)); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return parsedSnapshot{}, fmt.Errorf("%s: %w", envFile, err)
		}
		var snap consensusSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return parsedSnapshot{}, fmt.Errorf("%s: %w", envFile, err)
		}
		validators, err := parseNodeIDs(snap.Validators)
		if err != nil {
			return parsedSnapshot{}, fmt.Errorf("%s validators: %w", envFile, err)
		}
		operators, err := parseNodeIDs(snap.Operators)
		if err != nil {
			return parsedSnapshot{}, fmt.Errorf("%s operators: %w", envFile, err)
		}
		ps := parsedSnapshot{validators: validators, operators: operators}
		if snap.Scopes != nil {
			if snap.Scopes.Validators != nil {
				ps.validatorScopes, err = parseScopeMap(snap.Scopes.Validators)
				if err != nil {
					return parsedSnapshot{}, fmt.Errorf("%s scopes.validators: %w", envFile, err)
				}
			}
			if snap.Scopes.Operators != nil {
				ps.operatorScopes, err = parseScopeMap(snap.Scopes.Operators)
				if err != nil {
					return parsedSnapshot{}, fmt.Errorf("%s scopes.operators: %w", envFile, err)
				}
			}
		}
		return ps, nil
	}
	validators, err := parseNodeIDs(splitLines(os.Getenv(envValidators)))
	if err != nil {
		return parsedSnapshot{}, fmt.Errorf("%s: %w", envValidators, err)
	}
	operators, err := parseNodeIDs(splitLines(os.Getenv(envOperators)))
	if err != nil {
		return parsedSnapshot{}, fmt.Errorf("%s: %w", envOperators, err)
	}
	return parsedSnapshot{validators: validators, operators: operators}, nil
}

// parseScopeMap parses a NodeID-string→path-prefix map into a
// NodeID→prefix map. Each key MUST be a valid NodeID (a typo is a hard
// failure — refusing to boot with a malformed scope grant, matching
// parseNodeIDs). The prefix value is normalized (surrounding whitespace and
// slashes trimmed) so scope containment compares canonical "/"-joined
// paths; an empty prefix means the member is unconfined (root). The result
// is non-nil even for an empty input so the caller distinguishes "scoped,
// zero grants" (fail-closed for every member) from "flat, no scopes" (nil).
func parseScopeMap(raw map[string]string) (map[ids.NodeID]string, error) {
	out := make(map[ids.NodeID]string, len(raw))
	for k, v := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		id, err := ids.NodeIDFromString(k)
		if err != nil {
			return nil, fmt.Errorf("scope key %q: %w", k, err)
		}
		out[id] = strings.Trim(strings.TrimSpace(v), "/")
	}
	return out, nil
}

// splitLines splits on newlines, commas, and whitespace. Empty
// elements are dropped. Lets the operator pick whichever delimiter is
// convenient for its template engine.
func splitLines(raw string) []string {
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 8)
	field := strings.Builder{}
	for _, r := range raw {
		if r == '\n' || r == ',' || r == ' ' || r == '\t' || r == '\r' {
			if field.Len() > 0 {
				out = append(out, field.String())
				field.Reset()
			}
			continue
		}
		field.WriteRune(r)
	}
	if field.Len() > 0 {
		out = append(out, field.String())
	}
	return out
}

// parseNodeIDs returns the parsed NodeID slice; any malformed entry
// is a hard failure (refuses to boot with a typo in the snapshot).
func parseNodeIDs(items []string) ([]ids.NodeID, error) {
	out := make([]ids.NodeID, 0, len(items))
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		id, err := ids.NodeIDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", s, err)
		}
		out = append(out, id)
	}
	return out, nil
}
