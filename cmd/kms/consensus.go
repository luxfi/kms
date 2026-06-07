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
type consensusSnapshot struct {
	Validators []string `json:"validators"`
	Operators  []string `json:"operators"`
}

// buildConsensusAuthorizer constructs the ConsensusAuthorizer wired
// at boot. Reads either KMS_CONSENSUS_FILE or the two NodeID env
// vars; refuses to boot if neither is present, since the ZAP server
// is fail-closed by construction.
func buildConsensusAuthorizer() (zapserver.ConsensusAuthorizer, error) {
	validators, operators, err := loadConsensusSnapshot()
	if err != nil {
		return nil, err
	}
	if len(validators) == 0 {
		return nil, errors.New("consensus validator authority is empty (refusing to boot fail-open)")
	}
	if len(operators) == 0 {
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
		Validators: zapserver.NewStaticAuthorityProvider(validators),
		Operator:   zapserver.NewStaticAuthorityProvider(operators),
		CacheTTL:   ttl,
	})
	if err != nil {
		return nil, err
	}
	// Probe both providers once so a malformed snapshot surfaces here
	// (in the fatal path) rather than on the first inbound request.
	if _, err := az.Authorize(context.Background(), zapserver.Identity{
		NodeID: validators[0],
	}, "self-test", zapserver.OpAuthGet); err != nil {
		return nil, fmt.Errorf("authorizer self-test: %w", err)
	}
	return az, nil
}

// loadConsensusSnapshot returns the (validators, operators) NodeID
// sets, sourcing from KMS_CONSENSUS_FILE first then falling back to
// KMS_CONSENSUS_VALIDATORS + KMS_CONSENSUS_OPERATORS env vars.
func loadConsensusSnapshot() ([]ids.NodeID, []ids.NodeID, error) {
	if path := strings.TrimSpace(os.Getenv(envFile)); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", envFile, err)
		}
		var snap consensusSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", envFile, err)
		}
		validators, err := parseNodeIDs(snap.Validators)
		if err != nil {
			return nil, nil, fmt.Errorf("%s validators: %w", envFile, err)
		}
		operators, err := parseNodeIDs(snap.Operators)
		if err != nil {
			return nil, nil, fmt.Errorf("%s operators: %w", envFile, err)
		}
		return validators, operators, nil
	}
	validators, err := parseNodeIDs(splitLines(os.Getenv(envValidators)))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", envValidators, err)
	}
	operators, err := parseNodeIDs(splitLines(os.Getenv(envOperators)))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", envOperators, err)
	}
	return validators, operators, nil
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
