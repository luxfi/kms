// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// consensus_scopes_test.go — boot-wiring coverage for the scope overlay.
//
// This is the level that decides whether a deployed pod changes
// behaviour, so it pins the two properties that keep this gate inert:
//
//   - every snapshot in the field today (no `scopes` key) still decodes,
//     and yields NO overlay;
//   - with KMS_AUTHZ_MODE unset, wrapAuthzMode returns the authorizer it
//     was handed, verbatim.

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

// writeSnapshot drops a snapshot file and points KMS_CONSENSUS_FILE at it.
func writeSnapshot(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "consensus-authority.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	t.Setenv(envFile, p)
}

const (
	nodeA = "NodeID-FjdREJWf4CHPfr1DVnQVuMf8ouRVgTMBH"
	nodeB = "NodeID-HHsMJb8a4tjymPUcnsZTuqn3WXDhEkUaJ"
)

// TestLoadConsensusSnapshot_LegacyFileHasNoOverlay — the exact bytes the
// operator emitted before this gate. It must still load, and the overlay
// must be nil (not an empty map, which would read as "scoped, nothing
// granted").
func TestLoadConsensusSnapshot_LegacyFileHasNoOverlay(t *testing.T) {
	writeSnapshot(t, `{"validators":["`+nodeA+`"],"operators":["`+nodeB+`"]}`)

	validators, operators, scopes, err := loadConsensusSnapshot()
	if err != nil {
		t.Fatalf("legacy snapshot failed to load: %v", err)
	}
	if len(validators) != 1 || len(operators) != 1 {
		t.Fatalf("authority sets misread: %v / %v", validators, operators)
	}
	if scopes != nil {
		t.Fatalf("legacy snapshot produced a non-nil overlay (%v) — absent must mean absent", scopes)
	}
}

// TestLoadConsensusSnapshot_UnknownKeysIgnored — a snapshot from a NEWER
// operator must not break an older kmsd. Forward compatibility is what
// lets the operator ship the overlay before any kmsd consumes it.
func TestLoadConsensusSnapshot_UnknownKeysIgnored(t *testing.T) {
	writeSnapshot(t, `{"validators":["`+nodeA+`"],"operators":["`+nodeB+`"],"somethingNew":{"a":1}}`)
	if _, _, _, err := loadConsensusSnapshot(); err != nil {
		t.Fatalf("unknown key broke the decode: %v", err)
	}
}

// TestLoadConsensusSnapshot_ParsesIdentityScopes — the overlay the
// operator now emits, decoded into the NodeID-keyed form.
func TestLoadConsensusSnapshot_ParsesIdentityScopes(t *testing.T) {
	writeSnapshot(t, `{
	  "validators":["`+nodeA+`"],
	  "operators":["`+nodeB+`"],
	  "scopes":{"identities":{
	    "`+nodeB+`":{"unconfined":true,"grants":[]},
	    "`+nodeA+`":{"grants":[
	      {"org":"hanzo","env":"prod","path":"bootnode"},
	      {"org":"hanzo","env":"prod","path":"bootnode-secrets"}
	    ]}
	  }}
	}`)

	_, _, scopes, err := loadConsensusSnapshot()
	if err != nil {
		t.Fatalf("scoped snapshot failed to load: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 identity entries, got %d: %v", len(scopes), scopes)
	}
	opID, err := ids.NodeIDFromString(nodeB)
	if err != nil {
		t.Fatal(err)
	}
	if !scopes[opID].Unconfined {
		t.Error("operator entry lost its Unconfined flag")
	}
	svcID, err := ids.NodeIDFromString(nodeA)
	if err != nil {
		t.Fatal(err)
	}
	svc := scopes[svcID]
	if svc.Unconfined {
		t.Error("service entry must not be unconfined")
	}
	if len(svc.Grants) != 2 {
		t.Fatalf("grant SET truncated to %d — the many-to-many shape must survive: %v", len(svc.Grants), svc.Grants)
	}
}

// TestLoadConsensusSnapshot_MalformedScopeNodeIDIsFatal — a typo in the
// overlay must fail at boot, matching how the authority lists behave.
func TestLoadConsensusSnapshot_MalformedScopeNodeIDIsFatal(t *testing.T) {
	writeSnapshot(t, `{"validators":["`+nodeA+`"],"operators":["`+nodeB+`"],
	  "scopes":{"identities":{"not-a-node-id":{"grants":[]}}}}`)
	if _, _, _, err := loadConsensusSnapshot(); err == nil {
		t.Fatal("a malformed NodeID in the overlay must be a hard failure")
	}
}

// TestWrapAuthzMode_UnsetIsIdentity — with KMS_AUTHZ_MODE unset, the
// wiring hands back the SAME authorizer value. This is the property that
// makes deploying this build a no-op for every pod in the field.
func TestWrapAuthzMode_UnsetIsIdentity(t *testing.T) {
	t.Setenv(zapserver.EnvAuthzMode, "")
	inner := &noopAuthorizer{}
	got, err := wrapAuthzMode(inner, map[ids.NodeID]zapserver.Grants{
		{0x01}: {Grants: []zapserver.Grant{{Org: "hanzo", Env: "prod", Path: "x"}}},
	})
	if err != nil {
		t.Fatalf("wrapAuthzMode: %v", err)
	}
	if got != zapserver.ConsensusAuthorizer(inner) {
		t.Fatalf("unset mode wrapped the authorizer (%T) — deploying this build would change the request path", got)
	}
}

// TestWrapAuthzMode_AuditWraps — audit installs the observer even when
// the snapshot carries no overlay (in which case every allowed request is
// reported, which is the correct signal: nothing is granted yet).
func TestWrapAuthzMode_AuditWraps(t *testing.T) {
	t.Setenv(zapserver.EnvAuthzMode, "audit")
	inner := &noopAuthorizer{}
	got, err := wrapAuthzMode(inner, nil)
	if err != nil {
		t.Fatalf("wrapAuthzMode: %v", err)
	}
	if got == zapserver.ConsensusAuthorizer(inner) {
		t.Fatal("audit mode did not install the observer")
	}
}

// TestWrapAuthzMode_EnforceRefusesToBoot — enforcement is a later gate.
// Setting it must stop the process, not switch on denial.
func TestWrapAuthzMode_EnforceRefusesToBoot(t *testing.T) {
	t.Setenv(zapserver.EnvAuthzMode, "enforce")
	if _, err := wrapAuthzMode(&noopAuthorizer{}, nil); err == nil {
		t.Fatal("KMS_AUTHZ_MODE=enforce must refuse to boot in this build")
	}
}

// TestWrapAuthzMode_TypoRefusesToBoot — a misspelled mode must not
// silently degrade to "off".
func TestWrapAuthzMode_TypoRefusesToBoot(t *testing.T) {
	t.Setenv(zapserver.EnvAuthzMode, "audti")
	if _, err := wrapAuthzMode(&noopAuthorizer{}, nil); err == nil {
		t.Fatal("a misspelled KMS_AUTHZ_MODE must refuse to boot")
	}
}

// TestConsensusSnapshot_WireShapeMatchesOperator pins the cross-repo
// contract against the exact bytes hanzoai/kms-operator's
// bootstrap.Snapshot.MarshalCanonical produces.
func TestConsensusSnapshot_WireShapeMatchesOperator(t *testing.T) {
	const operatorBytes = `{"validators":["` + nodeA + `"],"operators":["` + nodeB + `"],` +
		`"scopes":{"identities":{"` + nodeB + `":{"unconfined":true,"grants":[]},` +
		`"` + nodeA + `":{"grants":[{"org":"hanzo","env":"prod","path":"llm-secrets"}]}}}}`

	var snap consensusSnapshot
	if err := json.Unmarshal([]byte(operatorBytes), &snap); err != nil {
		t.Fatalf("operator wire form did not decode: %v", err)
	}
	if snap.Scopes == nil || len(snap.Scopes.Identities) != 2 {
		t.Fatalf("overlay misread: %+v", snap.Scopes)
	}
	if g := snap.Scopes.Identities[nodeA].Grants; len(g) != 1 || g[0].Path != "llm-secrets" {
		t.Fatalf("grant misaligned: %+v", g)
	}
}

// noopAuthorizer is a distinct type so pointer identity is meaningful.
type noopAuthorizer struct{}

func (n *noopAuthorizer) Authorize(_ context.Context, _ zapserver.Identity, _ string, _ zapserver.Op) (zapserver.Decision, error) {
	return zapserver.Allow("test"), nil
}
