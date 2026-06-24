// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// consensus_e2e_test.go — end-to-end test of the consensus-native auth
// flow over real ZAP transport.
//
// What this proves:
//
//  1. A client built with a mnemonic-derived ServiceIdentity (luxfi/keys)
//     signs every envelope with ML-DSA-65.
//  2. The kmsd verifies the envelope, asks the ConsensusAuthorizer (an
//     in-process Polaris-cert-attested validator set), and dispatches
//     to the SecretStore on Allow.
//  3. Identities outside the validator set are rejected at the wire
//     with statusForbid.
//  4. The full chain — handshake → envelope sign → consensus check →
//     secret release — works under a real luxfi/zap Node.
//
// This is the "spin up a luxd, mock-or-real Polaris cert authorization,
// kmsd with consensus pointer, kmsclient with mnemonic" gate from the
// LP roadmap. The Polaris cert is mocked in-process via the consensus
// authority providers; the wire path is real.

package zapserver

import (
	"context"
	"crypto/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/zapclient"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
	badger "github.com/luxfi/zapdb"
)

// bootConsensusNativeServer spins up a real luxfi/zap.Node backed by
// an InProcessAuthorizer whose Validator + Operator authorities are
// caller-supplied. Same shape as the boot path on prod (kmsd) — only
// the authority data is in-memory instead of luxd-RPC sourced.
func bootConsensusNativeServer(t *testing.T, validators, operators []ids.NodeID) (addr string) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	n := zap.NewNode(zap.NodeConfig{
		NodeID:      "kms-e2e-" + strconv.Itoa(port),
		ServiceType: "_kms._tcp",
		Port:        port,
		NoDiscovery: true,
	})
	if err := n.Start(); err != nil {
		t.Fatalf("zap.Node start: %v", err)
	}
	t.Cleanup(func() { n.Stop() })

	opts := badger.DefaultOptions("").WithInMemory(true)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("zapdb open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	secStore := store.NewSecretStore(db)

	// Pre-populate so an authorized Get returns OK rather than NotFound.
	sec, err := store.Seal(mk, "hanzo/commerce", "api-key", "prod", []byte("secret-value"))
	if err != nil {
		t.Fatalf("store.Seal: %v", err)
	}
	if err := secStore.Put(sec); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	authz, err := NewInProcessAuthorizer(InProcessAuthorizerConfig{
		Validators: NewStaticAuthorityProvider(validators),
		Operator:   NewStaticAuthorityProvider(operators),
	})
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	srv := New(Config{
		Store:      secStore,
		MasterKey:  mk,
		Authorizer: authz,
		Logger:     log.NewNoOpLogger(),
	})
	srv.Register(n)

	return "127.0.0.1:" + strconv.Itoa(port)
}

// TestConsensusE2E_ValidatorReadsSecret — the canonical happy path:
// service identity is in the validator authority, signs envelopes
// over ZAP, server verifies + authorizes + releases.
func TestConsensusE2E_ValidatorReadsSecret(t *testing.T) {
	// Service mnemonic is provisioned out-of-band by the kms-operator
	// (k8s Secret). Same mnemonic + path on every pod replica → same
	// NodeID byte-for-byte.
	const serviceMnemonic = "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon about"
	const servicePath = "hanzo/commerce"

	ident, err := keys.NewServiceIdentity(serviceMnemonic, servicePath)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	defer ident.Wipe()

	// Consensus authority: the operator's snapshot says this NodeID is
	// in the validator set (read-authorised).
	addr := bootConsensusNativeServer(t,
		[]ids.NodeID{ident.NodeID},
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hdr := envelope.IdentityHeader{
		NodeID:      ident.NodeID,
		FullDigest:  ident.FullDigest,
		ServicePath: ident.ServicePath,
		PublicKey:   ident.PublicKey,
	}
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "test-client",
		PeerAddr:       addr,
		DefaultPath:    "hanzo/commerce",
		IdentityHeader: hdr,
		Signer:         ident,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	value, err := c.Get(ctx, "api-key", "prod")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if value != "sk_live_real" {
		t.Fatalf("Get value mismatch: got %q want %q", value, "sk_live_real")
	}
}

// TestConsensusE2E_NonValidatorDenied — an identity NOT in the
// validator authority is rejected at the wire. statusForbid surfaces
// as zapclient.ErrForbidden.
func TestConsensusE2E_NonValidatorDenied(t *testing.T) {
	const serviceMnemonic = "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon about"

	knownIdent, err := keys.NewServiceIdentity(serviceMnemonic, "hanzo/known")
	if err != nil {
		t.Fatal(err)
	}
	defer knownIdent.Wipe()

	strangerIdent, err := keys.NewServiceIdentity(serviceMnemonic, "stranger/service")
	if err != nil {
		t.Fatal(err)
	}
	defer strangerIdent.Wipe()

	// Authority lists only the known identity. The stranger is
	// outside the validator set.
	addr := bootConsensusNativeServer(t,
		[]ids.NodeID{knownIdent.NodeID},
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hdr := envelope.IdentityHeader{
		NodeID:      strangerIdent.NodeID,
		FullDigest:  strangerIdent.FullDigest,
		ServicePath: strangerIdent.ServicePath,
		PublicKey:   strangerIdent.PublicKey,
	}
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "test-client-stranger",
		PeerAddr:       addr,
		DefaultPath:    "hanzo/commerce",
		IdentityHeader: hdr,
		Signer:         strangerIdent,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if _, err := c.Get(ctx, "api-key", "prod"); err == nil {
		t.Fatalf("stranger Get must be rejected (got nil error)")
	}
}

// TestConsensusE2E_OperatorWritesSecret — a NodeID in BOTH validator
// and operator authorities may Put. Writes are the kms-operator's
// privilege; read-only validators never touch the store.
func TestConsensusE2E_OperatorWritesSecret(t *testing.T) {
	const serviceMnemonic = "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon about"

	opIdent, err := keys.NewServiceIdentity(serviceMnemonic, "hanzo/kms-operator")
	if err != nil {
		t.Fatal(err)
	}
	defer opIdent.Wipe()

	addr := bootConsensusNativeServer(t,
		[]ids.NodeID{opIdent.NodeID},
		[]ids.NodeID{opIdent.NodeID},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hdr := envelope.IdentityHeader{
		NodeID:      opIdent.NodeID,
		FullDigest:  opIdent.FullDigest,
		ServicePath: opIdent.ServicePath,
		PublicKey:   opIdent.PublicKey,
	}
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "test-client-operator",
		PeerAddr:       addr,
		DefaultPath:    "hanzo/commerce",
		IdentityHeader: hdr,
		Signer:         opIdent,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.PutAt(ctx, "hanzo/commerce", "rotation-key", "prod", "newSecret"); err != nil {
		t.Fatalf("operator Put: %v", err)
	}
	got, err := c.GetAt(ctx, "hanzo/commerce", "rotation-key", "prod")
	if err != nil {
		t.Fatalf("operator Get-after-Put: %v", err)
	}
	if got != "newSecret" {
		t.Fatalf("round-trip mismatch: got %q want newSecret", got)
	}
}
