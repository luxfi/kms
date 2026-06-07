// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// smoke-replay is a one-shot proof that the kmsd anti-replay ledger
// closes the wall-clock-window replay gap. The harness boots an
// in-process kmsd (with a 2-second nonce ledger TTL so we can exercise
// the post-TTL path in real time), opens a ZAP transport, then exercises
// three scenarios in order:
//
//   1. Submit a freshly-signed envelope — expect statusOK ("first OK").
//   2. Submit the SAME envelope bytes again within TTL — expect
//      statusForbid with reason "envelope: replay-detected" ("replay
//      rejected").
//   3. Sleep > ledger TTL, submit a freshly-signed envelope with a new
//      nonce — expect statusOK ("post-TTL fresh nonce OK").
//
// The harness exits non-zero on any deviation and prints the verbatim
// outcome at every step.
//
// Run:
//
//	go run ./cmd/smoke-replay
//
// Expected output (the canonical PASS):
//
//	smoke: boot listenAddr=127.0.0.1:NNNNN ledgerTTL=2s
//	smoke: identity nodeID=NodeID-... path=hanzo/commerce
//	smoke: scenario-1 first OK status=0x00 body={"value":"c21va2Utc2VlZA=="}
//	smoke: scenario-2 replay rejected status=0x03 body={"error":"envelope: replay-detected"}
//	smoke: scenario-3 post-TTL fresh nonce OK status=0x00 body={"value":"c21va2Utc2VlZA=="}
//	smoke: PASS
//
// Any deviation is FAIL with a non-zero exit code.

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/zapserver"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
	badger "github.com/luxfi/zapdb"
)

// The smoke harness is its own binary, so we keep parameters as
// constants. ledgerTTL is deliberately small (2s) so the post-TTL
// scenario runs in a few seconds end-to-end. Production kmsd uses
// envelope.DefaultNonceLedgerTTL = MaxClockSkew + 1m = 6m.
const (
	ledgerTTL     = 2 * time.Second
	ledgerGC      = 500 * time.Millisecond
	smokeMnemonic = "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon about"
	smokeServicePath = "hanzo/commerce"
	smokeSecretPath  = "hanzo/commerce"
	smokeSecretName  = "ping"
	smokeSecretEnv   = "smoke"
	smokeSecretValue = "smoke-seed"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "smoke: FAIL %v\n", err)
		os.Exit(1)
	}
	fmt.Println("smoke: PASS")
}

func run() error {
	ident, err := keys.NewServiceIdentity(smokeMnemonic, smokeServicePath)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	defer ident.Wipe()

	srv, addr, cleanup, err := bootServer(ident.NodeID)
	if err != nil {
		return fmt.Errorf("boot: %w", err)
	}
	defer cleanup()
	_ = srv

	fmt.Printf("smoke: boot listenAddr=%s ledgerTTL=%s\n", addr, ledgerTTL)
	fmt.Printf("smoke: identity nodeID=%s path=%s\n", ident.NodeID.String(), smokeServicePath)

	// Scenario 1: fresh envelope → expect statusOK.
	envBytes1, err := signEnvelope(ident, time.Now(), randomNonce())
	if err != nil {
		return fmt.Errorf("sign env1: %w", err)
	}
	status1, body1, err := callDirect(addr, envBytes1)
	if err != nil {
		return fmt.Errorf("scenario-1: call: %w", err)
	}
	fmt.Printf("smoke: scenario-1 first OK status=0x%02X body=%s\n", status1, string(body1))
	if status1 != 0x00 {
		return fmt.Errorf("scenario-1 expected status=0x00, got 0x%02X body=%s", status1, body1)
	}

	// Scenario 2: replay same bytes → expect statusForbid + replay-detected.
	status2, body2, err := callDirect(addr, envBytes1)
	if err != nil {
		return fmt.Errorf("scenario-2: call: %w", err)
	}
	fmt.Printf("smoke: scenario-2 replay rejected status=0x%02X body=%s\n", status2, string(body2))
	if status2 != 0x03 {
		return fmt.Errorf("scenario-2 expected status=0x03 (forbid), got 0x%02X body=%s", status2, body2)
	}
	if !strings.Contains(string(body2), "replay-detected") {
		return fmt.Errorf("scenario-2 expected body to contain replay-detected, got %q", body2)
	}

	// Scenario 3: sleep past TTL, sign fresh envelope, expect statusOK.
	sleep := ledgerTTL + 500*time.Millisecond
	fmt.Printf("smoke: scenario-3 sleep %s past TTL...\n", sleep)
	time.Sleep(sleep)
	envBytes3, err := signEnvelope(ident, time.Now(), randomNonce())
	if err != nil {
		return fmt.Errorf("sign env3: %w", err)
	}
	status3, body3, err := callDirect(addr, envBytes3)
	if err != nil {
		return fmt.Errorf("scenario-3: call: %w", err)
	}
	fmt.Printf("smoke: scenario-3 post-TTL fresh nonce OK status=0x%02X body=%s\n", status3, string(body3))
	if status3 != 0x00 {
		return fmt.Errorf("scenario-3 expected status=0x00, got 0x%02X body=%s", status3, body3)
	}
	return nil
}

// bootServer brings up a real luxfi/zap.Node + zapserver.Server backed by
// an in-memory secret store and a tiny-TTL nonce ledger so the smoke
// harness can exercise replay defence in seconds. Returns the listen
// address and a cleanup func.
func bootServer(identity ids.NodeID) (*zapserver.Server, string, func(), error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", nil, fmt.Errorf("listen: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	n := zap.NewNode(zap.NodeConfig{
		NodeID:      "kms-smoke-" + strconv.Itoa(port),
		ServiceType: "_kms._tcp",
		Port:        port,
		NoDiscovery: true,
	})
	if err := n.Start(); err != nil {
		return nil, "", nil, fmt.Errorf("zap start: %w", err)
	}

	opts := badger.DefaultOptions("").WithInMemory(true)
	db, err := badger.Open(opts)
	if err != nil {
		n.Stop()
		return nil, "", nil, fmt.Errorf("zapdb: %w", err)
	}

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		db.Close()
		n.Stop()
		return nil, "", nil, fmt.Errorf("rand mk: %w", err)
	}
	secStore := store.NewSecretStore(db)
	sealed, err := store.Seal(mk, smokeSecretPath, smokeSecretName, smokeSecretEnv, []byte(smokeSecretValue))
	if err != nil {
		db.Close()
		n.Stop()
		return nil, "", nil, fmt.Errorf("seal: %w", err)
	}
	if err := secStore.Put(sealed); err != nil {
		db.Close()
		n.Stop()
		return nil, "", nil, fmt.Errorf("store.Put: %w", err)
	}

	authz, err := zapserver.NewInProcessAuthorizer(zapserver.InProcessAuthorizerConfig{
		Validators: zapserver.NewStaticAuthorityProvider([]ids.NodeID{identity}),
		Operator:   zapserver.NewStaticAuthorityProvider(nil),
	})
	if err != nil {
		db.Close()
		n.Stop()
		return nil, "", nil, fmt.Errorf("authz: %w", err)
	}

	ledger := zapserver.NewMemoryNonceLedger(zapserver.MemoryNonceLedgerConfig{
		TTL:        ledgerTTL,
		GCInterval: ledgerGC,
	})

	srv := zapserver.New(zapserver.Config{
		Store:       secStore,
		MasterKey:   mk,
		Authorizer:  authz,
		NonceLedger: ledger,
		Logger:      log.NewNoOpLogger(),
	})
	srv.Register(n)

	cleanup := func() {
		ledger.Stop()
		n.Stop()
		db.Close()
	}
	return srv, "127.0.0.1:" + strconv.Itoa(port), cleanup, nil
}

// signEnvelope builds an OpSecretGet envelope for the smoke secret.
// Pure function in (identity, time, nonce) so the harness can re-sign
// or replay verbatim by passing the same arguments.
func signEnvelope(ident *keys.ServiceIdentity, now time.Time, nonce string) ([]byte, error) {
	hdr := envelope.IdentityHeader{
		NodeID:      ident.NodeID,
		FullDigest:  ident.FullDigest,
		ServicePath: ident.ServicePath,
		PublicKey:   ident.PublicKey,
	}
	inner, err := json.Marshal(map[string]string{
		"path": smokeSecretPath,
		"name": smokeSecretName,
		"env":  smokeSecretEnv,
	})
	if err != nil {
		return nil, err
	}
	env, err := envelope.Build(hdr, ident, 0x0040, inner, nonce, now)
	if err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

// randomNonce returns a base64-encoded 16-byte random nonce. Same shape
// the canonical zapclient.call produces.
func randomNonce() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return base64.StdEncoding.EncodeToString(buf[:])
}

// callDirect dials the kmsd via a fresh luxfi/zap.Node, submits the
// pre-built envelope bytes as an OpSecretGet payload, and parses the
// status byte + JSON body from the response.
//
// The harness uses SkipHandshake → no hybrid session, no AEAD-seal of
// the body. That keeps the wire path simple for the smoke proof; the
// nonce ledger sits behind the verifyAndAuthorize chain and fires
// identically with or without a session.
func callDirect(addr string, envBytes []byte) (byte, []byte, error) {
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      "smoke-client-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		ServiceType: "_kms._tcp",
		Port:        0,
		NoDiscovery: true,
	})
	if err := n.Start(); err != nil {
		return 0, nil, fmt.Errorf("client start: %w", err)
	}
	defer n.Stop()

	if err := n.ConnectDirect(addr); err != nil {
		return 0, nil, fmt.Errorf("connect: %w", err)
	}
	var peerID string
	for _, p := range n.Peers() {
		peerID = p
		break
	}
	if peerID == "" {
		return 0, nil, errors.New("peer not resolved")
	}

	// Wire body: opcode(2 LE) || envelope bytes. Universal mux on the
	// server side dispatches via the first 2 bytes when no per-opcode
	// handler matches the message type.
	payload := make([]byte, 2+len(envBytes))
	binary.LittleEndian.PutUint16(payload[:2], 0x0040)
	copy(payload[2:], envBytes)

	b := zap.NewBuilder(len(payload) + 16)
	b.WriteBytes(payload)
	raw := b.Finish()
	msg, err := zap.Parse(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("build msg: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := n.Call(ctx, peerID, msg)
	if err != nil {
		return 0, nil, fmt.Errorf("call: %w", err)
	}
	root := resp.Root()
	body := root.Bytes(0)
	if len(body) < 1 {
		b := resp.Bytes()
		if len(b) <= zap.HeaderSize {
			return 0, nil, errors.New("empty response")
		}
		body = b[zap.HeaderSize:]
	}
	return body[0], body[1:], nil
}
