// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// http_test.go — the HTTP /v1/sdk surface. These tests drive the real
// http.Handler end-to-end (httptest), so envelope verification,
// consensus authorization, the nonce ledger, and the secret-store /
// sign-backend dispatch all run exactly as they do in production. The
// only in-memory piece is the authority snapshot (a StaticAuthority
// provider) and, for sign/verify, a recorder SignBackend that records
// delegation WITHOUT faking threshold crypto.

package zapserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/log"
	badger "github.com/luxfi/zapdb"
)

// httpTestClock is the wall-clock the test server pins. Envelopes sign
// under the same value so freshness passes unless a test deliberately
// skews.
var httpTestClock = time.Unix(1_717_200_000, 0)

// recorderSigner is a SignBackend test double. It RECORDS every
// delegation so a test can assert the KMS handed the backend the right
// (validatorID, keyType, message) — it does NOT fake threshold math. The
// real t-of-n signature correctness lives in luxfi/mpc; this proves only
// the KMS-side auth + dispatch contract.
type recorderSigner struct {
	mu          sync.Mutex
	signCalls   []signCall
	verifyCalls []signCall
	verifyRet   bool
}

type signCall struct {
	validatorID string
	keyType     string
	msg         []byte
	sig         []byte
}

func (r *recorderSigner) Sign(_ context.Context, validatorID, keyType string, msg []byte) (SignResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signCalls = append(r.signCalls, signCall{validatorID: validatorID, keyType: keyType, msg: append([]byte(nil), msg...)})
	return SignResult{Signature: "sig:" + validatorID + ":" + keyType}, nil
}

func (r *recorderSigner) Verify(_ context.Context, validatorID, keyType string, msg, sig []byte) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifyCalls = append(r.verifyCalls, signCall{validatorID: validatorID, keyType: keyType, msg: append([]byte(nil), msg...), sig: append([]byte(nil), sig...)})
	return r.verifyRet, nil
}

func (r *recorderSigner) signCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.signCalls)
}

// newHTTPServer wires a Server with an in-memory SecretStore and an
// optional signer, returning the server and its /v1/sdk handler.
func newHTTPServer(t *testing.T, validators, operators []ids.NodeID, signer SignBackend) (*Server, http.Handler) {
	t.Helper()
	opts := badger.DefaultOptions("").WithInMemory(true)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mk := make([]byte, 32)
	for i := range mk {
		mk[i] = byte(i + 1)
	}
	authz, err := NewInProcessAuthorizer(InProcessAuthorizerConfig{
		Validators: NewStaticAuthorityProvider(validators),
		Operator:   NewStaticAuthorityProvider(operators),
	})
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	srv := New(Config{
		Store:      store.NewSecretStore(db),
		MasterKey:  mk,
		Authorizer: authz,
		Signer:     signer,
		Logger:     log.NewNoOpLogger(),
		Now:        func() time.Time { return httpTestClock },
	})
	return srv, srv.HTTPHandler()
}

// tlsChannel runs a real TLS handshake over an in-memory pipe and hands
// back the server's view of it. Both ends of that handshake are the
// test, so the exporter it yields is the same value a real client on the
// far end would compute — which is what lets these tests address an
// envelope to the connection they are about to send it on.
func tlsChannel(t *testing.T) *tls.ConnectionState {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kms-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"kms-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	cliPipe, srvPipe := net.Pipe()
	t.Cleanup(func() { cliPipe.Close(); srvPipe.Close() })
	srvConn := tls.Server(srvPipe, &tls.Config{Certificates: []tls.Certificate{cert}})
	cliConn := tls.Client(cliPipe, &tls.Config{InsecureSkipVerify: true, ServerName: "kms-test"})

	done := make(chan error, 1)
	go func() { done <- srvConn.Handshake() }()
	if err := cliConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	state := srvConn.ConnectionState()
	return &state
}

// bindOf is the binding the KMS derives for a connection — the same one
// the caller must name in its envelope.
func bindOf(t *testing.T, state *tls.ConnectionState) []byte {
	t.Helper()
	b, err := state.ExportKeyingMaterial(bindLabel, nil, envelope.BindSize)
	if err != nil {
		t.Fatalf("exporter: %v", err)
	}
	return b
}

// do issues a signed-envelope POST to /v1/sdk/secrets over a TLS
// connection, with the envelope addressed to that connection, and
// returns the recorder.
func do(t *testing.T, h http.Handler, ident *keys.ServiceIdentity, op uint16, inner any, nonce string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	state := tlsChannel(t)
	raw := envelopeFor(t, ident, op, buildInner(t, inner), now, nonce, bindOf(t, state))
	return send(t, h, raw, state)
}

// send posts already-built envelope bytes over the given connection.
// Tests that send twice reuse one connection, which is what a replay
// actually looks like.
func send(t *testing.T, h http.Handler, raw []byte, state *tls.ConnectionState) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/sdk/secrets", bytes.NewReader(raw))
	req.TLS = state
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// seedHTTP puts a sealed secret directly into the server's store.
func seedHTTP(t *testing.T, s *Server, path, name, env, value string) {
	t.Helper()
	sec, err := store.Seal(s.masterKey, path, name, env, []byte(value))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := s.store.Put(sec); err != nil {
		t.Fatalf("put: %v", err)
	}
}

// ---- secret plane ----

func TestHTTP_ValidatorGet_200(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	srv, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, nil, nil)
	seedHTTP(t, srv, "hanzo/auto", "api-key", "prod", "sk_live_42")

	rec := do(t, h, ident, OpSecretGet, getReq{Path: "hanzo/auto", Name: "api-key", Env: "prod"}, "n1", httpTestClock)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out getResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	pt, err := base64.StdEncoding.DecodeString(out.Value)
	if err != nil {
		t.Fatalf("b64: %v", err)
	}
	if string(pt) != "sk_live_42" {
		t.Fatalf("value=%q want sk_live_42", pt)
	}
}

func TestHTTP_NonValidator_403(t *testing.T) {
	stranger := newIdentity(t, "stranger/svc")
	defer stranger.Wipe()
	known := newIdentity(t, "hanzo/auto")
	defer known.Wipe()
	srv, h := newHTTPServer(t, []ids.NodeID{known.NodeID}, nil, nil)
	seedHTTP(t, srv, "hanzo/auto", "api-key", "prod", "v")

	rec := do(t, h, stranger, OpSecretGet, getReq{Path: "hanzo/auto", Name: "api-key", Env: "prod"}, "n1", httpTestClock)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stranger Get code=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_ValidatorWrite_403(t *testing.T) {
	// A validator that is NOT in the operator set may read but not write.
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	_, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, nil, nil)

	put := putReq{Path: "hanzo/auto", Name: "k", Env: "prod", Value: base64.StdEncoding.EncodeToString([]byte("v"))}
	rec := do(t, h, ident, OpSecretPut, put, "n1", httpTestClock)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("validator Put code=%d want 403", rec.Code)
	}
	del := delReq{Path: "hanzo/auto", Name: "k", Env: "prod"}
	rec = do(t, h, ident, OpSecretDelete, del, "n2", httpTestClock)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("validator Delete code=%d want 403", rec.Code)
	}
}

func TestHTTP_OperatorPut_Then_Get(t *testing.T) {
	op := newIdentity(t, "hanzo/kms-operator")
	defer op.Wipe()
	_, h := newHTTPServer(t, []ids.NodeID{op.NodeID}, []ids.NodeID{op.NodeID}, nil)

	put := putReq{Path: "hanzo/commerce", Name: "api-key", Env: "prod", Value: base64.StdEncoding.EncodeToString([]byte("sk_live_xxx"))}
	rec := do(t, h, op, OpSecretPut, put, "n1", httpTestClock)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator Put code=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, op, OpSecretGet, getReq{Path: "hanzo/commerce", Name: "api-key", Env: "prod"}, "n2", httpTestClock)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator Get code=%d", rec.Code)
	}
	var out getResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	pt, _ := base64.StdEncoding.DecodeString(out.Value)
	if string(pt) != "sk_live_xxx" {
		t.Fatalf("round-trip value=%q", pt)
	}
}

// Rotate is not a separate opcode: rotating a secret value is an
// operator Put (upsert). This pins that contract — a second Put replaces
// the value and a Get returns the latest.
func TestHTTP_Rotate_IsUpsertPut(t *testing.T) {
	op := newIdentity(t, "hanzo/kms-operator")
	defer op.Wipe()
	_, h := newHTTPServer(t, []ids.NodeID{op.NodeID}, []ids.NodeID{op.NodeID}, nil)

	for i, val := range []string{"v1", "v2"} {
		put := putReq{Path: "p", Name: "k", Env: "prod", Value: base64.StdEncoding.EncodeToString([]byte(val))}
		rec := do(t, h, op, OpSecretPut, put, "put-"+val, httpTestClock)
		if rec.Code != http.StatusOK {
			t.Fatalf("put[%d] code=%d", i, rec.Code)
		}
	}
	rec := do(t, h, op, OpSecretGet, getReq{Path: "p", Name: "k", Env: "prod"}, "get", httpTestClock)
	var out getResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	pt, _ := base64.StdEncoding.DecodeString(out.Value)
	if string(pt) != "v2" {
		t.Fatalf("rotate: got %q want v2", pt)
	}
}

func TestHTTP_GetMissing_404(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	_, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, nil, nil)
	rec := do(t, h, ident, OpSecretGet, getReq{Path: "hanzo/auto", Name: "nope", Env: "prod"}, "n1", httpTestClock)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing Get code=%d want 404", rec.Code)
	}
}

func TestHTTP_Replay_403(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	srv, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, nil, nil)
	seedHTTP(t, srv, "hanzo/auto", "api-key", "prod", "v")

	state := tlsChannel(t)
	raw := envelopeFor(t, ident, OpSecretGet, buildInner(t, getReq{Path: "hanzo/auto", Name: "api-key", Env: "prod"}), httpTestClock, "replay-nonce", bindOf(t, state))

	first := send(t, h, raw, state)
	if first.Code != http.StatusOK {
		t.Fatalf("first code=%d body=%s", first.Code, first.Body.String())
	}
	second := send(t, h, raw, state)
	if second.Code != http.StatusForbidden {
		t.Fatalf("replay code=%d want 403", second.Code)
	}
	// Replay must be masked as a generic "forbidden" — no ledger probe.
	var e map[string]string
	_ = json.Unmarshal(second.Body.Bytes(), &e)
	if e["error"] != "forbidden" {
		t.Fatalf("replay body=%q want generic forbidden", second.Body.String())
	}
}

func TestHTTP_Stale_403(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	_, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, nil, nil)
	// Sign 10 minutes in the past; server clock is httpTestClock.
	old := httpTestClock.Add(-10 * time.Minute)
	rec := do(t, h, ident, OpSecretGet, getReq{Path: "hanzo/auto", Name: "k", Env: "prod"}, "stale", old)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stale code=%d want 403", rec.Code)
	}
}

func TestHTTP_Malformed_400(t *testing.T) {
	_, h := newHTTPServer(t, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/sdk/secrets", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed code=%d want 400", rec.Code)
	}
}

func TestHTTP_Tampered_403(t *testing.T) {
	ident := newIdentity(t, "hanzo/kms-operator")
	defer ident.Wipe()
	_, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, []ids.NodeID{ident.NodeID}, nil)

	raw := signedEnvelopeBytes(t, ident, OpSecretPut, buildInner(t, putReq{
		Path: "p", Name: "k", Env: "prod", Value: base64.StdEncoding.EncodeToString([]byte("ok")),
	}), httpTestClock, "tamper")
	// Swap the inner value AFTER signing; signature no longer covers it.
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Req = buildInner(t, putReq{Path: "p", Name: "k", Env: "prod", Value: base64.StdEncoding.EncodeToString([]byte("EVIL"))})
	tampered, _ := json.Marshal(env)

	req := httptest.NewRequest(http.MethodPost, "/v1/sdk/secrets", bytes.NewReader(tampered))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tampered code=%d want 403", rec.Code)
	}
}

func TestHTTP_Oversize_413(t *testing.T) {
	_, h := newHTTPServer(t, nil, nil, nil)
	big := bytes.Repeat([]byte("A"), MaxEnvelopeBytes+2)
	req := httptest.NewRequest(http.MethodPost, "/v1/sdk/secrets", bytes.NewReader(big))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize code=%d want 413", rec.Code)
	}
}

func TestHTTP_UnknownOpcode_403(t *testing.T) {
	// A validly-signed envelope carrying an opcode the authorizer does
	// not recognise is denied at authorization (not dispatched).
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	_, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, []ids.NodeID{ident.NodeID}, nil)
	rec := do(t, h, ident, 0x9999, map[string]string{"path": "p"}, "n1", httpTestClock)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown op code=%d want 403", rec.Code)
	}
}

// ---- threshold sign / verify plane ----

func TestHTTP_Sign_OperatorDelegates(t *testing.T) {
	op := newIdentity(t, "hanzo/kms-operator")
	defer op.Wipe()
	rec := &recorderSigner{}
	_, h := newHTTPServer(t, []ids.NodeID{op.NodeID}, []ids.NodeID{op.NodeID}, rec)

	msg := []byte("block-header-bytes")
	req := signReq{ValidatorID: "val-1", KeyType: "bls", Message: base64.StdEncoding.EncodeToString(msg)}
	resp := do(t, h, op, OpSign, req, "n1", httpTestClock)
	if resp.Code != http.StatusOK {
		t.Fatalf("operator Sign code=%d body=%s", resp.Code, resp.Body.String())
	}
	if rec.signCount() != 1 {
		t.Fatalf("backend sign calls=%d want 1", rec.signCount())
	}
	got := rec.signCalls[0]
	if got.validatorID != "val-1" || got.keyType != "bls" || !bytes.Equal(got.msg, msg) {
		t.Fatalf("delegated wrong params: %+v", got)
	}
	var out SignResult
	_ = json.Unmarshal(resp.Body.Bytes(), &out)
	if out.Signature != "sig:val-1:bls" {
		t.Fatalf("sig=%q", out.Signature)
	}
}

func TestHTTP_Sign_Validator_403_NoDelegation(t *testing.T) {
	// A read-only validator (not in operator set) must NOT be able to
	// sign, and the backend must NEVER be reached.
	val := newIdentity(t, "hanzo/auto")
	defer val.Wipe()
	rec := &recorderSigner{}
	_, h := newHTTPServer(t, []ids.NodeID{val.NodeID}, nil, rec)

	req := signReq{ValidatorID: "val-1", KeyType: "bls", Message: base64.StdEncoding.EncodeToString([]byte("m"))}
	resp := do(t, h, val, OpSign, req, "n1", httpTestClock)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("validator Sign code=%d want 403", resp.Code)
	}
	if rec.signCount() != 0 {
		t.Fatalf("backend was called %d times on a forbidden sign — auth must gate BEFORE dispatch", rec.signCount())
	}
}

func TestHTTP_Sign_Replay_403(t *testing.T) {
	op := newIdentity(t, "hanzo/kms-operator")
	defer op.Wipe()
	rec := &recorderSigner{}
	_, h := newHTTPServer(t, []ids.NodeID{op.NodeID}, []ids.NodeID{op.NodeID}, rec)

	state := tlsChannel(t)
	raw := envelopeFor(t, op, OpSign, buildInner(t, signReq{
		ValidatorID: "val-1", KeyType: "corona", Message: base64.StdEncoding.EncodeToString([]byte("m")),
	}), httpTestClock, "sign-replay", bindOf(t, state))

	r1 := send(t, h, raw, state)
	if r1.Code != http.StatusOK {
		t.Fatalf("first sign code=%d", r1.Code)
	}
	r2 := send(t, h, raw, state)
	if r2.Code != http.StatusForbidden {
		t.Fatalf("replayed sign code=%d want 403", r2.Code)
	}
	// The replayed sign must not have reached the backend a second time.
	if rec.signCount() != 1 {
		t.Fatalf("backend sign calls=%d want 1 (replay must be blocked before dispatch)", rec.signCount())
	}
}

func TestHTTP_Sign_NotConfigured_400(t *testing.T) {
	// Operator auth passes but no SignBackend is wired → statusError → 400.
	op := newIdentity(t, "hanzo/kms-operator")
	defer op.Wipe()
	_, h := newHTTPServer(t, []ids.NodeID{op.NodeID}, []ids.NodeID{op.NodeID}, nil)
	req := signReq{ValidatorID: "val-1", KeyType: "bls", Message: base64.StdEncoding.EncodeToString([]byte("m"))}
	resp := do(t, h, op, OpSign, req, "n1", httpTestClock)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("unconfigured Sign code=%d want 400", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "signing not configured") {
		t.Fatalf("body=%s", resp.Body.String())
	}
}

func TestHTTP_Verify_Validator_200(t *testing.T) {
	// Verify is a READ op — any validator may call it.
	val := newIdentity(t, "hanzo/auto")
	defer val.Wipe()
	rec := &recorderSigner{verifyRet: true}
	_, h := newHTTPServer(t, []ids.NodeID{val.NodeID}, nil, rec)

	req := verifyReq{
		ValidatorID: "val-1", KeyType: "corona",
		Message:   base64.StdEncoding.EncodeToString([]byte("m")),
		Signature: base64.StdEncoding.EncodeToString([]byte("s")),
	}
	resp := do(t, h, val, OpVerify, req, "n1", httpTestClock)
	if resp.Code != http.StatusOK {
		t.Fatalf("validator Verify code=%d body=%s", resp.Code, resp.Body.String())
	}
	var out map[string]bool
	_ = json.Unmarshal(resp.Body.Bytes(), &out)
	if !out["valid"] {
		t.Fatalf("verify body=%s want valid:true", resp.Body.String())
	}
	if len(rec.verifyCalls) != 1 {
		t.Fatalf("verify calls=%d want 1", len(rec.verifyCalls))
	}
}

func TestHTTP_Verify_NonValidator_403(t *testing.T) {
	stranger := newIdentity(t, "stranger/svc")
	defer stranger.Wipe()
	known := newIdentity(t, "hanzo/auto")
	defer known.Wipe()
	rec := &recorderSigner{verifyRet: true}
	_, h := newHTTPServer(t, []ids.NodeID{known.NodeID}, nil, rec)

	req := verifyReq{ValidatorID: "val-1", KeyType: "bls", Message: "", Signature: ""}
	resp := do(t, h, stranger, OpVerify, req, "n1", httpTestClock)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("stranger Verify code=%d want 403", resp.Code)
	}
	if len(rec.verifyCalls) != 0 {
		t.Fatalf("backend verify reached on forbidden request")
	}
}

// An envelope that reaches this surface over a connection with no keys
// of its own is refused. Without that, the HTTP door would launder any
// envelope an on-path attacker lifted off the ZAP wire: it would arrive
// signed, fresh, unreplayed, and addressed to somewhere else entirely.
func TestHTTPWithoutAChannelIsRefused(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	srv, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, nil, nil)
	seedHTTP(t, srv, "hanzo/auto", "api-key", "prod", "the-secret")

	state := tlsChannel(t)
	raw := envelopeFor(t, ident, OpSecretGet,
		buildInner(t, getReq{Path: "hanzo/auto", Name: "api-key", Env: "prod"}),
		httpTestClock, "no-channel", bindOf(t, state))

	// Same bytes, presented on nothing.
	rec := send(t, h, raw, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "the-secret") {
		t.Fatalf("the secret came back: %s", rec.Body.String())
	}
}

// The same, one step subtler: a real TLS connection, but not the one the
// envelope was written for.
func TestHTTPOnAnotherChannelIsRefused(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	srv, h := newHTTPServer(t, []ids.NodeID{ident.NodeID}, nil, nil)
	seedHTTP(t, srv, "hanzo/auto", "api-key", "prod", "the-secret")

	mine, theirs := tlsChannel(t), tlsChannel(t)
	if bytes.Equal(bindOf(t, mine), bindOf(t, theirs)) {
		t.Fatal("two TLS connections produced the same binding")
	}
	raw := envelopeFor(t, ident, OpSecretGet,
		buildInner(t, getReq{Path: "hanzo/auto", Name: "api-key", Env: "prod"}),
		httpTestClock, "other-channel", bindOf(t, mine))

	rec := send(t, h, raw, theirs)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "the-secret") {
		t.Fatalf("the secret came back: %s", rec.Body.String())
	}
}
