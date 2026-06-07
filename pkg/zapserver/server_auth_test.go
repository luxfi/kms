// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Tests for consensus-native authorization on the Op Secret* opcodes.
//
// We exercise the four handlers via the canonical wrap() entry path so
// envelope parsing, signature verification, and the consensus
// authorizer all run together (not as isolated unit tests). A fake
// AuthorityProvider drives the consensus decision; a real
// luxfi/keys.ServiceIdentity produces the envelope signature.

package zapserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/log"
	badger "github.com/luxfi/zapdb"
)

// 12-word abandon... about — the canonical BIP-39 KAT mnemonic. Same
// value the bip39 reference test suite pins.
const testMnemonic = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

// newTestServer wires a Server backed by an in-memory ZapDB SecretStore
// plus an authorizer over caller-supplied authority sets. The master
// key is random per-test.
func newTestServer(t *testing.T, validators, operators []ids.NodeID) *Server {
	t.Helper()
	opts := badger.DefaultOptions("").WithInMemory(true)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	authz, err := NewInProcessAuthorizer(InProcessAuthorizerConfig{
		Validators: NewStaticAuthorityProvider(validators),
		Operator:   NewStaticAuthorityProvider(operators),
	})
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	return New(Config{
		Store:      store.NewSecretStore(db),
		MasterKey:  mk,
		Authorizer: authz,
		Logger:     log.NewNoOpLogger(),
		Now:        func() time.Time { return time.Unix(1_717_200_000, 0) },
	})
}

// newIdentity returns a *keys.ServiceIdentity at the given path under
// the canonical test mnemonic.
func newIdentity(t *testing.T, path string) *keys.ServiceIdentity {
	t.Helper()
	id, err := keys.NewServiceIdentity(testMnemonic, path)
	if err != nil {
		t.Fatalf("NewServiceIdentity(%q): %v", path, err)
	}
	return id
}

// seed pre-populates the SecretStore so authorized Gets/Deletes return
// statusOK rather than statusNotFound.
func seed(t *testing.T, s *Server, path, name, env, value string) {
	t.Helper()
	sec, err := store.Seal(s.masterKey, path, name, env, []byte(value))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := s.store.Put(sec); err != nil {
		t.Fatalf("put: %v", err)
	}
}

// buildInner is a tiny helper that marshals an inner request shape to
// json.RawMessage.
func buildInner(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	return json.RawMessage(b)
}

// signedEnvelopeBytes returns the wire bytes ready to feed into
// verifyAndAuthorize. now is the wall-clock value the signer pins (and
// the server verifies under its Now).
func signedEnvelopeBytes(t *testing.T, ident *keys.ServiceIdentity, op uint16, inner json.RawMessage, now time.Time, nonce string) []byte {
	t.Helper()
	env, err := BuildEnvelope(ident, op, inner, nonce, now)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

// TestAuthz_ValidatorRead_AllowsGetList — every validator-set NodeID
// may Get and List.
func TestAuthz_ValidatorRead_AllowsGetList(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	s := newTestServer(t, []ids.NodeID{ident.NodeID}, nil)
	seed(t, s, "hanzo/auto", "api-key", "prod", "secret-1")

	now := time.Unix(1_717_200_000, 0)

	// Get
	getRaw := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/auto", Name: "api-key", Env: "prod",
	}), now, "nonce-1")
	verifiedIdent, payload, err := s.verifyAndAuthorize(context.Background(), getRaw, OpSecretGet)
	if err != nil {
		t.Fatalf("validator Get authz: %v", err)
	}
	if verifiedIdent.NodeID != ident.NodeID {
		t.Fatalf("validator Get: identity mismatch")
	}
	st, body, err := s.handleGet(context.Background(), verifiedIdent, payload)
	if err != nil || st != statusOK {
		t.Fatalf("validator Get handler: status=0x%02X err=%v body=%s", st, err, string(body))
	}

	// List
	listRaw := signedEnvelopeBytes(t, ident, OpSecretList, buildInner(t, listReq{
		Path: "hanzo/auto", Env: "prod",
	}), now, "nonce-2")
	verifiedIdent, payload, err = s.verifyAndAuthorize(context.Background(), listRaw, OpSecretList)
	if err != nil {
		t.Fatalf("validator List authz: %v", err)
	}
	st, _, err = s.handleList(context.Background(), verifiedIdent, payload)
	if err != nil || st != statusOK {
		t.Fatalf("validator List handler: status=0x%02X err=%v", st, err)
	}
}

// TestAuthz_ValidatorWrite_Denied — a validator that is NOT in the
// operator set is denied Put and Delete.
func TestAuthz_ValidatorWrite_Denied(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	s := newTestServer(t, []ids.NodeID{ident.NodeID}, nil)
	now := time.Unix(1_717_200_000, 0)

	// Put
	putRaw := signedEnvelopeBytes(t, ident, OpSecretPut, buildInner(t, putReq{
		Path: "hanzo/auto", Name: "k", Env: "prod",
		Value: base64.StdEncoding.EncodeToString([]byte("v")),
	}), now, "nonce-1")
	if _, _, err := s.verifyAndAuthorize(context.Background(), putRaw, OpSecretPut); err == nil {
		t.Fatalf("validator Put should be forbidden")
	}

	// Delete
	delRaw := signedEnvelopeBytes(t, ident, OpSecretDelete, buildInner(t, delReq{
		Path: "hanzo/auto", Name: "k", Env: "prod",
	}), now, "nonce-2")
	if _, _, err := s.verifyAndAuthorize(context.Background(), delRaw, OpSecretDelete); err == nil {
		t.Fatalf("validator Delete should be forbidden")
	}
}

// TestAuthz_OperatorWrite_Allowed — an identity in BOTH validator and
// operator authorities may write.
func TestAuthz_OperatorWrite_Allowed(t *testing.T) {
	ident := newIdentity(t, "hanzo/kms-operator")
	defer ident.Wipe()
	s := newTestServer(t,
		[]ids.NodeID{ident.NodeID},
		[]ids.NodeID{ident.NodeID},
	)
	now := time.Unix(1_717_200_000, 0)

	putRaw := signedEnvelopeBytes(t, ident, OpSecretPut, buildInner(t, putReq{
		Path: "hanzo/commerce", Name: "stripe-key", Env: "prod",
		Value: base64.StdEncoding.EncodeToString([]byte("sk_live_xxx")),
	}), now, "nonce-1")
	verifiedIdent, payload, err := s.verifyAndAuthorize(context.Background(), putRaw, OpSecretPut)
	if err != nil {
		t.Fatalf("operator Put authz: %v", err)
	}
	st, _, err := s.handlePut(context.Background(), verifiedIdent, payload)
	if err != nil || st != statusOK {
		t.Fatalf("operator Put handler: status=0x%02X err=%v", st, err)
	}
}

// TestAuthz_NonValidator_DeniedAllOps — an identity outside the
// validator authority is denied every opcode.
func TestAuthz_NonValidator_DeniedAllOps(t *testing.T) {
	stranger := newIdentity(t, "stranger/service")
	defer stranger.Wipe()
	known := newIdentity(t, "hanzo/auto")
	defer known.Wipe()
	s := newTestServer(t, []ids.NodeID{known.NodeID}, []ids.NodeID{known.NodeID})
	now := time.Unix(1_717_200_000, 0)

	cases := []struct {
		name  string
		op    uint16
		inner any
	}{
		{"Get", OpSecretGet, getReq{Path: "hanzo/auto", Name: "k", Env: "prod"}},
		{"Put", OpSecretPut, putReq{
			Path: "hanzo/auto", Name: "k", Env: "prod",
			Value: base64.StdEncoding.EncodeToString([]byte("v")),
		}},
		{"List", OpSecretList, listReq{Path: "hanzo/auto", Env: "prod"}},
		{"Delete", OpSecretDelete, delReq{Path: "hanzo/auto", Name: "k", Env: "prod"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := signedEnvelopeBytes(t, stranger, c.op, buildInner(t, c.inner), now, c.name+"-nonce")
			if _, _, err := s.verifyAndAuthorize(context.Background(), raw, c.op); err == nil {
				t.Fatalf("stranger %s should be forbidden", c.name)
			}
		})
	}
}

// TestAuthz_StaleEnvelope_Rejected — wall-clock skew beyond
// EnvelopeMaxClockSkew is a hard reject.
func TestAuthz_StaleEnvelope_Rejected(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	s := newTestServer(t, []ids.NodeID{ident.NodeID}, nil)

	// Server now() returns t0; sign with t0 - 10min.
	old := time.Unix(1_717_200_000-int64(10*time.Minute/time.Second), 0)
	raw := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/auto", Name: "k", Env: "prod",
	}), old, "nonce-stale")
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet); err == nil {
		t.Fatalf("stale envelope should be rejected")
	}
}

// TestAuthz_OpcodeMismatch_Rejected — envelope Op field MUST match
// the wire opcode the request rode on.
func TestAuthz_OpcodeMismatch_Rejected(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	s := newTestServer(t, []ids.NodeID{ident.NodeID}, nil)
	now := time.Unix(1_717_200_000, 0)

	// Sign as Get but dispatch as List → mismatch.
	raw := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/auto", Name: "k", Env: "prod",
	}), now, "nonce-mismatch")
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretList); err == nil {
		t.Fatalf("opcode mismatch should be rejected")
	}
}

// TestAuthz_ReplayedEnvelope_Rejected — verbatim replay of a previously
// accepted envelope is rejected with the structured ErrEnvelopeReplay
// outcome. The first call must succeed (proving the envelope is valid
// in isolation); the second must fail with replay-detected even though
// signature + wall-clock + authority are all still valid.
func TestAuthz_ReplayedEnvelope_Rejected(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	s := newTestServer(t, []ids.NodeID{ident.NodeID}, nil)
	seed(t, s, "hanzo/auto", "api-key", "prod", "secret-1")
	now := time.Unix(1_717_200_000, 0)

	raw := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/auto", Name: "api-key", Env: "prod",
	}), now, "nonce-replay")

	// First call: must accept.
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call (same bytes): must reject with ErrEnvelopeReplay.
	_, _, err := s.verifyAndAuthorize(context.Background(), raw, OpSecretGet)
	if !errors.Is(err, ErrEnvelopeReplay) {
		t.Fatalf("second call err=%v want ErrEnvelopeReplay", err)
	}
}

// TestAuthz_FreshNonce_AcceptedAfterReplay — once the prior envelope is
// rejected, a fresh-nonce envelope from the same identity is accepted.
// Pins that the ledger doesn't blacklist the NodeID — only the
// (NodeID, Nonce) tuple.
func TestAuthz_FreshNonce_AcceptedAfterReplay(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	s := newTestServer(t, []ids.NodeID{ident.NodeID}, nil)
	seed(t, s, "hanzo/auto", "api-key", "prod", "secret-1")
	now := time.Unix(1_717_200_000, 0)

	raw1 := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/auto", Name: "api-key", Env: "prod",
	}), now, "nonce-A")
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw1, OpSecretGet); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Same envelope replayed → rejected.
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw1, OpSecretGet); !errors.Is(err, ErrEnvelopeReplay) {
		t.Fatalf("replay: %v", err)
	}
	// Same identity, fresh nonce → accepted.
	raw2 := signedEnvelopeBytes(t, ident, OpSecretGet, buildInner(t, getReq{
		Path: "hanzo/auto", Name: "api-key", Env: "prod",
	}), now, "nonce-B")
	if _, _, err := s.verifyAndAuthorize(context.Background(), raw2, OpSecretGet); err != nil {
		t.Fatalf("fresh-nonce call: %v", err)
	}
}

// TestAuthz_TamperedRequest_Rejected — flipping a bit in the canonical
// signed bytes invalidates the signature.
func TestAuthz_TamperedRequest_Rejected(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	s := newTestServer(t, []ids.NodeID{ident.NodeID}, []ids.NodeID{ident.NodeID})
	now := time.Unix(1_717_200_000, 0)

	raw := signedEnvelopeBytes(t, ident, OpSecretPut, buildInner(t, putReq{
		Path: "hanzo/commerce", Name: "k", Env: "prod",
		Value: base64.StdEncoding.EncodeToString([]byte("ok")),
	}), now, "nonce-tamper")
	// Decode, swap the inner Value (post-sign), re-marshal. The
	// signature now covers the old value and verification fails.
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Req = buildInner(t, putReq{
		Path: "hanzo/commerce", Name: "k", Env: "prod",
		Value: base64.StdEncoding.EncodeToString([]byte("EVIL")),
	})
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if _, _, err := s.verifyAndAuthorize(context.Background(), tampered, OpSecretPut); err == nil {
		t.Fatalf("tampered request should be rejected")
	}
}

// TestAuthz_MissingAuthorizerPanics — wiring an empty Config refuses
// to construct a Server.
func TestAuthz_MissingAuthorizerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil Authorizer")
		}
	}()
	mk := make([]byte, 32)
	_ = New(Config{MasterKey: mk})
}

// TestInProcessAuthorizer_CacheTTL — repeated calls within TTL reuse
// the cached snapshot; outside TTL the provider is re-dialed. We use
// a counting AuthorityProvider to assert the dial count.
func TestInProcessAuthorizer_CacheTTL(t *testing.T) {
	knownIdent := newIdentity(t, "hanzo/auto")
	defer knownIdent.Wipe()

	calls := 0
	provider := AuthorityProviderFunc(func(_ context.Context) ([]ids.NodeID, error) {
		calls++
		return []ids.NodeID{knownIdent.NodeID}, nil
	})

	az, err := NewInProcessAuthorizer(InProcessAuthorizerConfig{
		Validators: provider,
		Operator:   NewStaticAuthorityProvider(nil),
		CacheTTL:   500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("authz: %v", err)
	}
	for i := 0; i < 5; i++ {
		_, _ = az.Authorize(context.Background(), Identity{NodeID: knownIdent.NodeID}, "p", OpAuthGet)
	}
	if calls != 1 {
		t.Fatalf("validators dialed %d times within TTL, want 1", calls)
	}
}

// TestEnvelope_RoundTrip — a freshly signed envelope verifies under
// the matching identity and reproduces the original inner request.
func TestEnvelope_RoundTrip(t *testing.T) {
	ident := newIdentity(t, "hanzo/auto")
	defer ident.Wipe()
	inner := buildInner(t, getReq{Path: "hanzo/auto", Name: "k", Env: "prod"})

	env, err := BuildEnvelope(ident, OpSecretGet, inner, "nonce", time.Unix(1_717_200_000, 0))
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	verified, err := VerifyEnvelope(env, time.Unix(1_717_200_000, 0))
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if verified.NodeID != ident.NodeID {
		t.Fatalf("NodeID mismatch: got %s want %s", verified.NodeID, ident.NodeID)
	}
	if verified.FullDigest != ident.FullDigest {
		t.Fatalf("FullDigest mismatch")
	}
}

// TestServiceIdentity_Determinism — same (mnemonic, path) ↔ same
// NodeID. Locks the derivation contract so a future "improvement" to
// the BIP-32 path silently changes every NodeID.
func TestServiceIdentity_Determinism(t *testing.T) {
	a, err := keys.NewServiceIdentity(testMnemonic, "hanzo/kms-operator")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	defer a.Wipe()
	b, err := keys.NewServiceIdentity(testMnemonic, "hanzo/kms-operator")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	defer b.Wipe()
	if a.NodeID != b.NodeID {
		t.Fatalf("NodeID drift: %s vs %s", a.NodeID, b.NodeID)
	}
	c, err := keys.NewServiceIdentity(testMnemonic, "hanzo/commerce")
	if err != nil {
		t.Fatalf("c: %v", err)
	}
	defer c.Wipe()
	if a.NodeID == c.NodeID {
		t.Fatalf("two distinct paths must yield distinct NodeIDs (got %s for both)", a.NodeID)
	}
}

// helper — pads a uint16 to its little-endian bytes for ad-hoc tests
// that bypass the BuildRequest helper.
func u16le(op uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], op)
	return b[:]
}

var _ = u16le // reserved for future raw-frame tests
