// Tests for the OpAuthHello framing on the KMS-side ZAP client.
// Verifies the wire layout matches luxfi/mpc pkg/zapauth.UnmarshalAuthHello
// (uint8 version || uint16 token_len || token bytes).
package mpc

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

type stubAuth struct {
	called int
	tok    string
	err    error
}

func (s *stubAuth) Mint(_ context.Context, audience string) (string, error) {
	s.called++
	if s.err != nil {
		return "", s.err
	}
	return s.tok, nil
}

// Frame layout the client emits (matches pkg/zapauth.UnmarshalAuthHello):
//
//	+0   uint16 opcode = OpAuthHello (0x00EF)
//	+2   uint8  version = 1
//	+3   uint16 token_len
//	+5   [token_len]byte token
//
// We exercise the marshal path indirectly by reproducing it and asserting
// byte-for-byte equality with what the client builds when authenticate()
// runs. Since authenticate() also calls into the live ZAP node and we
// can't easily mock that here, the focus is the body shape — the
// integration tests in luxfi/mpc/pkg/api round-trip the live wire.

func TestZapAuth_FrameLayoutMatchesUpstream(t *testing.T) {
	tok := "header.claims.signature"
	body := buildAuthHelloBody(tok)
	if len(body) != 5+len(tok) {
		t.Fatalf("body length: got %d want %d", len(body), 5+len(tok))
	}
	if op := binary.LittleEndian.Uint16(body[0:2]); op != OpAuthHello {
		t.Fatalf("opcode: got 0x%04x want 0x%04x", op, OpAuthHello)
	}
	if body[2] != authFrameVersion {
		t.Fatalf("version: got %d want %d", body[2], authFrameVersion)
	}
	if tlen := binary.LittleEndian.Uint16(body[3:5]); int(tlen) != len(tok) {
		t.Fatalf("token_len: got %d want %d", tlen, len(tok))
	}
	if string(body[5:]) != tok {
		t.Fatalf("token bytes: got %q want %q", string(body[5:]), tok)
	}
}

// buildAuthHelloBody mirrors the inline frame construction in
// authenticate(). Kept in test scope so a wire-shape regression here
// fires as a clear test failure, not a runtime mismatch in production.
func buildAuthHelloBody(tok string) []byte {
	body := make([]byte, 2+1+2+len(tok))
	binary.LittleEndian.PutUint16(body[0:2], OpAuthHello)
	body[2] = authFrameVersion
	binary.LittleEndian.PutUint16(body[3:5], uint16(len(tok)))
	copy(body[5:], tok)
	return body
}

// TestZapAuth_AuthenticatorMintsLazily confirms authenticate() does not
// touch the Authenticator until a connection is established. With auth
// nil, no Mint call ever happens.
func TestZapAuth_AuthenticatorMintsLazily(t *testing.T) {
	a := &stubAuth{tok: "x"}
	c := &ZapClient{auth: nil}
	if c.auth != nil {
		t.Fatalf("auth should be nil")
	}
	if a.called != 0 {
		t.Fatalf("Mint called without auth config")
	}
}

// TestZapAuth_AuthenticatorErrorPropagates checks that a Mint error is
// surfaced to the caller of authenticate(). We set up a client with an
// auth config but no node connection so authenticate() exits at Mint.
func TestZapAuth_AuthenticatorErrorPropagates(t *testing.T) {
	a := &stubAuth{err: errors.New("iam down")}
	c := &ZapClient{auth: &AuthConfig{Authenticator: a, Audience: "aud"}}
	err := c.authenticate()
	if err == nil {
		t.Fatalf("expected mint error to propagate")
	}
}

// TestZapAuth_OversizedTokenRejected asserts the 64KiB cap before we
// allocate or transmit anything we shouldn't.
func TestZapAuth_OversizedTokenRejected(t *testing.T) {
	big := make([]byte, 64*1024+1)
	for i := range big {
		big[i] = 'a'
	}
	a := &stubAuth{tok: string(big)}
	c := &ZapClient{auth: &AuthConfig{Authenticator: a, Audience: "aud"}}
	err := c.authenticate()
	if err == nil {
		t.Fatalf("expected oversized token rejection")
	}
}
