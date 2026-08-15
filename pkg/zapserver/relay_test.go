// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// relay_test.go — an attacker in the middle of the credential leg.
//
// Key agreement alone says a channel is private, not who is on the other
// end of it. So put someone in the middle who agrees keys with both
// sides: it answers the caller's ClientHello with keys of its own, and
// separately agrees keys with the real KMS. It then holds both session
// keys, reads everything the caller sends, and can forward a request
// verbatim — signature and all — to the KMS. The caller's ML-DSA
// signature does not help by itself: the relay never has to forge it,
// only to carry it.
//
// What stops it is that the request names the channel it was written
// for. The caller's envelope names the channel it agreed with the relay;
// the KMS checks it against the channel it agreed with the relay; the
// two are different, and the KMS declines. The relay cannot re-sign the
// envelope for its own channel, and it cannot make its channel produce
// the caller's binding without the caller's keys.
//
// The caller here is the shipping zapclient and the KMS is the shipping
// zapserver — the only test code is the attacker.

package zapserver

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	kmszap "github.com/luxfi/kms/pkg/zap"
	"github.com/luxfi/kms/pkg/zapclient"
	"github.com/luxfi/zap"
)

// relay sits between a caller and the real KMS holding both session
// keys. toCaller is the session the caller believes is the KMS;
// toKMS is the session the KMS believes is the caller.
type relay struct {
	node    *zap.Node
	kmsPeer string
	toKMS   *kmszap.Session

	// The rest is touched by both the test and the handler goroutines.
	mu       sync.Mutex
	toCaller *kmszap.Session
	// read records the plaintext of every request the caller sent, to
	// show the relay really is reading the traffic and not merely
	// shuttling bytes it cannot see.
	read [][]byte
	// rewrite makes the relay put its OWN channel's name into the
	// caller's envelope before forwarding, rather than carrying it
	// unchanged.
	rewrite bool
}

func (r *relay) setCaller(s *kmszap.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.toCaller = s
}

func (r *relay) caller() *kmszap.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.toCaller
}

func (r *relay) setRewrite() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rewrite = true
}

func (r *relay) rewriting() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rewrite
}

func (r *relay) record(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.read = append(r.read, append([]byte(nil), b...))
}

func (r *relay) seen() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.read...)
}

// newRelay stands up an attacker listening on its own port and agrees
// keys with the real KMS at kmsAddr. The caller is pointed at addr.
func newRelay(t *testing.T, kmsAddr string) (r *relay, addr string) {
	t.Helper()
	port := freePort(t)
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      "relay-" + strconv.Itoa(port),
		ServiceType: "_kms._tcp",
		Port:        port,
		NoDiscovery: true,
	})
	if err := n.Start(); err != nil {
		t.Fatalf("relay node start: %v", err)
	}
	t.Cleanup(func() { n.Stop() })
	r = &relay{node: n}

	// The attacker's own key agreement with the real KMS, using the
	// same handshake any caller would run.
	if err := n.ConnectDirect(kmsAddr); err != nil {
		t.Fatalf("relay connect KMS: %v", err)
	}
	for _, pid := range n.Peers() {
		r.kmsPeer = pid
		break
	}
	if r.kmsPeer == "" {
		t.Fatal("relay resolved no KMS peer")
	}
	state, hello, err := kmszap.NewClient(kmszap.CapMLKEM768)
	if err != nil {
		t.Fatalf("relay ClientHello: %v", err)
	}
	reply := r.callKMS(t, kmszap.OpClientHello, hello)
	result, err := state.ClientFinish(reply)
	if err != nil {
		t.Fatalf("relay ClientFinish: %v", err)
	}
	if r.toKMS, err = kmszap.NewSession(result); err != nil {
		t.Fatalf("relay session to KMS: %v", err)
	}

	// Answer the caller's key agreement as if we were the KMS.
	n.Handle(kmszap.OpClientHello, func(_ context.Context, _ string, msg *zap.Message) (*zap.Message, error) {
		hello := payloadOf(msg)[2:]
		replyWire, res, err := kmszap.ServerRespond(kmszap.CapMLKEM768, hello)
		if err != nil {
			return respond(statusError, errJSON("relay hello")), nil
		}
		sess, err := kmszap.NewSession(res)
		if err != nil {
			return respond(statusError, errJSON("relay session")), nil
		}
		r.setCaller(sess)
		return respond(statusOK, replyWire), nil
	})

	// Carry a secret request to the KMS unchanged, re-sealed for the
	// channel the attacker agreed with it.
	n.Handle(OpSecretGet, func(_ context.Context, _ string, msg *zap.Message) (*zap.Message, error) {
		sealed := payloadOf(msg)[2:]
		plain, err := r.caller().Open(kmszap.DirClientToServer, sealed)
		if err != nil {
			return respond(statusError, errJSON("relay open")), nil
		}
		r.record(plain)
		if r.rewriting() {
			var env Envelope
			if err := json.Unmarshal(plain, &env); err != nil {
				return respond(statusError, errJSON("relay parse")), nil
			}
			env.Bind = r.toKMS.Bind()
			if plain, err = json.Marshal(&env); err != nil {
				return respond(statusError, errJSON("relay remarshal")), nil
			}
		}
		onward, err := r.toKMS.Seal(kmszap.DirClientToServer, plain)
		if err != nil {
			return respond(statusError, errJSON("relay seal")), nil
		}
		raw := r.callKMSRaw(t, OpSecretGet, onward)
		status, body := raw[0], raw[1:]
		body, err = r.toKMS.Open(kmszap.DirServerToClient, body)
		if err != nil {
			// The KMS refused before a session reply was framed.
			return respond(status, body), nil
		}
		back, err := r.caller().Seal(kmszap.DirServerToClient, body)
		if err != nil {
			return respond(statusError, errJSON("relay reseal")), nil
		}
		return respond(status, back), nil
	})

	return r, "127.0.0.1:" + strconv.Itoa(port)
}

// callKMS sends one op to the real KMS and returns the body after the
// status byte, failing the test on a non-OK status.
func (r *relay) callKMS(t *testing.T, op uint16, body []byte) []byte {
	t.Helper()
	raw := r.callKMSRaw(t, op, body)
	if raw[0] != statusOK {
		t.Fatalf("relay: KMS status=0x%02X body=%s", raw[0], string(raw[1:]))
	}
	return raw[1:]
}

// callKMSRaw sends one op and returns status||body verbatim.
func (r *relay) callKMSRaw(t *testing.T, op uint16, body []byte) []byte {
	t.Helper()
	payload := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(payload[:2], op)
	copy(payload[2:], body)
	b := zap.NewBuilder(len(payload) + 32)
	b.WriteBytes(payload)
	msg, err := zap.Parse(b.FinishWithFlags(op << 8))
	if err != nil {
		t.Fatalf("relay build message: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := r.node.Call(ctx, r.kmsPeer, msg)
	if err != nil {
		t.Fatalf("relay call KMS: %v", err)
	}
	raw := payloadOf(resp)
	if len(raw) < 1 {
		t.Fatal("relay: empty reply from KMS")
	}
	return raw
}

// payloadOf pulls the body out of a ZAP message the same way the server
// and client do.
func payloadOf(msg *zap.Message) []byte {
	if raw := msg.Root().Bytes(0); len(raw) > 0 {
		return raw
	}
	b := msg.Bytes()
	if len(b) > zap.HeaderSize {
		return b[zap.HeaderSize:]
	}
	return nil
}

// A caller that reaches the real KMS gets its secret. This is the
// control: it fixes that the harness, the identity, the authorizer and
// the store all work, so the refusal below can only be the relay.
func TestCallerReachingTheKMSGetsTheSecret(t *testing.T) {
	addr, _ := bootServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ident, hdr := newE2EIdentity(t, "ats/direct")
	defer ident.Wipe()
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "caller-direct",
		PeerAddr:       addr,
		DefaultPath:    "ats",
		IdentityHeader: hdr,
		Signer:         ident,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	value, err := c.Get(ctx, "settlement-key", "dev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if value != "hunter2" {
		t.Fatalf("got %q want %q", value, "hunter2")
	}
}

// The same caller, same identity, same KMS — with someone in the middle
// who agreed keys with both. The KMS declines, and the secret stays
// where it is.
func TestRelayedRequestIsRefused(t *testing.T) {
	kmsAddr, _ := bootServer(t)
	r, relayAddr := newRelay(t, kmsAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ident, hdr := newE2EIdentity(t, "ats/relayed")
	defer ident.Wipe()
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "caller-relayed",
		PeerAddr:       relayAddr,
		DefaultPath:    "ats",
		IdentityHeader: hdr,
		Signer:         ident,
	})
	if err != nil {
		t.Fatalf("Dial through relay: %v", err)
	}
	defer c.Close()

	value, err := c.Get(ctx, "settlement-key", "dev")
	if err == nil {
		t.Fatalf("the KMS answered a relayed request with %q", value)
	}
	if value != "" {
		t.Fatalf("a value came back through the relay: %q", value)
	}

	// The attacker really was in the middle: it read the caller's
	// request in the clear. What it could not do is present it as its
	// own.
	if len(r.seen()) == 0 {
		t.Fatal("the relay never saw the request — it was not in the middle, so this proves nothing")
	}
	if !strings.Contains(string(r.seen()[0]), "settlement-key") {
		t.Fatalf("the relay could not read the request it forwarded: %q", string(r.seen()[0]))
	}

	// And the relay's own channel to the KMS is sound — the refusal is
	// about who the request was addressed to, not a broken connection.
	if r.toKMS == nil || r.caller() == nil {
		t.Fatal("the relay did not agree keys with both sides")
	}
}

// A cleverer relay edits the caller's envelope to name its own channel
// instead of carrying the caller's. That is the obvious move, and it
// fails for the obvious reason: the name is inside what the caller
// signed, so changing it breaks the signature, and the relay has no key
// to make a new one.
func TestRelayRewritingTheChannelIsRefused(t *testing.T) {
	kmsAddr, _ := bootServer(t)
	r, relayAddr := newRelay(t, kmsAddr)
	r.setRewrite()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ident, hdr := newE2EIdentity(t, "ats/relay-rewrite")
	defer ident.Wipe()
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "caller-relay-rewrite",
		PeerAddr:       relayAddr,
		DefaultPath:    "ats",
		IdentityHeader: hdr,
		Signer:         ident,
	})
	if err != nil {
		t.Fatalf("Dial through relay: %v", err)
	}
	defer c.Close()

	value, err := c.Get(ctx, "settlement-key", "dev")
	if err == nil {
		t.Fatalf("the KMS answered a rewritten request with %q", value)
	}
	if value != "" {
		t.Fatalf("a value came back through the relay: %q", value)
	}
	if len(r.seen()) == 0 {
		t.Fatal("the relay never saw the request — it was not in the middle, so this proves nothing")
	}
}

// The two channels really do carry different names. If they did not, the
// check above would pass for the wrong reason.
func TestTheTwoChannelsHaveDifferentBindings(t *testing.T) {
	kmsAddr, _ := bootServer(t)
	r, relayAddr := newRelay(t, kmsAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ident, hdr := newE2EIdentity(t, "ats/two-channels")
	defer ident.Wipe()
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "caller-two-channels",
		PeerAddr:       relayAddr,
		DefaultPath:    "ats",
		IdentityHeader: hdr,
		Signer:         ident,
	})
	if err != nil {
		t.Fatalf("Dial through relay: %v", err)
	}
	defer c.Close()

	if r.caller() == nil || r.toKMS == nil {
		t.Fatal("the relay did not agree keys with both sides")
	}
	if string(r.caller().Bind()) == string(r.toKMS.Bind()) {
		t.Fatal("both channels produced the same binding — a relay would be invisible")
	}
}
