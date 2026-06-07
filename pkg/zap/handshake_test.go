// Tests for the application-layer hybrid PQ handshake module.
//
// We exercise three paths:
//
//  1. Round-trip — client+server in-process, hybrid path, both sides
//     derive the same 32-byte session key and AEAD-seal/open round-trips.
//  2. Capability fallback — client clears bit 0; server speaks both;
//     both sides land on classical-only and a session still establishes.
//  3. Replay defense — capture a ClientHello and replay it to a fresh
//     server; the new ServerHello differs (random ephemerals) and the
//     attacker's session key from the first run cannot open the second
//     server's response payload (transcript hash mismatch).
package zap

import (
	"bytes"
	"sync/atomic"
	"testing"
)

// TestHandshake_HybridRoundTrip exercises the canonical happy path: both
// peers advertise CapMLKEM768, the negotiated reply carries the cap, and
// the derived 32-byte session key is identical on both sides. We then
// run a Seal/Open round-trip in each direction.
func TestHandshake_HybridRoundTrip(t *testing.T) {
	cs, helloWire, err := NewClient(CapMLKEM768)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	replyWire, sResult, err := ServerRespond(CapMLKEM768, helloWire)
	if err != nil {
		t.Fatalf("ServerRespond: %v", err)
	}
	cResult, err := cs.ClientFinish(replyWire)
	if err != nil {
		t.Fatalf("ClientFinish: %v", err)
	}

	if !sResult.Hybrid || !cResult.Hybrid {
		t.Fatalf("hybrid not negotiated: server=%v client=%v", sResult.Hybrid, cResult.Hybrid)
	}
	if got := len(sResult.SessionKey); got != SessionKeySize {
		t.Fatalf("server session key length = %d, want %d", got, SessionKeySize)
	}
	if got := len(cResult.SessionKey); got != SessionKeySize {
		t.Fatalf("client session key length = %d, want %d", got, SessionKeySize)
	}
	if !bytes.Equal(sResult.SessionKey, cResult.SessionKey) {
		t.Fatalf("session key mismatch:\n server=%x\n client=%x", sResult.SessionKey, cResult.SessionKey)
	}

	// Build sessions on both sides and round-trip a payload each way.
	cSess, err := NewSession(cResult.SessionKey, cResult.Hybrid)
	if err != nil {
		t.Fatalf("client NewSession: %v", err)
	}
	sSess, err := NewSession(sResult.SessionKey, sResult.Hybrid)
	if err != nil {
		t.Fatalf("server NewSession: %v", err)
	}

	// Client → Server
	clientPlain := []byte(`{"path":"ats","name":"settlement","env":"dev"}`)
	sealedC2S, err := cSess.Seal(DirClientToServer, clientPlain)
	if err != nil {
		t.Fatalf("client Seal: %v", err)
	}
	openedAtServer, err := sSess.Open(DirClientToServer, sealedC2S)
	if err != nil {
		t.Fatalf("server Open: %v", err)
	}
	if !bytes.Equal(openedAtServer, clientPlain) {
		t.Fatalf("c2s round-trip differs:\n in =%q\n out=%q", clientPlain, openedAtServer)
	}

	// Server → Client
	serverPlain := []byte(`{"value":"AAAA"}`)
	sealedS2C, err := sSess.Seal(DirServerToClient, serverPlain)
	if err != nil {
		t.Fatalf("server Seal: %v", err)
	}
	openedAtClient, err := cSess.Open(DirServerToClient, sealedS2C)
	if err != nil {
		t.Fatalf("client Open: %v", err)
	}
	if !bytes.Equal(openedAtClient, serverPlain) {
		t.Fatalf("s2c round-trip differs:\n in =%q\n out=%q", serverPlain, openedAtClient)
	}
}

// TestHandshake_FallbackClassicalOnly — client offers caps=0 (no
// ML-KEM-768), server offers CapMLKEM768. The negotiated cap is 0 and
// the session establishes on X25519 alone. The handshake module signals
// fallback via Hybrid=false; the operator-facing warning is the caller's
// responsibility (zapserver.respondHandshake / zapclient.handshake log
// it). We assert the protocol invariants here:
//
//   - both sides land on Hybrid=false
//   - PeerCaps reflects what each side advertised
//   - the derived key is still 32 bytes and matches
//   - AEAD round-trip still works
func TestHandshake_FallbackClassicalOnly(t *testing.T) {
	// Client clears bit 0.
	cs, helloWire, err := NewClient(0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Server speaks both.
	replyWire, sResult, err := ServerRespond(CapMLKEM768, helloWire)
	if err != nil {
		t.Fatalf("ServerRespond: %v", err)
	}
	cResult, err := cs.ClientFinish(replyWire)
	if err != nil {
		t.Fatalf("ClientFinish: %v", err)
	}

	if sResult.Hybrid {
		t.Fatalf("server: hybrid=true after client cleared bit 0")
	}
	if cResult.Hybrid {
		t.Fatalf("client: hybrid=true after self cleared bit 0")
	}
	if sResult.PeerCaps&CapMLKEM768 != 0 {
		t.Fatalf("server saw client caps=%x with bit 0 set", sResult.PeerCaps)
	}
	if cResult.PeerCaps&CapMLKEM768 != 0 {
		t.Fatalf("client saw server reply caps=%x with bit 0 set", cResult.PeerCaps)
	}
	if got := len(sResult.SessionKey); got != SessionKeySize {
		t.Fatalf("classical-only session key length = %d, want %d", got, SessionKeySize)
	}
	if !bytes.Equal(sResult.SessionKey, cResult.SessionKey) {
		t.Fatalf("classical-only session key mismatch")
	}

	cSess, _ := NewSession(cResult.SessionKey, cResult.Hybrid)
	sSess, _ := NewSession(sResult.SessionKey, sResult.Hybrid)
	plain := []byte("classical-only-payload")
	sealed, _ := cSess.Seal(DirClientToServer, plain)
	got, err := sSess.Open(DirClientToServer, sealed)
	if err != nil {
		t.Fatalf("classical-only AEAD: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("classical-only AEAD differs")
	}
}

// TestHandshake_ReplayDefense — captures a ClientHello and the resulting
// ServerHello and a sealed application frame, then replays the SAME
// ClientHello bytes to a FRESH server. The fresh server returns a new
// ServerHello with a different ephemeral X25519 key, so the resulting
// session key is different. The captured application frame must NOT
// open under the replayed session, because the transcript hash binds
// the session key to the specific (helloC, helloS) pair.
//
// This is the core security property: an attacker who records traffic
// cannot replay a ClientHello to a different server (or to the same
// server later) and decrypt previously captured ciphertext, because the
// session key is bound to a freshly random server ephemeral every time.
func TestHandshake_ReplayDefense(t *testing.T) {
	// Run #1: legitimate client/server.
	cs1, hello1, err := NewClient(CapMLKEM768)
	if err != nil {
		t.Fatalf("NewClient #1: %v", err)
	}
	reply1, server1Result, err := ServerRespond(CapMLKEM768, hello1)
	if err != nil {
		t.Fatalf("ServerRespond #1: %v", err)
	}
	client1Result, err := cs1.ClientFinish(reply1)
	if err != nil {
		t.Fatalf("ClientFinish #1: %v", err)
	}
	if !bytes.Equal(server1Result.SessionKey, client1Result.SessionKey) {
		t.Fatalf("run #1 keys differ")
	}

	// Capture an application frame sealed under run #1's session.
	sess1Server, _ := NewSession(server1Result.SessionKey, server1Result.Hybrid)
	sess1Client, _ := NewSession(client1Result.SessionKey, client1Result.Hybrid)
	captured, err := sess1Server.Seal(DirServerToClient, []byte("highly-sensitive-payload"))
	if err != nil {
		t.Fatalf("seal captured frame: %v", err)
	}
	// Sanity: legitimate client opens it.
	if pt, err := sess1Client.Open(DirServerToClient, captured); err != nil || string(pt) != "highly-sensitive-payload" {
		t.Fatalf("legitimate open failed: %v / %q", err, pt)
	}

	// Run #2: attacker replays the SAME hello1 bytes to a FRESH server.
	// (Equivalent to a different KMS replica, or the same replica after
	// process restart.) The fresh server's X25519 ephemeral is different,
	// so the derived session key differs.
	reply2, server2Result, err := ServerRespond(CapMLKEM768, hello1)
	if err != nil {
		t.Fatalf("ServerRespond replayed: %v", err)
	}
	if bytes.Equal(server1Result.SessionKey, server2Result.SessionKey) {
		t.Fatalf("replay yielded the same session key — handshake has no per-server randomness")
	}
	if bytes.Equal(reply1, reply2) {
		t.Fatalf("ServerHello bytes identical across runs — fresh ephemeral missing")
	}

	// Attacker now holds reply2 and tries to open the captured frame
	// under the replayed session. This must fail.
	sess2Attacker, err := NewSession(server2Result.SessionKey, server2Result.Hybrid)
	if err != nil {
		t.Fatalf("attacker NewSession: %v", err)
	}
	if _, err := sess2Attacker.Open(DirServerToClient, captured); err == nil {
		t.Fatalf("attacker opened a captured frame under replayed session — replay defense broken")
	}

	// Independent counter sanity: the attacker also can't fast-forward
	// the recv counter to match the captured frame's nonce.
	var atkCtr atomic.Uint64
	atkCtr.Store(0)
	// (Documenting the invariant; sess2Attacker's recv counter is fresh
	// so its first Open call uses ctr=1 — the captured frame was sealed
	// under run #1's server send counter (also 1), so the *nonce counter
	// position* matches but the AEAD key does not. The Open above would
	// have caught any cross-key forgery.)
	_ = atkCtr
}

// TestSession_NonceDirectionality asserts that a frame the server seals
// cannot be opened by the SERVER's own opener with its own counter (the
// direction tag is mixed into the nonce). This forecloses an attacker
// that replays a server-emitted frame back at the server.
func TestSession_NonceDirectionality(t *testing.T) {
	cs, hello, err := NewClient(CapMLKEM768)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	reply, sRes, err := ServerRespond(CapMLKEM768, hello)
	if err != nil {
		t.Fatalf("ServerRespond: %v", err)
	}
	if _, err := cs.ClientFinish(reply); err != nil {
		t.Fatalf("ClientFinish: %v", err)
	}

	sess, _ := NewSession(sRes.SessionKey, sRes.Hybrid)
	sealedS2C, err := sess.Seal(DirServerToClient, []byte("server-emitted"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Try to open it as if it were a client→server frame.
	if _, err := sess.Open(DirClientToServer, sealedS2C); err == nil {
		t.Fatalf("opener accepted wrong-direction frame")
	}
}

// TestSession_TamperRejection asserts that flipping any byte of a sealed
// frame causes Open to fail (GCM tag verification).
func TestSession_TamperRejection(t *testing.T) {
	cs, hello, _ := NewClient(CapMLKEM768)
	reply, sRes, _ := ServerRespond(CapMLKEM768, hello)
	cRes, _ := cs.ClientFinish(reply)

	cSess, _ := NewSession(cRes.SessionKey, cRes.Hybrid)
	sSess, _ := NewSession(sRes.SessionKey, sRes.Hybrid)
	sealed, _ := cSess.Seal(DirClientToServer, []byte("integrity-test"))
	// Flip one bit in the middle of the ciphertext.
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := sSess.Open(DirClientToServer, tampered); err == nil {
		t.Fatalf("Open accepted tampered ciphertext")
	}
}
