// Session-layer framing helpers built on top of the handshake module.
//
// A completed handshake yields a 32-byte AES-256-GCM key. Every secret-
// carrying payload is sealed with that key before it crosses the wire and
// opened on the receiver. The ZAP frame envelope (opcode, message header)
// stays in clear — only the payload bytes the application supplies are
// confidential.
//
// Nonces are 12 bytes (GCM standard): 4-byte direction tag || 8-byte
// big-endian monotonic counter. The direction tag prevents a sealed frame
// the server emits from being re-injected on the client→server channel
// and vice versa. The counter is enforced never to wrap inside a single
// session; the underlying TCP stream from luxfi/zap delivers frames
// strictly in-order so peer counters stay in lockstep without any
// sequence number on the wire.
//
// Wire layout for a sealed payload:
//
//	+0   ciphertext || GCM tag
//
// A replayed frame opens with a nonce mismatch (the receiver counter has
// advanced) and the AEAD rejects it. A tampered frame fails the GCM tag
// the same way. The handshake transcript hash binds the session key to
// both hello frames, so a captured ClientHello cannot resume into a
// previously observed session.
package zap

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
)

// Direction tags mix into the nonce so a frame the server seals is
// undecryptable on the server's own opener and vice versa.
const (
	DirClientToServer uint32 = 0x43325300 // "C2S\x00"
	DirServerToClient uint32 = 0x53324300 // "S2C\x00"
)

// Session is the per-connection AEAD state, plus the binding that names
// the channel. Hybrid records whether ML-KEM-768 ran, for
// operator-visible logging.
type Session struct {
	aead    cipher.AEAD
	bind    []byte
	hybrid  bool
	sendCtr atomic.Uint64
	recvCtr atomic.Uint64
}

// NewSession turns a completed handshake into a Session ready to seal
// and open frames.
//
// It takes the whole result rather than the key alone so that a session
// always carries the binding derived alongside its key. There is no
// other constructor, and therefore no session whose binding belongs to
// some other exchange.
func NewSession(r *HandshakeResult) (*Session, error) {
	if r == nil {
		return nil, errors.New("zap/session: handshake result is nil")
	}
	if len(r.Bind) != BindSize {
		return nil, fmt.Errorf("zap/session: binding must be %d bytes, got %d", BindSize, len(r.Bind))
	}
	a, err := SessionAEAD(r.SessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{aead: a, bind: r.Bind, hybrid: r.Hybrid}, nil
}

// Bind returns the binding a request must carry to be honoured on this
// session. Both endpoints compute the same 32 bytes; nobody else can.
func (s *Session) Bind() []byte { return s.bind }

// Hybrid reports whether the session was negotiated with ML-KEM-768
// active. Operators log this once per session at INFO.
func (s *Session) Hybrid() bool { return s.hybrid }

// Seal encrypts plaintext payload bytes for the given direction. The
// returned slice is the GCM ciphertext+tag (no length prefix).
//
// The send counter advances on every call; callers must use the same
// Session instance for every frame they send. Concurrent Seal is safe.
func (s *Session) Seal(direction uint32, plaintext []byte) ([]byte, error) {
	ctr := s.sendCtr.Add(1)
	if ctr == 0 {
		return nil, errors.New("zap/session: send counter overflow")
	}
	nonce := makeNonce(direction, ctr)
	return s.aead.Seal(nil, nonce, plaintext, nil), nil
}

// Open verifies and decrypts a sealed frame. The receive counter
// advances on every call; an out-of-order or replayed frame fails GCM
// and the counter is rolled back so the channel stays usable.
func (s *Session) Open(direction uint32, sealed []byte) ([]byte, error) {
	if len(sealed) < s.aead.Overhead() {
		return nil, errors.New("zap/session: sealed frame too short")
	}
	ctr := s.recvCtr.Add(1)
	if ctr == 0 {
		return nil, errors.New("zap/session: recv counter overflow")
	}
	nonce := makeNonce(direction, ctr)
	pt, err := s.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		// Roll the counter back so a benign retry can succeed; a true
		// attacker still cannot forge under the AEAD key.
		s.recvCtr.Add(^uint64(0))
		return nil, fmt.Errorf("zap/session: aead open: %w", err)
	}
	return pt, nil
}

// makeNonce builds a 12-byte GCM nonce: 4 bytes of direction tag || 8
// bytes of big-endian counter. Big-endian on the counter makes the nonce
// monotonically increase as a byte string, which is the documented GCM
// safe pattern for monotonic counters.
func makeNonce(direction uint32, counter uint64) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint32(out[0:4], direction)
	binary.BigEndian.PutUint64(out[4:12], counter)
	return out
}
