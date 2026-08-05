// Round-trip tests for the ZAP client's error handling.
//
// The security claim under test: a server ERROR body must never be
// reported to the caller as success. The server frames failures as
// {"error": "..."} under the same opcode it was asked for, so neither the
// opcode check nor the JSON decode can catch it — Go ignores unknown
// fields, so an error body decodes cleanly into every success struct.
//
// Reshare is the worst case and is tested first: its ONLY signal is the
// error return, so without the check a refused reshare reports success
// and the operator believes the share set moved when it did not.
package mpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/zap"

	kmszap "github.com/luxfi/kms/pkg/zap"
)

// errServer stands up a zap.Node that speaks the real protocol —
// handshake, then auth — and answers every KMS opcode with the server's
// error envelope, sealed exactly as pkg/api/zap_kms_server.go seals it.
func errServer(t *testing.T, msg string) string {
	t.Helper()
	return serveWith(t, func(op uint16, _ []byte) []byte {
		b, _ := json.Marshal(map[string]string{"error": msg})
		return b
	})
}

// serveWith runs a minimal MPC-side server. reply is called with the
// OPENED payload and returns the plaintext body to seal back.
func serveWith(t *testing.T, reply func(op uint16, payload []byte) []byte) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      "err-server",
		ServiceType: "_lux-kms._tcp",
		Port:        port,
		NoDiscovery: true,
	})

	var mu sync.Mutex
	sessions := map[string]*kmszap.Session{}

	frame := func(op uint16, body []byte) (*zap.Message, error) {
		out := make([]byte, 2+len(body))
		binary.LittleEndian.PutUint16(out[0:2], op)
		copy(out[2:], body)
		b := zap.NewBuilder(len(out) + 64)
		b.WriteBytes(out)
		return zap.Parse(b.Finish())
	}

	handler := func(_ context.Context, from string, m *zap.Message) (*zap.Message, error) {
		raw := m.Bytes()
		if len(raw) < zap.HeaderSize+2 {
			return nil, errors.New("short request")
		}
		op := binary.LittleEndian.Uint16(raw[zap.HeaderSize : zap.HeaderSize+2])
		body := raw[zap.HeaderSize+2:]

		if op == kmszap.OpClientHello {
			replyWire, res, err := kmszap.ServerRespond(kmszap.CapMLKEM768, body)
			if err != nil {
				return nil, err
			}
			sess, err := kmszap.NewSession(res.SessionKey, res.Hybrid)
			if err != nil {
				return nil, err
			}
			mu.Lock()
			sessions[from] = sess
			mu.Unlock()
			return frame(kmszap.OpServerHello, replyWire)
		}

		mu.Lock()
		sess := sessions[from]
		mu.Unlock()
		if sess == nil {
			return frame(op, []byte(`{"error":"handshake required"}`))
		}
		payload, err := sess.Open(kmszap.DirClientToServer, body)
		if err != nil {
			return frame(op, []byte(`{"error":"session decrypt failed"}`))
		}

		var out []byte
		if op == kmszap.OpAuth {
			out = []byte(`{"subject":"lux/lux-kms","owner":"lux"}`)
		} else {
			out = reply(op, payload)
		}
		sealed, err := sess.Seal(kmszap.DirServerToClient, out)
		if err != nil {
			return nil, err
		}
		return frame(op, sealed)
	}

	node.Handle(0, handler)
	for _, op := range []uint16{
		kmszap.OpClientHello, kmszap.OpAuth,
		OpStatus, OpKeygen, OpSign, OpReshare, OpWallet, OpDecrypt,
	} {
		node.Handle(op, handler)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("start err-server: %v", err)
	}
	t.Cleanup(node.Stop)
	time.Sleep(50 * time.Millisecond)
	return addr
}

// testToken is the IAM credential the client presents.
func testToken(context.Context) (string, error) { return "test-iam-token", nil }

// dial connects a fresh client. Each gets a unique node ID: luxfi/zap
// rejects a second connection claiming a NodeID that is already connected,
// so reusing one across subtests would fail on that, not on anything the
// test means to assert.
func dial(t *testing.T, addr string) *ZapClient {
	t.Helper()
	c, err := NewZapClient(fmt.Sprintf("test-client-%s", t.Name()), addr, testToken)
	if err != nil {
		t.Fatalf("NewZapClient: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// TestReshareRefusedIsError is the load-bearing case. Reshare returns only
// an error; a server refusal that decodes as success is invisible.
func TestReshareRefusedIsError(t *testing.T) {
	c := dial(t, errServer(t, "reshare refused: threshold below quorum"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := c.Reshare(ctx, "wallet-1", ReshareRequest{NewThreshold: 1})
	if err == nil {
		t.Fatal("SECURITY: refused reshare reported SUCCESS — server error body was swallowed")
	}
	var we *WireError
	if !errors.As(err, &we) {
		t.Fatalf("want *WireError, got %T: %v", err, err)
	}
	if we.Op != OpReshare {
		t.Errorf("WireError.Op: want 0x%04x got 0x%04x", OpReshare, we.Op)
	}
	if we.Message != "reshare refused: threshold below quorum" {
		t.Errorf("WireError.Message: got %q", we.Message)
	}
	t.Logf("refused reshare correctly surfaced: %v", err)
}

// TestErrorBodyNeverDecodesAsSuccess covers every opcode whose result is a
// struct. Without the error check each of these returns a non-nil,
// zero-valued result and a nil error.
func TestErrorBodyNeverDecodesAsSuccess(t *testing.T) {
	addr := errServer(t, "backend unavailable")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("Sign", func(t *testing.T) {
		c := dial(t, addr)
		res, err := c.Sign(ctx, SignRequest{WalletID: "w", Message: []byte("m")})
		if err == nil {
			t.Fatalf("SECURITY: error body decoded as SignResult %+v", res)
		}
		if res != nil {
			t.Errorf("result must be nil on error, got %+v", res)
		}
	})
	t.Run("Keygen", func(t *testing.T) {
		c := dial(t, addr)
		res, err := c.Keygen(ctx, "vault-1", KeygenRequest{})
		if err == nil {
			t.Fatalf("SECURITY: error body decoded as KeygenResult %+v", res)
		}
	})
	t.Run("Status", func(t *testing.T) {
		c := dial(t, addr)
		res, err := c.Status(ctx)
		if err == nil {
			t.Fatalf("SECURITY: error body decoded as ClusterStatus %+v", res)
		}
	})
	t.Run("GetWallet", func(t *testing.T) {
		c := dial(t, addr)
		res, err := c.GetWallet(ctx, "w")
		if err == nil {
			t.Fatalf("SECURITY: error body decoded as Wallet %+v", res)
		}
	})
	// Decrypt is the REK bootstrap path (pkg/store/mpcrek). An error body
	// decoding as success here hands mpcrek a zero-length "plaintext"
	// REK; its length check catches that, but the error must not be
	// laundered into a nil error on the way.
	t.Run("Decrypt", func(t *testing.T) {
		c := dial(t, addr)
		res, err := c.Decrypt(ctx, "kms/rek/v1", nil)
		if err == nil {
			t.Fatalf("SECURITY: error body decoded as DecryptResult %+v", res)
		}
	})
}

// TestSuccessBodyStillDecodes is the control: the error check must not
// break the happy path. A body with no "error" key flows through intact.
func TestSuccessBodyStillDecodes(t *testing.T) {
	addr := serveWith(t, func(uint16, []byte) []byte {
		b, _ := json.Marshal(SignResult{R: "aa", S: "bb", Signature: "ccdd"})
		return b
	})
	c := dial(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.Sign(ctx, SignRequest{WalletID: "w", Message: []byte("m")})
	if err != nil {
		t.Fatalf("success body must not be treated as an error: %v", err)
	}
	if res.R != "aa" || res.S != "bb" || res.Signature != "ccdd" {
		t.Fatalf("success body corrupted: %+v", res)
	}
	t.Logf("success path intact over the sealed wire: %+v", res)
}

// TestClientRequiresToken: a client with no credential fails at
// construction rather than at the first threshold operation.
func TestClientRequiresToken(t *testing.T) {
	if _, err := NewZapClient("test-client", "127.0.0.1:1", nil); err == nil {
		t.Fatal("SECURITY: built a ZAP client with no IAM token source")
	} else {
		t.Logf("refused: %v", err)
	}
}
