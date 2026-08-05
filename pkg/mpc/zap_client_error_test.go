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
	"testing"
	"time"

	"github.com/luxfi/zap"
)

// errServer stands up a zap.Node that answers every opcode with the
// server's error envelope, framed exactly as pkg/api/zap_kms_server.go
// frames it: opcode(2 LE) || {"error": "..."}.
func errServer(t *testing.T, msg string) string {
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

	reply := func(_ context.Context, _ string, m *zap.Message) (*zap.Message, error) {
		raw := m.Bytes()
		if len(raw) < zap.HeaderSize+2 {
			return nil, errors.New("short request")
		}
		op := binary.LittleEndian.Uint16(raw[zap.HeaderSize : zap.HeaderSize+2])
		body, _ := json.Marshal(map[string]string{"error": msg})
		out := make([]byte, 2+len(body))
		binary.LittleEndian.PutUint16(out[0:2], op)
		copy(out[2:], body)
		b := zap.NewBuilder(len(out) + 64)
		b.WriteBytes(out)
		return zap.Parse(b.Finish())
	}
	node.Handle(0, reply)
	for _, op := range []uint16{OpStatus, OpKeygen, OpSign, OpReshare, OpWallet, OpDecrypt} {
		node.Handle(op, reply)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("start err-server: %v", err)
	}
	t.Cleanup(node.Stop)
	time.Sleep(50 * time.Millisecond)
	return addr
}

func dial(t *testing.T, addr string) *ZapClient {
	t.Helper()
	c, err := NewZapClient("test-client", addr)
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	node := zap.NewNode(zap.NodeConfig{
		NodeID: "ok-server", ServiceType: "_lux-kms._tcp",
		Port: port, NoDiscovery: true,
	})
	ok := func(_ context.Context, _ string, m *zap.Message) (*zap.Message, error) {
		raw := m.Bytes()
		op := binary.LittleEndian.Uint16(raw[zap.HeaderSize : zap.HeaderSize+2])
		body, _ := json.Marshal(SignResult{R: "aa", S: "bb", Signature: "ccdd"})
		out := make([]byte, 2+len(body))
		binary.LittleEndian.PutUint16(out[0:2], op)
		copy(out[2:], body)
		b := zap.NewBuilder(len(out) + 64)
		b.WriteBytes(out)
		return zap.Parse(b.Finish())
	}
	node.Handle(0, ok)
	node.Handle(OpSign, ok)
	if err := node.Start(); err != nil {
		t.Fatalf("start ok-server: %v", err)
	}
	defer node.Stop()
	time.Sleep(50 * time.Millisecond)

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
	t.Logf("success path intact: %+v", res)
}
