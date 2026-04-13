package zapclient

import (
	"testing"

	"github.com/luxfi/zap"
)

// These tests lock the wire-format constants to the server's values so drift
// between pkg/zapclient and pkg/zapserver is caught at compile/test time.
// Live interop is tested in cmd/kms integration tests.

func TestOpcodes_MatchServer(t *testing.T) {
	cases := []struct {
		name string
		op   uint16
		want uint16
	}{
		{"Get", OpSecretGet, 0x0040},
		{"Put", OpSecretPut, 0x0041},
		{"List", OpSecretList, 0x0042},
		{"Delete", OpSecretDelete, 0x0043},
	}
	for _, c := range cases {
		if c.op != c.want {
			t.Errorf("%s = 0x%04x, want 0x%04x", c.name, c.op, c.want)
		}
	}
}

func TestStatusBytes(t *testing.T) {
	if statusOK != 0x00 || statusNotFound != 0x01 || statusError != 0x02 || statusForbid != 0x03 {
		t.Fatalf("status bytes drift from server: ok=%d nf=%d err=%d forbid=%d",
			statusOK, statusNotFound, statusError, statusForbid)
	}
}

func TestBuildMessage_Parseable(t *testing.T) {
	// buildMessage must produce a message that zap.Parse can re-read. Exact
	// wire contents are a luxfi/zap detail; we only assert shape.
	body := []byte("hello-zap")
	msg := buildMessage(body)
	if msg == nil {
		t.Fatalf("buildMessage returned nil")
	}
	if msg.Size() == 0 {
		t.Fatalf("message size is zero")
	}
	// Round-trip through Parse — if the framing is wrong, this errors out.
	reparsed, err := zap.Parse(msg.Bytes())
	if err != nil {
		t.Fatalf("built message is not re-parseable: %v", err)
	}
	if reparsed == nil {
		t.Fatalf("re-parsed message is nil")
	}
}
