package zapclient

import (
	"testing"

	"github.com/luxfi/zap"
)

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
		t.Fatalf("status bytes drift: ok=%d nf=%d err=%d forbid=%d",
			statusOK, statusNotFound, statusError, statusForbid)
	}
}

func TestBuildMessageWithType_Parseable(t *testing.T) {
	body := []byte("hello-zap")
	msg := buildMessageWithType(0x0040, body)
	if msg == nil {
		t.Fatal("buildMessageWithType returned nil")
	}
	if msg.Size() == 0 {
		t.Fatal("message size is zero")
	}
	reparsed, err := zap.Parse(msg.Bytes())
	if err != nil {
		t.Fatalf("not re-parseable: %v", err)
	}
	if reparsed == nil {
		t.Fatal("re-parsed message is nil")
	}
	// Verify the flags encode our opcode
	if got := reparsed.Flags() >> 8; got != 0x0040 {
		t.Fatalf("flags>>8 = 0x%04x, want 0x0040", got)
	}
}
