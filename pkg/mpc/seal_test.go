package mpc

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	kmszap "github.com/luxfi/kms/pkg/zap"
)

// What this connection carries is the root key every per-secret DEK is wrapped
// under. A request must never leave in a form a reader on the path can parse.
func TestARequestDoesNotLeaveInTheClear(t *testing.T) {
	c := &ZapClient{session: testSession(t)}
	const keyID = "rek-prod-2026"

	sealed, err := c.session.Seal(kmszap.DirClientToServer, mustJSON(t, map[string]string{"keyId": keyID}))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed, []byte(keyID)) {
		t.Fatal("the key id is readable in what goes on the wire")
	}
	var probe map[string]string
	if json.Unmarshal(sealed, &probe) == nil {
		t.Fatal("the payload still parses as JSON — it is not sealed")
	}
}

// A client that could not agree a session must not be usable. If one is ever
// reachable, its call path refuses rather than sending in the clear — which is
// the behaviour this replaced.
func TestNoSessionMeansNoSend(t *testing.T) {
	c := &ZapClient{}
	if _, err := c.call(context.Background(), OpKeygen, map[string]string{"k": "v"}); err == nil {
		t.Fatal("a sessionless client sent a request")
	}
}

func testSession(t *testing.T) *kmszap.Session {
	t.Helper()
	state, hello, err := kmszap.NewClient(kmszap.CapMLKEM768)
	if err != nil {
		t.Fatalf("client hello: %v", err)
	}
	reply, _, err := kmszap.ServerRespond(kmszap.CapMLKEM768, hello)
	if err != nil {
		t.Fatalf("server respond: %v", err)
	}
	res, err := state.ClientFinish(reply)
	if err != nil {
		t.Fatalf("client finish: %v", err)
	}
	s, err := kmszap.NewSession(res)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return s
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
