package main

import (
	"context"
	"strings"
	"testing"
)

// The admin credential rides in this request's query, and Go's transport error
// carries the whole URL — it redacts userinfo and never the query. That error
// reached two places that outlive the request: the audit line, and the 502 body
// handed back to the caller. The caller is authenticated as a kms admin and does
// NOT hold that credential, so repeating it hands them one they were never
// given. A caller can force the failure at will by hanging up, because the
// context is the request's own.
func TestTheIAMFailureDoesNotCarryTheAdminCredential(t *testing.T) {
	const secret = "ADMIN-SECRET-VALUE-DO-NOT-REPEAT"
	// Port 1 refuses, so the transport fails without reaching anything.
	c := &oidcConfig{iamEndpoint: "http://127.0.0.1:1", owner: "hanzo"}

	_, _, err := c.callIAMAddApplication(context.Background(), "kms-admin", secret, "probe", "probe")
	if err == nil {
		t.Skip("port 1 answered; cannot produce a transport failure here")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the admin credential reached the caller and the audit line: %s", err)
	}
	if strings.Contains(err.Error(), "clientSecret") {
		t.Fatalf("the query reached the caller: %s", err)
	}
	if err.Error() == "" {
		t.Fatal("the failure says nothing; an operator cannot act on it")
	}
}
