package main

import (
	"os"
	"strings"
	"testing"
)

// A root key in the environment is a root key in a Secret, and anything that
// reads Secrets — a cloud API token, a shell in the pod, a volume snapshot —
// then holds the one value that opens every secret this store keeps. Sealing
// under a root that sits beside the ciphertext protects nothing from the reader
// who has both, so the environment is not a source.
func TestNoRootKeyComesFromTheEnvironment(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	i := strings.Index(body, "func loadREK()")
	if i < 0 {
		t.Fatal("loadREK not found — this test has stopped covering the root key")
	}
	fn := body[i:]
	if j := strings.Index(fn, "\n}\n"); j > 0 {
		fn = fn[:j]
	}
	if !strings.Contains(fn, "mpcrek.Bootstrap") {
		t.Fatal("loadREK no longer reaches the ring")
	}
	// The name may appear, but only to refuse it. A decode of it is a source.
	if strings.Contains(fn, "DecodeString(b64)") || strings.Contains(fn, "return mk") {
		t.Fatal("loadREK decodes a root key from the environment")
	}
	if !strings.Contains(fn, "log.Fatalf") || !strings.Contains(fn, "KMS_MASTER_KEY_B64") {
		t.Fatal("an environment root key is ignored rather than refused; an operator who set it would believe the store is sealed")
	}
}
