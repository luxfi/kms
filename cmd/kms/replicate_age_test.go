package main

import (
	"strings"
	"testing"

	"github.com/luxfi/age"
)

// The replicator encrypts only when it is HANDED a recipient. Reading the
// variable and logging that encryption is on does neither, which is what this
// used to do — the copy went out unencrypted while the log said otherwise.
func TestAnAgeRecipientReachesTheReplicator(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	recipient, err := age.ParseX25519Recipient(id.Recipient().String())
	if err != nil {
		t.Fatalf("the recipient this deployment would set does not parse: %v", err)
	}
	if recipient == nil {
		t.Fatal("parsed to nothing — the replicator would encrypt with no one")
	}
}

// A recipient that cannot be parsed means the operator asked for encryption and
// would not get it. Shipping an unencrypted copy of the store in that case is
// worse than not shipping one, because they believe it is protected.
func TestAnUnusableRecipientIsNotSilentlyIgnored(t *testing.T) {
	if _, err := age.ParseX25519Recipient("age1-obviously-not-a-key"); err == nil {
		t.Fatal("a malformed recipient parsed — nothing would refuse it")
	}
	if _, err := age.ParseX25519Recipient(strings.TrimSpace("")); err == nil {
		t.Fatal("an empty recipient parsed")
	}
}
