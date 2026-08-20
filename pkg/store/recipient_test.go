package store

import (
	"bytes"
	"strings"
	"testing"
)

func mint(t *testing.T) (identity, recipient string) {
	t.Helper()
	identity, recipient, err := Recipient()
	if err != nil {
		t.Fatal(err)
	}
	return identity, recipient
}

// The round trip, which is the only thing that has to work.
func TestARecipientOpensWhatWasSealedToIt(t *testing.T) {
	identity, recipient := mint(t)
	want := []byte("sk-live-the-actual-credential")

	sec, err := SealTo(recipient, "/orgs/acme", "OPENAI_API_KEY", "main", want)
	if err != nil {
		t.Fatal(err)
	}
	if sec.Scheme != ModeRecipient {
		t.Fatalf("scheme = %q, want %q", sec.Scheme, ModeRecipient)
	}
	if sec.KeyHandle != recipient {
		t.Fatalf("the secret does not record which recipient sealed it: %q", sec.KeyHandle)
	}
	if bytes.Contains(sec.Ciphertext, want) || bytes.Contains(sec.WrappedDEK, want) {
		t.Fatal("the plaintext is present in the sealed record")
	}

	got, err := OpenWith(identity, sec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("opened %q, want %q", got, want)
	}
}

// THE PROPERTY THIS EXISTS FOR. Sealing takes the public half, so a process that
// enrols credentials holds nothing that opens one. If this ever passes with the
// recipient alone, the split is gone and so is the reason for the scheme.
func TestThePublicHalfDoesNotOpenAnything(t *testing.T) {
	_, recipient := mint(t)

	sec, err := SealTo(recipient, "/orgs/acme", "OPENAI_API_KEY", "main", []byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(recipient, sec); err == nil {
		t.Fatal("the recipient's PUBLIC key opened a secret sealed to it")
	}
}

// Another recipient's identity is not a key to this one, so one holder of one
// identity does not become a holder of every secret.
func TestAnotherIdentityDoesNotOpenIt(t *testing.T) {
	_, recipient := mint(t)
	other, _ := mint(t)

	sec, err := SealTo(recipient, "/orgs/acme", "OPENAI_API_KEY", "main", []byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(other, sec); err == nil {
		t.Fatal("an unrelated identity opened the secret")
	}
}

// The master key is not a way in. A deployment that holds the master and a
// recipient-sealed store holds ciphertext and nothing else — which is the whole
// claim being made about a cluster that can be exec'd into.
func TestTheMasterKeyDoesNotOpenARecipientSealedSecret(t *testing.T) {
	_, recipient := mint(t)
	master := bytes.Repeat([]byte{7}, 32)

	sec, err := SealTo(recipient, "/orgs/acme", "OPENAI_API_KEY", "main", []byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(master, sec)
	if err == nil {
		t.Fatal("the master key opened a secret sealed to a recipient")
	}
	// And it says so plainly, rather than as an authentication failure that
	// reads like a damaged record.
	if !strings.Contains(err.Error(), recipient) {
		t.Fatalf("the refusal does not name the recipient that can open it:\n  %v", err)
	}
}

// A secret moved to another coordinate must stop opening. The AAD binds the
// payload to path/name/env, so a store that shuffles rows cannot serve one
// tenant's credential under another's name.
func TestAMovedSecretDoesNotOpen(t *testing.T) {
	identity, recipient := mint(t)

	sec, err := SealTo(recipient, "/orgs/acme", "OPENAI_API_KEY", "main", []byte("acme's credential"))
	if err != nil {
		t.Fatal(err)
	}
	for _, moved := range []struct {
		what string
		to   *Secret
	}{
		{"path", &Secret{Path: "/orgs/globex", Name: sec.Name, Env: sec.Env, Ciphertext: sec.Ciphertext, WrappedDEK: sec.WrappedDEK, Scheme: sec.Scheme}},
		{"name", &Secret{Path: sec.Path, Name: "OTHER_KEY", Env: sec.Env, Ciphertext: sec.Ciphertext, WrappedDEK: sec.WrappedDEK, Scheme: sec.Scheme}},
		{"env", &Secret{Path: sec.Path, Name: sec.Name, Env: "dev", Ciphertext: sec.Ciphertext, WrappedDEK: sec.WrappedDEK, Scheme: sec.Scheme}},
	} {
		t.Run(moved.what, func(t *testing.T) {
			if _, err := OpenWith(identity, moved.to); err == nil {
				t.Fatalf("a secret opened under a different %s", moved.what)
			}
		})
	}
}

// A master-sealed secret is refused by name rather than attempted, so the two
// schemes cannot be confused for one another in either direction.
func TestOpenWithRefusesAMasterSealedSecret(t *testing.T) {
	identity, _ := mint(t)
	master := bytes.Repeat([]byte{9}, 32)

	sec, err := Seal(master, "/orgs/acme", "OPENAI_API_KEY", "main", []byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenWith(identity, sec)
	if err == nil {
		t.Fatal("a master-sealed secret was opened by the recipient path")
	}
	if !strings.Contains(err.Error(), sec.Scheme) {
		t.Fatalf("the refusal does not say which scheme it found:\n  %v", err)
	}
}

// Sealing under no recipient must fail rather than find something else to use.
func TestSealingNeedsARecipient(t *testing.T) {
	if _, err := SealTo("", "/orgs/acme", "K", "main", []byte("v")); err == nil {
		t.Fatal("sealed a secret with no recipient")
	}
	if _, err := SealTo("age1pq1-not-a-real-key", "/orgs/acme", "K", "main", []byte("v")); err == nil {
		t.Fatal("sealed a secret to an unparseable recipient")
	}
}

// Two seals of one value share nothing, so a store cannot be read by comparing
// records to each other.
func TestTwoSealsOfOneValueDiffer(t *testing.T) {
	_, recipient := mint(t)
	v := []byte("credential")

	a, err := SealTo(recipient, "/orgs/acme", "K", "main", v)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealTo(recipient, "/orgs/acme", "K", "main", v)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("two seals of the same value produced the same bytes")
	}
}
