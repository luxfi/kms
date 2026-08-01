package store

import (
	"testing"

	badger "github.com/luxfi/zapdb"
)

func findTestStore(t *testing.T) *SecretStore {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true).WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewSecretStore(db)
}

func mustPut(t *testing.T, s *SecretStore, path, env, name string) {
	t.Helper()
	if err := s.Put(&Secret{Path: path, Env: env, Name: name, Ciphertext: []byte("ct")}); err != nil {
		t.Fatalf("put %s/%s/%s: %v", path, env, name, err)
	}
}

// TestSplitSecretKeyRoundTrips is the property a listing rests on: whatever
// coordinate Find reports for a key must address that exact key again. If it
// did not, a caller could see a name it cannot then fetch or delete — a listing
// that is worse than none.
func TestSplitSecretKeyRoundTrips(t *testing.T) {
	for _, c := range []struct{ path, env, name string }{
		{"deploy", "prod", "UNIVERSE_PIN_TOKEN"},
		{"", "prod", "ROOT_KEY"},          // a secret at the store root
		{"deploy/ci", "prod", "RUNNER"},   // nested path
		{"a/b/c/d", "staging", "DEEP"},    // deeply nested
		{"deploy", "prod", "dotted.name"}, // punctuation in the name
		{"deploy", "prod", "a b"},         // space in the name
		{"deploy", "prod", "a/b"},         // ambiguous: still rejoins to its own key
	} {
		key := string(secretKey(c.path, c.name, c.env))
		path, env, name, ok := splitSecretKey(key)
		if !ok {
			t.Fatalf("splitSecretKey(%q) not ok", key)
		}
		if got := string(secretKey(path, name, env)); got != key {
			t.Fatalf("round trip: %q -> (%q,%q,%q) -> %q", key, path, env, name, got)
		}
	}

	// Anything that is not a secret record is skipped, never reported.
	for _, key := range []string{"kms/keys/val-1", "kms/secrets/onlyone", "", "kms/secrets/p/e/"} {
		if _, _, _, ok := splitSecretKey(key); ok {
			t.Fatalf("splitSecretKey(%q) = ok, want skipped", key)
		}
	}
}

// TestFindSelectsSubtreeAndEnv pins the two filter dimensions at the store
// level: path is a recursive subtree on a segment boundary, env is an exact
// filter, and omitting either means "all of it" rather than a silent default.
func TestFindSelectsSubtreeAndEnv(t *testing.T) {
	s := findTestStore(t)
	mustPut(t, s, "", "prod", "ROOT")
	mustPut(t, s, "deploy", "prod", "PIN")
	mustPut(t, s, "deploy", "staging", "PIN")
	mustPut(t, s, "deploy/ci", "prod", "RUNNER")
	mustPut(t, s, "deployfoo", "prod", "OTHER")

	got := func(q Query) []Ref {
		t.Helper()
		refs, err := s.Find(q)
		if err != nil {
			t.Fatalf("find %+v: %v", q, err)
		}
		return refs
	}

	if all := got(Query{}); len(all) != 5 {
		t.Fatalf("zero Query must select every record, got %d: %+v", len(all), all)
	}
	// Ordering is (path, env, name) so two runs are diffable.
	if all := got(Query{}); all[0].Path != "" || all[1].Path != "deploy" || all[1].Env != "prod" {
		t.Fatalf("results are not ordered by (path, env, name): %+v", all)
	}

	sub := got(Query{Path: "deploy"})
	if len(sub) != 3 { // PIN prod, PIN staging, deploy/ci RUNNER — never deployfoo
		t.Fatalf("path=deploy must descend and stop at the segment boundary, got %+v", sub)
	}
	for _, r := range sub {
		if r.Path == "deployfoo" || r.Path == "" {
			t.Fatalf("path=deploy leaked %+v", r)
		}
	}

	if env := got(Query{Env: "staging"}); len(env) != 1 || env[0].Path != "deploy" {
		t.Fatalf("env filter must span every path and only that env, got %+v", env)
	}
	if both := got(Query{Path: "deploy", Env: "prod"}); len(both) != 2 {
		t.Fatalf("path+env must intersect, got %+v", both)
	}
	// Slash spellings of one subtree are one subtree.
	for _, p := range []string{"/deploy", "deploy/", "/deploy/"} {
		if len(got(Query{Path: p})) != 3 {
			t.Fatalf("path=%q must mean the same subtree as %q", p, "deploy")
		}
	}
	if none := got(Query{Env: "nope"}); len(none) != 0 {
		t.Fatalf("an env with no records is empty, got %+v", none)
	}
}

// TestPutRejectsAmbiguousCoord keeps the keyspace injective: env and name are
// the last two key segments, so a '/' in either would let two coordinates spell
// one key. Refused at the boundary rather than stored and mis-reported later.
func TestPutRejectsAmbiguousCoord(t *testing.T) {
	s := findTestStore(t)
	for _, c := range []struct{ env, name string }{
		{"prod", "a/b"},
		{"pr/od", "NAME"},
		{"", "NAME"},
		{"prod", ""},
		{"prod", "bad\x00name"},
		{"prod", "bad\nname"},
	} {
		if err := s.Put(&Secret{Path: "p", Env: c.env, Name: c.name, Ciphertext: []byte("ct")}); err == nil {
			t.Fatalf("Put(env=%q name=%q) = nil, want ErrInvalidCoord", c.env, c.name)
		}
	}
	if refs, _ := s.Find(Query{}); len(refs) != 0 {
		t.Fatalf("a refused write must store nothing, got %+v", refs)
	}
}
