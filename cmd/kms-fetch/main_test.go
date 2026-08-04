package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// KMS_SECRETS is the whole interface between a manifest and this binary, so a
// malformed entry has to fail loudly at parse rather than resolve to something
// surprising at fetch.
func TestParseSpecs(t *testing.T) {
	t.Run("a coordinate splits at the LAST slash", func(t *testing.T) {
		got, err := parseSpecs("TOKEN=platform/deploy/UNIVERSE_PIN_TOKEN")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d specs, want 1", len(got))
		}
		if got[0].path != "platform/deploy" || got[0].key != "UNIVERSE_PIN_TOKEN" {
			t.Fatalf("split %+v — a path may have many segments, a name is one", got[0])
		}
	})

	t.Run("a bare name is the root path", func(t *testing.T) {
		got, err := parseSpecs("K=SOME_KEY")
		if err != nil {
			t.Fatal(err)
		}
		if got[0].path != "" || got[0].key != "SOME_KEY" {
			t.Fatalf("got %+v, want root path and SOME_KEY", got[0])
		}
	})

	t.Run("several entries, whitespace tolerated", func(t *testing.T) {
		got, err := parseSpecs(" A=p/one , B=q/two ")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].as != "A" || got[1].as != "B" {
			t.Fatalf("got %+v", got)
		}
	})

	// Each of these would otherwise become a runtime surprise: a file written
	// somewhere unintended, or one entry silently overwriting another.
	for _, bad := range []struct{ name, in string }{
		{"empty", ""},
		{"no equals", "JUST_A_NAME"},
		{"no name", "=path/key"},
		{"no coordinate", "NAME="},
		{"names no secret", "NAME=path/"},
		{"a path separator in the filename", "a/b=path/key"},
		{"the same name twice", "A=p/one,A=q/two"},
	} {
		t.Run("rejects "+bad.name, func(t *testing.T) {
			if _, err := parseSpecs(bad.in); err == nil {
				t.Fatalf("parseSpecs(%q) was accepted", bad.in)
			}
		})
	}
}

// A secret is written whole or not at all: a reader that opens the file while it
// is being written must never see a truncated credential.
func TestWriteAtomicIsCompleteAndUnreadableToOthers(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "TOKEN")
	if err := writeAtomic(dst, []byte("s3cret"), 0o400); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "s3cret" {
		t.Fatalf("read %q", b)
	}

	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o400 {
		t.Fatalf("mode is %v, want 0400 — a credential is owner-read-only", fi.Mode().Perm())
	}

	// The temp file must not survive: a leftover copy of a secret under a
	// predictable-ish name is exactly what this binary exists to avoid.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v — the temp file was left behind", names)
	}
}

// An initContainer's failure is read from its exit code before anyone reads its
// log, so the codes have to distinguish the three operator problems.
func TestExitCodesSeparateTheOperatorProblems(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{&configError{"missing"}, exitConfig},
		{&dialError{errors.New("connection refused")}, exitDial},
		{&fetchError{as: "TOKEN", err: errors.New("not found")}, exitFetch},
		{errors.New("something else"), 1},
	}
	for _, c := range cases {
		if got := exitFor(c.err); got != c.want {
			t.Errorf("exitFor(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

// "KMS is unreachable" and "that name is wrong" are different problems and must
// not be reported as each other.
func TestUnreachableIsDistinguishedFromNotFound(t *testing.T) {
	for _, s := range []string{"dial tcp: connection refused", "context deadline exceeded", "no such host", "unexpected EOF"} {
		if !isUnreachable(errors.New(s)) {
			t.Errorf("%q should read as unreachable", s)
		}
	}
	for _, s := range []string{"secret not found", "forbidden", "invalid coordinate"} {
		if isUnreachable(errors.New(s)) {
			t.Errorf("%q should NOT read as unreachable", s)
		}
	}
}
