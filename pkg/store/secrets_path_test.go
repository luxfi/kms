package store

import "testing"

// One canonical spelling per path. The POST body carries a free-form path while
// a GET's path comes from the URL, so the two framings used to disagree over a
// leading slash: the write landed at kms/secrets//svc/... and every read looked
// under kms/secrets/svc/... . 201 then 404 — the caller was told the write
// succeeded and the value was unreachable, so a consumer took an empty
// credential from a store that had reported success.
func TestSecretKeyPathIsCanonical(t *testing.T) {
	want := string(secretKey("svc", "TOKEN", "prod"))
	for _, spelling := range []string{"/svc", "svc/", "/svc/"} {
		if got := string(secretKey(spelling, "TOKEN", "prod")); got != want {
			t.Errorf("secretKey(%q) = %q, want %q", spelling, got, want)
		}
	}
}

// The property that matters to a caller: whatever spelling wrote the record,
// every other spelling reads THAT record back — and there is only ever one.
func TestPutThenGetAcrossPathSpellings(t *testing.T) {
	s := findTestStore(t)

	if err := s.Put(&Secret{Path: "/svc", Env: "prod", Name: "TOKEN", Ciphertext: []byte("v1")}); err != nil {
		t.Fatalf("put: %v", err)
	}
	for _, spelling := range []string{"svc", "/svc", "svc/", "/svc/"} {
		got, err := s.Get(spelling, "TOKEN", "prod")
		if err != nil {
			t.Fatalf("get(%q): %v", spelling, err)
		}
		if string(got.Ciphertext) != "v1" {
			t.Fatalf("get(%q) returned a different record", spelling)
		}
	}

	// One record, not four: a write through another spelling must UPDATE, not
	// fork a second stranded copy that only its own spelling can reach.
	if err := s.Put(&Secret{Path: "svc/", Env: "prod", Name: "TOKEN", Ciphertext: []byte("v2")}); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	refs, err := s.Find(Query{Path: "svc", Env: "prod"})
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("find = %d records, want 1 (a spelling forked the keyspace): %+v", len(refs), refs)
	}
	got, err := s.Get("/svc", "TOKEN", "prod")
	if err != nil || string(got.Ciphertext) != "v2" {
		t.Fatalf("get after re-put = %v, %v; want v2", got, err)
	}

	// And a listed coordinate addresses the record it names — a listing whose
	// rows cannot be fetched or deleted is worse than none.
	if _, err := s.Get(refs[0].Path, refs[0].Name, refs[0].Env); err != nil {
		t.Fatalf("listed coordinate %+v is not fetchable: %v", refs[0], err)
	}
	if err := s.Delete(refs[0].Path, refs[0].Name, refs[0].Env); err != nil {
		t.Fatalf("listed coordinate %+v is not deletable: %v", refs[0], err)
	}
}
