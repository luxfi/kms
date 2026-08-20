package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The invariant this file exists to hold: A SECRET THAT WAS WRITTEN IS A SECRET
// THE LIST RETURNS.
//
// It was missing, and its absence cost a day of continuous deployment. Every
// read of deploy/UNIVERSE_PIN_TOKEN answered 200 with a value while every list
// of the same store answered 200 with []. Nothing anywhere reported an error,
// so a stale, invalid token sat in KMS unnoticed: each build published an image
// and pinned nothing. You cannot audit, rotate, or verify the coverage of a
// store you cannot enumerate.
//
// The store keys a secret at kms/secrets/{path}/{env}/{name}, which braids
// path and env into one string. A single prefix scan over that key can only
// ever answer for one exact (path, env) pair, so a listing had three separate
// ways to come back empty while the record sat right there:
//
//	1. it silently defaulted env to "default" while the fleet writes "prod";
//	2. it matched a path exactly, so a secret one segment deeper was invisible;
//	3. it silently ignored any query parameter it did not recognize, so the
//	   ?prefix=deploy that both shipped SDKs emit filtered nothing and read back
//	   as an empty store.
//
// Each case below is one of those, written as the round trip: put it, then ask
// for it the way a caller actually asks.

// listBody is the list response, decoded.
type listBody struct {
	Names   []string `json:"names"`
	Total   int      `json:"total"`
	Secrets []struct {
		Path string `json:"path"`
		Env  string `json:"env"`
		Name string `json:"name"`
	} `json:"secrets"`
	Query struct {
		Path string `json:"path"`
		Env  string `json:"env"`
	} `json:"query"`
	Message string `json:"message"`
}

// listFixture stands up the real routes over a real store and returns the two
// verbs the round trip needs.
type listFixture struct {
	t   *testing.T
	srv *httptest.Server
	tok string
}

func newListFixture(t *testing.T) *listFixture {
	t.Helper()
	auth, bearer, cleanup := newTestKeyAuth(t, roleKMSAdmin)
	t.Cleanup(cleanup)
	mux := http.NewServeMux()
	registerSecretRoutes(mux, auth, newTestSecretStore(t), testREK())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &listFixture{t: t, srv: srv, tok: bearer}
}

func (f *listFixture) do(method, path, body string) (int, string) {
	f.t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+f.tok)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// put writes a secret and fails the test if the write did not take.
func (f *listFixture) put(path, name, env string) {
	f.t.Helper()
	body := fmt.Sprintf(`{"path":%q,"name":%q,"env":%q,"value":%q}`, path, name, env, "v-"+name)
	if code, b := f.do("POST", "/v1/kms/secrets", body); code != http.StatusCreated {
		f.t.Fatalf("PUT %s/%s env=%s = %d, want 201: %s", path, name, env, code, b)
	}
}

// list issues a list request and decodes it.
func (f *listFixture) list(query string) (int, listBody) {
	f.t.Helper()
	code, raw := f.do("GET", "/v1/kms/secrets"+query, "")
	var out listBody
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		f.t.Fatalf("GET /v1/kms/secrets%s: decode %q: %v", query, raw, err)
	}
	return code, out
}

// has reports whether the listing contains name at exactly (path, env). It
// checks the full coordinate, not just the name, so a test cannot pass on a
// same-named record from another environment.
func (b listBody) has(path, env, name string) bool {
	for _, s := range b.Secrets {
		if s.Path == path && s.Env == env && s.Name == name {
			return true
		}
	}
	return false
}

// TestList_SeesWhatWasWritten is THE regression: write a secret, then ask the
// list for it the way callers actually ask — with no filters at all. This is
// the exact query that answered [] while deploy/UNIVERSE_PIN_TOKEN sat in the
// store, and the one no test covered.
func TestList_SeesWhatWasWritten(t *testing.T) {
	f := newListFixture(t)
	f.put("deploy", "UNIVERSE_PIN_TOKEN", "prod")

	code, got := f.list("")
	if code != http.StatusOK {
		t.Fatalf("bare list = %d, want 200", code)
	}
	if !got.has("deploy", "prod", "UNIVERSE_PIN_TOKEN") {
		t.Fatalf("a secret that was written is not in the unfiltered listing: total=%d names=%v", got.Total, got.Names)
	}

	// The same record, reachable by every honest spelling of "where it lives".
	for _, q := range []string{
		"?path=deploy",          // its own path
		"?path=deploy/",         // trailing slash
		"?path=/deploy",         // leading slash
		"?env=prod",             // its env, any path
		"?path=deploy&env=prod", // both
		"?prefix=deploy",        // the spelling the shipped SDKs emit
	} {
		code, got := f.list(q)
		if code != http.StatusOK {
			t.Fatalf("list %s = %d, want 200", q, code)
		}
		if !got.has("deploy", "prod", "UNIVERSE_PIN_TOKEN") {
			t.Fatalf("list %s did not return the written secret: total=%d", q, got.Total)
		}
	}
}

// TestList_CrossesEnvironments pins the first silent-empty axis: env is a key
// component, so a listing that quietly picks one env reports an empty store
// while another env holds every record. Omitting env must mean EVERY env, and
// each row must say which env it is from.
func TestList_CrossesEnvironments(t *testing.T) {
	f := newListFixture(t)
	f.put("deploy", "GITHUB_TOKEN", "prod")
	f.put("deploy", "GITHUB_TOKEN", "staging")

	_, all := f.list("")
	if !all.has("deploy", "prod", "GITHUB_TOKEN") || !all.has("deploy", "staging", "GITHUB_TOKEN") {
		t.Fatalf("no-env listing must span every env, got %d rows: %+v", all.Total, all.Secrets)
	}
	if all.Query.Env != "" {
		t.Fatalf("query echo says env=%q; an unfiltered list must not claim an env", all.Query.Env)
	}

	// Naming an env narrows to it — and to nothing else.
	_, prod := f.list("?env=prod")
	if !prod.has("deploy", "prod", "GITHUB_TOKEN") || prod.has("deploy", "staging", "GITHUB_TOKEN") {
		t.Fatalf("env=prod must return exactly the prod record, got %+v", prod.Secrets)
	}

	// An env nothing was written to is honestly empty, and says which env it
	// searched so the caller can tell "wrong question" from "empty store".
	_, none := f.list("?env=dev")
	if none.Total != 0 {
		t.Fatalf("env=dev = %d rows, want 0", none.Total)
	}
	if none.Query.Env != "dev" {
		t.Fatalf("empty result must echo the env it searched, got %q", none.Query.Env)
	}
}

// TestList_DescendsSubPaths pins the second axis: a listing that matches a path
// exactly cannot see a secret one segment deeper, so an operator asking "what
// is under deploy?" is told "nothing" while deploy/ci holds records. A path
// filter is a SUBTREE, and the boundary is a segment — deploy never matches
// deployfoo.
func TestList_DescendsSubPaths(t *testing.T) {
	f := newListFixture(t)
	f.put("", "ROOT_KEY", "prod")
	f.put("deploy", "PIN_TOKEN", "prod")
	f.put("deploy/ci", "RUNNER_TOKEN", "prod")
	f.put("deployfoo", "OTHER_TOKEN", "prod")

	_, all := f.list("")
	for _, want := range [][3]string{
		{"", "prod", "ROOT_KEY"},
		{"deploy", "prod", "PIN_TOKEN"},
		{"deploy/ci", "prod", "RUNNER_TOKEN"},
		{"deployfoo", "prod", "OTHER_TOKEN"},
	} {
		if !all.has(want[0], want[1], want[2]) {
			t.Fatalf("unfiltered listing missing %v; got %+v", want, all.Secrets)
		}
	}

	_, sub := f.list("?path=deploy")
	if !sub.has("deploy", "prod", "PIN_TOKEN") || !sub.has("deploy/ci", "prod", "RUNNER_TOKEN") {
		t.Fatalf("path=deploy must descend into deploy/ci, got %+v", sub.Secrets)
	}
	if sub.has("deployfoo", "prod", "OTHER_TOKEN") {
		t.Fatalf("path=deploy must not match deployfoo (segment boundary), got %+v", sub.Secrets)
	}
	if sub.has("", "prod", "ROOT_KEY") {
		t.Fatalf("path=deploy must not return the root, got %+v", sub.Secrets)
	}
}

// TestList_RejectsUnknownParameter pins the third and worst axis. ?prefix= was
// a real request against the live service: it was silently dropped, the list
// ran unfiltered, and the caller read the answer as "this store is empty". A
// filter the server does not implement must be an error, never a different
// question answered as if it were the one asked.
func TestList_RejectsUnknownParameter(t *testing.T) {
	f := newListFixture(t)
	f.put("deploy", "UNIVERSE_PIN_TOKEN", "prod")

	for _, q := range []string{
		"?secretPath=deploy",  // the /api/v3 vocabulary, not this API's
		"?environment=prod",   // same
		"?env=prod&secrets=x", // mixed with a valid one
		"?Path=deploy",        // wrong case is a different parameter
		"?envs=prod",          // near-miss
		"?nonsense=zzz",
	} {
		code, got := f.list(q)
		if code != http.StatusBadRequest {
			t.Fatalf("list %s = %d, want 400 (a filter the server ignores is worse than no filter); body total=%d", q, code, got.Total)
		}
		if !strings.Contains(got.Message, "unknown query parameter") {
			t.Fatalf("list %s: message %q must name the offending parameter", q, got.Message)
		}
	}

	// An env that cannot match any key is rejected too, rather than returning
	// an empty list that reads as an empty store.
	if code, _ := f.list("?env=a/b"); code != http.StatusBadRequest {
		t.Fatalf("list ?env=a/b = %d, want 400", code)
	}
}

// TestList_TracksDelete closes the loop on the sibling operation: a deleted
// secret must leave the listing, and deleting one env's record must not remove
// another env's record of the same name.
func TestList_TracksDelete(t *testing.T) {
	f := newListFixture(t)
	f.put("deploy", "ROTATE_ME", "prod")
	f.put("deploy", "ROTATE_ME", "staging")

	if code, b := f.do("DELETE", "/v1/kms/secrets/deploy/ROTATE_ME?env=prod", ""); code != http.StatusOK {
		t.Fatalf("delete = %d, want 200: %s", code, b)
	}

	_, all := f.list("")
	if all.has("deploy", "prod", "ROTATE_ME") {
		t.Fatalf("deleted secret still listed: %+v", all.Secrets)
	}
	if !all.has("deploy", "staging", "ROTATE_ME") {
		t.Fatalf("deleting one env removed another env's record: %+v", all.Secrets)
	}

	// Deleting the last one empties the store, and the listing says so
	// honestly rather than erroring.
	if code, b := f.do("DELETE", "/v1/kms/secrets/deploy/ROTATE_ME?env=staging", ""); code != http.StatusOK {
		t.Fatalf("delete = %d, want 200: %s", code, b)
	}
	code, empty := f.list("")
	if code != http.StatusOK || empty.Total != 0 {
		t.Fatalf("emptied store = %d with %d rows, want 200 with 0", code, empty.Total)
	}
}

// TestList_RejectsAmbiguousName guards the decode the listing depends on. env
// and name are the last two key segments, so a '/' in either would let two
// different coordinates spell one key and make a listing's report of that key
// ambiguous. The write is refused at the boundary — loudly, with a 400 — so the
// keyspace stays injective.
func TestList_RejectsAmbiguousName(t *testing.T) {
	f := newListFixture(t)
	for _, body := range []string{
		`{"path":"deploy","name":"a/b","env":"prod","value":"x"}`,
		`{"path":"deploy","name":"OK","env":"pr/od","value":"x"}`,
	} {
		if code, b := f.do("POST", "/v1/kms/secrets", body); code != http.StatusBadRequest {
			t.Fatalf("POST %s = %d, want 400: %s", body, code, b)
		}
	}
	_, all := f.list("")
	if all.Total != 0 {
		t.Fatalf("a refused write must store nothing, got %+v", all.Secrets)
	}
}

// `prefix` is a SPELLING of `path`, not a second question. Two shipped
// first-party SDKs emit it against this route, so it must select exactly the
// same records — and the response must echo the canonical name back, so there
// stays one name for the value even though two spellings reach it.
func TestList_PrefixIsTheSameQuestionAsPath(t *testing.T) {
	f := newListFixture(t)
	f.put("deploy", "PIN_TOKEN", "prod")
	f.put("deploy/ci", "RUNNER_TOKEN", "prod")
	f.put("deployfoo", "OTHER_TOKEN", "prod")

	_, byPath := f.list("?path=deploy")
	_, byPrefix := f.list("?prefix=deploy")

	if byPath.Total == 0 {
		t.Fatal("?path=deploy matched nothing; the comparison below would be vacuous")
	}
	if byPrefix.Total != byPath.Total {
		t.Fatalf("?prefix=deploy = %d rows, ?path=deploy = %d; one spelling, one answer", byPrefix.Total, byPath.Total)
	}
	for _, want := range byPath.Secrets {
		if !byPrefix.has(want.Path, want.Env, want.Name) {
			t.Fatalf("?prefix=deploy missed %s/%s@%s", want.Path, want.Name, want.Env)
		}
	}
	// Same segment boundary as path: a sibling that merely shares the prefix
	// string is NOT in the subtree. `prefix` naming a string prefix would widen
	// disclosure; it does not.
	if byPrefix.has("deployfoo", "prod", "OTHER_TOKEN") {
		t.Fatal("?prefix=deploy reached deployfoo; the alias must keep the segment boundary")
	}
	if byPrefix.Query.Path != "deploy" {
		t.Fatalf("query echo = %q, want the canonical spelling %q", byPrefix.Query.Path, "deploy")
	}
}
