// Tests for principal-role authorization on the Op Secret* opcodes.
//
// We exercise the four handlers directly (no real ZAP node) because the
// authz layer is a pure function of (NodeID, path, op) — wiring up
// luxfi/zap network handshakes here would just slow the test without
// adding coverage. The wire-compat test in
// `cmd/kmsd/wire_compat_test.go` and the existing
// `pkg/zapclient/client_test.go` already cover the ZAP framing path.
package zapserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luxfi/kms/pkg/store"
	badger "github.com/luxfi/zapdb"
)

// newTestServer wires a Server backed by an in-memory ZapDB SecretStore
// and the supplied ACL. The master key is random per-test so any leaked
// plaintext on a regression is harmless.
func newTestServer(t *testing.T, acl *ACL) *Server {
	t.Helper()
	opts := badger.DefaultOptions("").WithInMemory(true)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return New(Config{
		Store:     store.NewSecretStore(db),
		MasterKey: mk,
		ACL:       acl,
	})
}

// seed pre-populates the SecretStore with a value that Get/Delete can
// target. Without seeding, an authorized Get would return statusNotFound
// rather than statusOK, hiding any auth-side regression.
func seed(t *testing.T, s *Server, path, name, env, value string) {
	t.Helper()
	sec, err := store.Seal(s.masterKey, path, name, env, []byte(value))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := s.store.Put(sec); err != nil {
		t.Fatalf("put: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestAuthz_OpenMode_AllowsEveryone documents the legacy behavior — when
// no ACL is configured, every NodeID is permitted. This is the rollout
// safety valve so an unconfigured prod doesn't fall off a cliff.
func TestAuthz_OpenMode_AllowsEveryone(t *testing.T) {
	s := newTestServer(t, nil)
	seed(t, s, "ats", "settlement-key", "dev", "secret-1")

	st, _, err := s.handleGet(context.Background(), "anyone", mustJSON(t, getReq{
		Path: "ats", Name: "settlement-key", Env: "dev",
	}))
	if err != nil {
		t.Fatalf("handleGet: %v", err)
	}
	if st != statusOK {
		t.Fatalf("open-mode get: want statusOK, got 0x%02X", st)
	}
}

// TestAuthz_EnforcedMode_UnknownNodeIsForbidden — fail-closed. Once an
// ACL is configured, any unknown NodeID receives 0x03 forbid on every
// opcode.
func TestAuthz_EnforcedMode_UnknownNodeIsForbidden(t *testing.T) {
	acl := NewACL([]ACLEntry{
		{NodeID: "ats-1", PathPrefix: "ats", Role: RoleRead},
	})
	s := newTestServer(t, acl)
	seed(t, s, "ats", "settlement-key", "dev", "secret-1")

	cases := []struct {
		name string
		op   uint16
		call func(s *Server, from string) (byte, []byte, error)
	}{
		{"Get", OpSecretGet, func(s *Server, from string) (byte, []byte, error) {
			return s.handleGet(context.Background(), from, mustJSON(t, getReq{
				Path: "ats", Name: "settlement-key", Env: "dev",
			}))
		}},
		{"Put", OpSecretPut, func(s *Server, from string) (byte, []byte, error) {
			return s.handlePut(context.Background(), from, mustJSON(t, putReq{
				Path: "ats", Name: "x", Env: "dev",
				Value: base64.StdEncoding.EncodeToString([]byte("v")),
			}))
		}},
		{"List", OpSecretList, func(s *Server, from string) (byte, []byte, error) {
			return s.handleList(context.Background(), from, mustJSON(t, listReq{
				Path: "ats", Env: "dev",
			}))
		}},
		{"Delete", OpSecretDelete, func(s *Server, from string) (byte, []byte, error) {
			return s.handleDelete(context.Background(), from, mustJSON(t, delReq{
				Path: "ats", Name: "settlement-key", Env: "dev",
			}))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, body, err := c.call(s, "stranger")
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}
			if st != statusForbid {
				t.Fatalf("unknown node %s: want statusForbid (0x03), got 0x%02X (body=%s)",
					c.name, st, string(body))
			}
		})
	}
}

// TestAuthz_RoleRead_PermitsGetList_DeniesMutation — read principals can
// fetch and list; they cannot mutate.
func TestAuthz_RoleRead_PermitsGetList_DeniesMutation(t *testing.T) {
	acl := NewACL([]ACLEntry{
		{NodeID: "ats-1", PathPrefix: "ats", Role: RoleRead},
	})
	s := newTestServer(t, acl)
	seed(t, s, "ats", "settlement-key", "dev", "secret-1")

	t.Run("Get permitted", func(t *testing.T) {
		st, _, err := s.handleGet(context.Background(), "ats-1", mustJSON(t, getReq{
			Path: "ats", Name: "settlement-key", Env: "dev",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if st != statusOK {
			t.Fatalf("read.Get: want statusOK, got 0x%02X", st)
		}
	})

	t.Run("List permitted", func(t *testing.T) {
		st, body, err := s.handleList(context.Background(), "ats-1", mustJSON(t, listReq{
			Path: "ats", Env: "dev",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if st != statusOK {
			t.Fatalf("read.List: want statusOK, got 0x%02X body=%s", st, string(body))
		}
	})

	t.Run("Put forbidden", func(t *testing.T) {
		st, _, err := s.handlePut(context.Background(), "ats-1", mustJSON(t, putReq{
			Path: "ats", Name: "x", Env: "dev",
			Value: base64.StdEncoding.EncodeToString([]byte("v")),
		}))
		if err != nil {
			t.Fatal(err)
		}
		if st != statusForbid {
			t.Fatalf("read.Put: want statusForbid, got 0x%02X", st)
		}
	})

	t.Run("Delete forbidden", func(t *testing.T) {
		st, _, err := s.handleDelete(context.Background(), "ats-1", mustJSON(t, delReq{
			Path: "ats", Name: "settlement-key", Env: "dev",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if st != statusForbid {
			t.Fatalf("read.Delete: want statusForbid, got 0x%02X", st)
		}
	})
}

// TestAuthz_RoleAdmin_PermitsAll — admin principals can use every opcode.
func TestAuthz_RoleAdmin_PermitsAll(t *testing.T) {
	acl := NewACL([]ACLEntry{
		{NodeID: "ops-admin", PathPrefix: "ats", Role: RoleAdmin},
	})
	s := newTestServer(t, acl)

	put := putReq{
		Path: "ats", Name: "k", Env: "dev",
		Value: base64.StdEncoding.EncodeToString([]byte("v")),
	}
	if st, _, err := s.handlePut(context.Background(), "ops-admin", mustJSON(t, put)); err != nil || st != statusOK {
		t.Fatalf("admin.Put: status=0x%02X err=%v", st, err)
	}

	get := getReq{Path: "ats", Name: "k", Env: "dev"}
	st, body, err := s.handleGet(context.Background(), "ops-admin", mustJSON(t, get))
	if err != nil || st != statusOK {
		t.Fatalf("admin.Get: status=0x%02X err=%v", st, err)
	}
	var gr getResp
	if err := json.Unmarshal(body, &gr); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	pt, _ := base64.StdEncoding.DecodeString(gr.Value)
	if string(pt) != "v" {
		t.Fatalf("admin.Get: round-trip mismatch: got %q want %q", string(pt), "v")
	}

	if st, _, err := s.handleDelete(context.Background(), "ops-admin", mustJSON(t, delReq{
		Path: "ats", Name: "k", Env: "dev",
	})); err != nil || st != statusOK {
		t.Fatalf("admin.Delete: status=0x%02X err=%v", st, err)
	}
}

// TestAuthz_PathPrefixSegmentAlignment — "ats" must not match "atsx".
// Without segment alignment, a principal scoped to org "a" could reach
// org "ax"'s secrets by prefix substring.
func TestAuthz_PathPrefixSegmentAlignment(t *testing.T) {
	acl := NewACL([]ACLEntry{
		{NodeID: "p", PathPrefix: "ats", Role: RoleRead},
	})
	s := newTestServer(t, acl)
	seed(t, s, "atsx", "k", "dev", "v") // different "org"

	st, _, err := s.handleGet(context.Background(), "p", mustJSON(t, getReq{
		Path: "atsx", Name: "k", Env: "dev",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if st != statusForbid {
		t.Fatalf("prefix bypass: principal scoped to 'ats' reached 'atsx'; got 0x%02X", st)
	}
}

// TestAuthz_PathPrefixSubpath — "ats" matches "ats/foo" and "ats/foo/bar".
func TestAuthz_PathPrefixSubpath(t *testing.T) {
	acl := NewACL([]ACLEntry{
		{NodeID: "p", PathPrefix: "ats", Role: RoleRead},
	})
	s := newTestServer(t, acl)
	seed(t, s, "ats/foo", "k", "dev", "v")

	st, _, err := s.handleGet(context.Background(), "p", mustJSON(t, getReq{
		Path: "ats/foo", Name: "k", Env: "dev",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if st != statusOK {
		t.Fatalf("subpath: want statusOK, got 0x%02X", st)
	}
}

// TestAuthz_UnscopedAdmin_CrossOrgReach — an entry with empty PathPrefix
// is the break-glass admin (mirrors the HTTP-side `isAdmin()` shortcut).
func TestAuthz_UnscopedAdmin_CrossOrgReach(t *testing.T) {
	acl := NewACL([]ACLEntry{
		{NodeID: "root", PathPrefix: "", Role: RoleAdmin},
	})
	s := newTestServer(t, acl)
	seed(t, s, "ats", "k", "dev", "a")
	seed(t, s, "bd", "k", "dev", "b")

	for _, p := range []string{"ats", "bd"} {
		st, _, err := s.handleGet(context.Background(), "root", mustJSON(t, getReq{
			Path: p, Name: "k", Env: "dev",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if st != statusOK {
			t.Fatalf("unscoped admin denied at %s: 0x%02X", p, st)
		}
	}
}

// TestAuthz_MultipleEntries_MostPermissiveWins — a NodeID may have both
// read on a wide prefix AND admin on a narrow one. Admin wins where it
// applies; read still applies elsewhere.
func TestAuthz_MultipleEntries_MostPermissiveWins(t *testing.T) {
	acl := NewACL([]ACLEntry{
		{NodeID: "n", PathPrefix: "ats", Role: RoleRead},
		{NodeID: "n", PathPrefix: "ats/own", Role: RoleAdmin},
	})
	s := newTestServer(t, acl)
	seed(t, s, "ats", "ro", "dev", "v")
	seed(t, s, "ats/own", "rw", "dev", "v")

	// Read on the wide prefix succeeds.
	if st, _, _ := s.handleGet(context.Background(), "n", mustJSON(t, getReq{
		Path: "ats", Name: "ro", Env: "dev",
	})); st != statusOK {
		t.Fatalf("wide read: 0x%02X", st)
	}

	// Mutation outside the narrow admin prefix is forbidden.
	if st, _, _ := s.handlePut(context.Background(), "n", mustJSON(t, putReq{
		Path: "ats", Name: "x", Env: "dev",
		Value: base64.StdEncoding.EncodeToString([]byte("v")),
	})); st != statusForbid {
		t.Fatalf("wide put should be denied, got 0x%02X", st)
	}

	// Mutation inside the narrow admin prefix succeeds.
	if st, _, _ := s.handlePut(context.Background(), "n", mustJSON(t, putReq{
		Path: "ats/own", Name: "y", Env: "dev",
		Value: base64.StdEncoding.EncodeToString([]byte("v")),
	})); st != statusOK {
		t.Fatalf("narrow put: 0x%02X", st)
	}
}

// TestLoadACLFromFile_RoundTrip — exercises the file-format parser used
// by the production boot path (KMS_ZAP_ACL).
func TestLoadACLFromFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.csv")
	body := "" +
		"# ZAP ACL — one entry per line\n" +
		"ats-1,ats,read\n" +
		"\n" +
		"  # comments and blank lines are ignored\n" +
		"ops-admin,,admin\n" +
		"ta-1, ta/own , admin\n" // whitespace tolerated
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	acl, err := LoadACLFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := len(acl.entries); got != 3 {
		t.Fatalf("entries: got %d want 3", got)
	}

	if err := acl.Decide("ats-1", "ats/foo", OpSecretGet); err != nil {
		t.Errorf("ats-1 should read ats/foo: %v", err)
	}
	if err := acl.Decide("ats-1", "ats/foo", OpSecretPut); err == nil {
		t.Errorf("ats-1 should not write")
	}
	if err := acl.Decide("ops-admin", "any/path", OpSecretDelete); err != nil {
		t.Errorf("unscoped admin should reach any path: %v", err)
	}
	if err := acl.Decide("ta-1", "ta/own/foo", OpSecretPut); err != nil {
		t.Errorf("ta-1 should write under ta/own: %v", err)
	}
	if err := acl.Decide("ta-1", "ta/other", OpSecretGet); err == nil {
		t.Errorf("ta-1 should not reach ta/other")
	}
}

// TestLoadACLFromFile_RejectsBadRole — explicit role allowlist; an unknown
// role is a config error, not silently ignored.
func TestLoadACLFromFile_RejectsBadRole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.csv")
	if err := os.WriteFile(path, []byte("n,p,owner\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadACLFromFile(path); err == nil {
		t.Fatalf("expected unknown-role error, got nil")
	}
}

// TestLoadACLFromFile_RejectsMalformed — CSV must have exactly 3 fields.
func TestLoadACLFromFile_RejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.csv")
	if err := os.WriteFile(path, []byte("only-two,read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadACLFromFile(path); err == nil {
		t.Fatalf("expected field-count error, got nil")
	}
}

// TestLoadACLFromEnv_Unset — KMS_ZAP_ACL absent → nil (open mode).
func TestLoadACLFromEnv_Unset(t *testing.T) {
	t.Setenv("KMS_ZAP_ACL", "")
	acl, err := LoadACLFromEnv()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if acl != nil {
		t.Fatalf("expected nil ACL in open mode")
	}
}

// TestAuthz_OpcodeMatrix_Exhaustive cross-references every (role, op) pair
// to make a regression that loosens admin/read mappings impossible to miss.
func TestAuthz_OpcodeMatrix_Exhaustive(t *testing.T) {
	cases := []struct {
		role  Role
		op    uint16
		allow bool
	}{
		{RoleRead, OpSecretGet, true},
		{RoleRead, OpSecretList, true},
		{RoleRead, OpSecretPut, false},
		{RoleRead, OpSecretDelete, false},
		{RoleAdmin, OpSecretGet, true},
		{RoleAdmin, OpSecretList, true},
		{RoleAdmin, OpSecretPut, true},
		{RoleAdmin, OpSecretDelete, true},
	}
	for _, c := range cases {
		got := roleAllowsOp(c.role, c.op)
		if got != c.allow {
			t.Errorf("roleAllowsOp(%s, %s)=%v want %v", c.role, opName(c.op), got, c.allow)
		}
	}
}
