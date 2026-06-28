package main

import (
	"fmt"
	"net/http"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// safeRegister runs one register func and returns any panic (Go 1.22 ServeMux
// raises a conflict panic on overlapping/duplicate patterns) as an error.
func safeRegister(name string, fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s: %v", name, r)
		}
	}()
	fn()
	return nil
}

// TestAllRegisterNoDuplicateRoutes mirrors main.go's registration sequence:
// every register<Area>API func is invoked against ONE ServeMux. A conflicting
// pattern panics at registration time, so this catches cross-area route
// collisions that the per-area tests (each on their own mux) cannot.
func TestAllRegisterNoDuplicateRoutes(t *testing.T) {
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	areas := []struct {
		name string
		fn   func()
	}{
		{"core", func() { registerCoreAPI(mux, db, "") }},
		{"projects", func() { registerProjectAPI(mux, db) }},
		{"secrets", func() { registerSecretsAPI(mux, db) }},
		{"identities", func() { registerIdentitiesAPI(mux, db) }},
		{"orgmembers", func() { registerOrgMembersAPI(mux, db) }},
		{"groupsscim", func() { registerGroupsScimAPI(mux, db) }},
		{"tokens", func() { registerTokensAPI(mux, db) }},
		{"secretmeta", func() { registerSecretMetaAPI(mux, db) }},
		{"dynrotation", func() { registerDynRotationAPI(mux, db) }},
		{"syncsconn", func() { registerSyncsConnAPI(mux, db) }},
		{"pki", func() { registerPkiAPI(mux, db) }},
		{"ssh", func() { registerSshAPI(mux, db) }},
		{"pam", func() { registerPamAPI(mux, db) }},
		{"aimcp", func() { registerAiMcpAPI(mux, db) }},
		{"kmskmip", func() { registerKmsKmipAPI(mux, db) }},
		{"approvals", func() { registerApprovalsAPI(mux, db) }},
		{"auditscan", func() { registerAuditScanAPI(mux, db) }},
		{"authconfig", func() { registerAuthConfigAPI(mux, db) }},
		{"misc", func() { registerMiscAPI(mux, db) }},
	}
	var failed bool
	for _, a := range areas {
		if err := safeRegister(a.name, a.fn); err != nil {
			failed = true
			t.Errorf("CONFLICT %v", err)
		}
	}
	if failed {
		t.FailNow()
	}
}
