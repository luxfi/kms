package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// pkiTestDB spins up an in-memory ZapDB for the PKI handler tests.
func pkiTestDB(t *testing.T) *badger.DB {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true).WithLogger(nil))
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// pkiTestToken mints a valid org-scoped session token via the shared webAuth.
func pkiTestToken(t *testing.T, db *badger.DB) string {
	t.Helper()
	a := newWebAuth(webAuthSecret(db))
	tok, err := a.mint("user-1", "org-1", webSessionTTL)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

// TestPkiRegisterNoPanic ensures registering PKI routes alongside the other
// stable web-API surfaces does not trip a Go 1.22 ServeMux pattern conflict.
func TestPkiRegisterNoPanic(t *testing.T) {
	db := pkiTestDB(t)
	mux := http.NewServeMux()
	// Register the stable surfaces too, to catch cross-file pattern conflicts
	// (e.g. /v1/projects/{id}/... specificity vs api_projects.go).
	registerCoreAPI(mux, db, "default")
	registerProjectAPI(mux, db)
	registerSecretsAPI(mux, db)
	registerPkiAPI(mux, db) // must not panic
}

func TestPkiUnauthorized(t *testing.T) {
	db := pkiTestDB(t)
	mux := http.NewServeMux()
	registerPkiAPI(mux, db)

	req := httptest.NewRequest(http.MethodGet, "/v1/cert-manager/ca?projectId=org-1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestPkiCaCRUD(t *testing.T) {
	db := pkiTestDB(t)
	mux := http.NewServeMux()
	registerPkiAPI(mux, db)
	tok := pkiTestToken(t, db)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	// Empty list first.
	rec := do(http.MethodGet, "/v1/cert-manager/ca?projectId=proj-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list cas: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var listResp struct {
		CertificateAuthorities []map[string]any `json:"certificateAuthorities"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listResp)
	if len(listResp.CertificateAuthorities) != 0 {
		t.Fatalf("want empty cas, got %d", len(listResp.CertificateAuthorities))
	}

	// Create a CA.
	rec = do(http.MethodPost, "/v1/cert-manager/ca/internal",
		`{"projectId":"proj-1","name":"root-ca","type":"internal"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create ca: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var ca map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ca)
	caID, _ := ca["id"].(string)
	if caID == "" {
		t.Fatalf("create ca: missing id in %s", rec.Body.String())
	}
	if ca["status"] != "active" {
		t.Fatalf("create ca: want status active, got %v", ca["status"])
	}

	// Get it back by type+id.
	rec = do(http.MethodGet, "/v1/cert-manager/ca/internal/"+caID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get ca: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// List by type returns it.
	rec = do(http.MethodGet, "/v1/cert-manager/ca/internal?projectId=proj-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list by type: want 200, got %d", rec.Code)
	}
	var byType []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &byType)
	if len(byType) != 1 {
		t.Fatalf("list by type: want 1, got %d (%s)", len(byType), rec.Body.String())
	}

	// Project-scoped CA tab returns it under {cas:[...]}.
	rec = do(http.MethodGet, "/v1/projects/proj-1/cas", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("project cas: want 200, got %d", rec.Code)
	}
	var projCas struct {
		Cas []map[string]any `json:"cas"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &projCas)
	if len(projCas.Cas) != 1 {
		t.Fatalf("project cas: want 1, got %d", len(projCas.Cas))
	}

	// Internal-CA crypto stubs respond 200 with the empty shapes.
	rec = do(http.MethodGet, "/v1/cert-manager/ca/internal/"+caID+"/ca-certificates", "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("ca-certificates stub: want 200 [], got %d (%s)", rec.Code, rec.Body.String())
	}

	// Delete it.
	rec = do(http.MethodDelete, "/v1/cert-manager/ca/internal/"+caID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete ca: want 200, got %d", rec.Code)
	}
	rec = do(http.MethodGet, "/v1/cert-manager/ca/internal/"+caID, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get deleted ca: want 404, got %d", rec.Code)
	}
}

func TestPkiProfilePolicyCollectionCRUD(t *testing.T) {
	db := pkiTestDB(t)
	mux := http.NewServeMux()
	registerPkiAPI(mux, db)
	tok := pkiTestToken(t, db)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	// Certificate profile create -> wrapped under {certificateProfile}.
	rec := do(http.MethodPost, "/v1/cert-manager/certificate-profiles",
		`{"projectId":"proj-2","slug":"web","certificatePolicyId":"pol-1","enrollmentType":"api","issuerType":"ca"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create profile: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var pr struct {
		CertificateProfile map[string]any `json:"certificateProfile"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pr)
	if pr.CertificateProfile["id"] == nil {
		t.Fatalf("create profile: missing id")
	}
	// Lookup by slug.
	rec = do(http.MethodGet, "/v1/cert-manager/certificate-profiles/slug/web?projectId=proj-2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("profile by slug: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Policy create.
	rec = do(http.MethodPost, "/v1/cert-manager/certificate-policies",
		`{"projectId":"proj-2","name":"strict"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create policy: want 200, got %d", rec.Code)
	}

	// Collection create + item add.
	rec = do(http.MethodPost, "/v1/pki/collections",
		`{"projectId":"proj-2","name":"coll","description":"d"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create collection: want 200, got %d", rec.Code)
	}
	var coll map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &coll)
	cid, _ := coll["id"].(string)
	rec = do(http.MethodPost, "/v1/pki/collections/"+cid+"/items",
		`{"type":"certificate","itemId":"abc"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add item: want 200, got %d", rec.Code)
	}
	rec = do(http.MethodGet, "/v1/pki/collections/"+cid+"/items", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list items: want 200, got %d", rec.Code)
	}
	var items struct {
		CollectionItems []map[string]any `json:"collectionItems"`
		TotalCount      int              `json:"totalCount"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &items)
	if items.TotalCount != 1 || len(items.CollectionItems) != 1 {
		t.Fatalf("list items: want 1, got %d", items.TotalCount)
	}
}

func TestPkiSubscriberByName(t *testing.T) {
	db := pkiTestDB(t)
	mux := http.NewServeMux()
	registerPkiAPI(mux, db)
	tok := pkiTestToken(t, db)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	rec := do(http.MethodPost, "/v1/pki/subscribers",
		`{"projectId":"proj-3","name":"svc-a","commonName":"svc-a.local","caId":"ca-1","subjectAlternativeNames":[],"keyUsages":[],"extendedKeyUsages":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create subscriber: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	// Fetch by name (scoped to project).
	rec = do(http.MethodGet, "/v1/pki/subscribers/svc-a?projectId=proj-3", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get subscriber: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var sub map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)
	if sub["name"] != "svc-a" || sub["status"] != "active" {
		t.Fatalf("subscriber shape wrong: %s", rec.Body.String())
	}
	// Issue-certificate stub returns the empty cert shape.
	rec = do(http.MethodPost, "/v1/pki/subscribers/svc-a/issue-certificate", `{"projectId":"proj-3"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("issue cert stub: want 200, got %d", rec.Code)
	}
}

func TestPkiAlertsV2AndSyncsEmptyTabs(t *testing.T) {
	db := pkiTestDB(t)
	mux := http.NewServeMux()
	registerPkiAPI(mux, db)
	tok := pkiTestToken(t, db)

	do := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	// v2 alerts list wrapper.
	rec := do(http.MethodGet, "/v1/cert-manager/alerts?projectId=proj-4")
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts v2 list: want 200, got %d", rec.Code)
	}
	var al struct {
		Alerts []any `json:"alerts"`
		Total  int   `json:"total"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &al)
	if al.Alerts == nil {
		t.Fatalf("alerts v2 list: alerts must be [] not null")
	}

	// sync options + list (empty).
	rec = do(http.MethodGet, "/v1/cert-manager/syncs/options")
	if rec.Code != http.StatusOK {
		t.Fatalf("sync options: want 200, got %d", rec.Code)
	}
	rec = do(http.MethodGet, "/v1/cert-manager/syncs?projectId=proj-4")
	if rec.Code != http.StatusOK {
		t.Fatalf("syncs list: want 200, got %d", rec.Code)
	}
	var sl struct {
		PkiSyncs []any `json:"pkiSyncs"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sl)
	if sl.PkiSyncs == nil {
		t.Fatalf("syncs list: pkiSyncs must be [] not null")
	}
}
