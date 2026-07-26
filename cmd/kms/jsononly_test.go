package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The service must never answer in HTML. It used to embed a console SPA that
// caught every unmatched path, so a wrong URL came back 200 with a web page —
// which is how a caller pointed at a route this server does not have went on
// believing it worked. These pin the replacement behaviour.

func TestJSONOnly_UnmatchedPathIsJSON404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", notFoundJSON)

	rec := httptest.NewRecorder()
	jsonOnly(mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v3/secrets/raw", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
	}
	if body["path"] != "/api/v3/secrets/raw" {
		t.Errorf("path = %q, want the requested path", body["path"])
	}
}

func TestJSONOnly_RedirectBodyIsNotHTML(t *testing.T) {
	// ServeMux redirects /v1/kms/orgs -> /v1/kms/orgs/ with an HTML body.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/orgs/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
	})

	rec := httptest.NewRecorder()
	jsonOnly(mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/kms/orgs", nil))

	if strings.Contains(rec.Body.String(), "<a href") || strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("redirect body contains HTML: %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, must never be HTML", ct)
	}
	if loc := rec.Header().Get("Location"); loc == "" {
		t.Error("Location header dropped — the redirect must still redirect")
	}
}

func TestJSONOnly_PlainTextErrorBecomesJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "something broke", http.StatusInternalServerError) // text/plain
	})

	rec := httptest.NewRecorder()
	jsonOnly(mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
	}
	if body["message"] != "something broke" {
		t.Errorf("message = %q, want the handler's message preserved", body["message"])
	}
}

func TestJSONOnly_JSONHandlersPassThroughByteForByte(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/kms/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "n": 1})
	})

	rec := httptest.NewRecorder()
	jsonOnly(mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/kms/status", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
	}
	if body["status"] != "ok" || body["n"] != float64(1) {
		t.Errorf("handler payload altered: %v", body)
	}
}
