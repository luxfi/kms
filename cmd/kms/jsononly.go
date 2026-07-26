package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// This service speaks JSON. Nothing else — no HTML, ever.
//
// That is not automatic. http.ServeMux writes an HTML body for its implicit
// trailing-slash redirect, http.Error writes text/plain, and its unmatched-route
// handler writes "404 page not found". A caller hitting a wrong path then reads
// a 200-shaped page or a bare string instead of a machine-readable error, which
// is precisely how a wrong URL went unnoticed against this host before: the
// embedded console answered everything with HTML, so a bad path looked fine.
//
// jsonOnly wraps the mux so every response carries application/json and a JSON
// body, whatever the handler underneath tried to write. Status and Location are
// untouched, so redirects still redirect — they just stop explaining themselves
// in HTML.
func jsonOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&jsonGuard{ResponseWriter: w}, r)
	})
}

type jsonGuard struct {
	http.ResponseWriter
	passthrough bool // handler already committed to JSON; leave its bytes alone
	wroteHeader bool
}

func (g *jsonGuard) WriteHeader(code int) {
	if g.wroteHeader {
		return
	}
	g.wroteHeader = true
	g.passthrough = strings.HasPrefix(g.Header().Get("Content-Type"), "application/json")
	if !g.passthrough {
		g.Header().Set("Content-Type", "application/json")
		g.Header().Del("Content-Length") // the replacement body is a different size
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *jsonGuard) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if g.passthrough {
		return g.ResponseWriter.Write(b)
	}
	// Whatever this was — redirect HTML, http.Error text — say it in JSON.
	// Report the caller's byte count so the handler sees a complete write.
	msg := strings.TrimSpace(string(b))
	if i := strings.IndexByte(msg, '<'); i == 0 {
		msg = http.StatusText(statusFromHeader(g.Header()))
	}
	_ = json.NewEncoder(g.ResponseWriter).Encode(map[string]string{"message": msg})
	return len(b), nil
}

// statusFromHeader recovers a usable message for a body we are discarding.
// Location present means a redirect; otherwise fall back to a generic error.
func statusFromHeader(h http.Header) int {
	if h.Get("Location") != "" {
		return http.StatusTemporaryRedirect
	}
	return http.StatusInternalServerError
}

// notFoundJSON is the unmatched-route handler. Registering "/" explicitly also
// stops ServeMux from falling back to its own text/plain 404.
func notFoundJSON(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]string{
		"message": "not found",
		"path":    r.URL.Path,
	})
}
