package iamclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Test fixture: a minimal IAM stub that handles
// POST /oauth/token with grant_type=client_credentials.
// ----------------------------------------------------------------------

type fakeIAM struct {
	*httptest.Server
	calls atomic.Int32
	// allow overrides per-test
	respond func(w http.ResponseWriter, r *http.Request)
}

func newFakeIAM(t *testing.T) *fakeIAM {
	t.Helper()
	f := &fakeIAM{}
	f.respond = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			http.Error(w, "no basic", http.StatusUnauthorized)
			return
		}
		_, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
		if err != nil {
			http.Error(w, "bad b64", http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, "wrong grant", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("tok-%d", f.calls.Add(1)),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.respond(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func TestIAMClient_MintHappyPath(t *testing.T) {
	srv := newFakeIAM(t)
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tok, err := c.Mint(context.Background(), "liquid-mpc")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(tok, "tok-") {
		t.Fatalf("token=%q want tok-*", tok)
	}
}

func TestIAMClient_CacheReuses(t *testing.T) {
	srv := newFakeIAM(t)
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := c.Mint(context.Background(), "liquid-mpc"); err != nil {
			t.Fatalf("Mint[%d]: %v", i, err)
		}
	}
	if got := srv.calls.Load(); got != 1 {
		t.Fatalf("expected 1 IAM call, got %d", got)
	}
}

func TestIAMClient_PerAudienceCache(t *testing.T) {
	srv := newFakeIAM(t)
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Mint(context.Background(), "liquid-mpc"); err != nil {
		t.Fatalf("Mint a: %v", err)
	}
	if _, err := c.Mint(context.Background(), "liquid-bd"); err != nil {
		t.Fatalf("Mint b: %v", err)
	}
	if got := srv.calls.Load(); got != 2 {
		t.Fatalf("expected 2 IAM calls (one per audience), got %d", got)
	}
}

func TestIAMClient_Invalidate(t *testing.T) {
	srv := newFakeIAM(t)
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Mint(context.Background(), "liquid-mpc"); err != nil {
		t.Fatalf("Mint 1: %v", err)
	}
	c.Invalidate("liquid-mpc")
	if _, err := c.Mint(context.Background(), "liquid-mpc"); err != nil {
		t.Fatalf("Mint 2: %v", err)
	}
	if got := srv.calls.Load(); got != 2 {
		t.Fatalf("expected 2 IAM calls after Invalidate, got %d", got)
	}
}

func TestIAMClient_RefreshOnExpiry(t *testing.T) {
	srv := newFakeIAM(t)
	clock := time.Unix(1_000_000, 0)
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
		EarlyRefresh: 60 * time.Second,
		Now:          func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Mint(context.Background(), "liquid-mpc"); err != nil {
		t.Fatalf("Mint 1: %v", err)
	}
	// IAM said expires_in=3600. With EarlyRefresh=60s the cache entry
	// is valid until clock + 3540s.
	clock = clock.Add(3539 * time.Second) // still cached
	if _, err := c.Mint(context.Background(), "liquid-mpc"); err != nil {
		t.Fatalf("Mint 2 (still cached): %v", err)
	}
	if got := srv.calls.Load(); got != 1 {
		t.Fatalf("expected 1 IAM call (still cached), got %d", got)
	}
	clock = clock.Add(2 * time.Second) // tipping past EarlyRefresh
	if _, err := c.Mint(context.Background(), "liquid-mpc"); err != nil {
		t.Fatalf("Mint 3 (refresh): %v", err)
	}
	if got := srv.calls.Load(); got != 2 {
		t.Fatalf("expected 2 IAM calls after early refresh, got %d", got)
	}
}

func TestIAMClient_ConfigValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing IAMBaseURL", Config{ClientID: "x", ClientSecret: "y"}},
		{"missing ClientID", Config{IAMBaseURL: "http://x", ClientSecret: "y"}},
		{"missing ClientSecret", Config{IAMBaseURL: "http://x", ClientID: "y"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewClient(tc.cfg); err == nil {
				t.Fatalf("NewClient: expected error")
			}
		})
	}
}

func TestIAMClient_ServerError(t *testing.T) {
	srv := newFakeIAM(t)
	srv.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"bad creds"}`))
	}
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Mint(context.Background(), "liquid-mpc")
	if err == nil || !errors.Is(err, ErrTokenRequest) {
		t.Fatalf("expected ErrTokenRequest, got %v", err)
	}
}

func TestIAMClient_OAuthError(t *testing.T) {
	srv := newFakeIAM(t)
	srv.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"audience not allowed"}`))
	}
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Mint(context.Background(), "liquid-mpc")
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("expected invalid_grant error, got %v", err)
	}
}

func TestIAMClient_EmptyToken(t *testing.T) {
	srv := newFakeIAM(t)
	srv.respond = func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "",
			"expires_in":   3600,
		})
	}
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Mint(context.Background(), "liquid-mpc")
	if err == nil || !errors.Is(err, ErrTokenEmpty) {
		t.Fatalf("expected ErrTokenEmpty, got %v", err)
	}
}

func TestIAMClient_AudienceRequired(t *testing.T) {
	srv := newFakeIAM(t)
	c, err := NewClient(Config{
		IAMBaseURL:   srv.URL,
		ClientID:     "liquid-kms",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Mint(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty audience")
	}
}
