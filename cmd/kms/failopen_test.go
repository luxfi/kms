// Tests for the boot-time MPC fail-open behaviour added in v1.8.2.
//
// Before v1.8.2, KMS called log.Fatalf on any MPC ZAP init or status
// failure — a transient MPC outage took the secrets surface down with
// it. v1.8.2 logs a warning, sets mpcAvailable=false, and lets the
// secrets-only routes keep serving. /v1/kms/keys/* responds 503 with a
// re-probe attempt so the same pod can recover when MPC comes back up.
//
// These tests pin both behaviours: the 503 with re-probe, and the
// transparent recovery once a re-probe succeeds.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
)

// fakeBackend is a minimal MPCBackend used only by the route tests.
// statusErr is consulted on every call so a single test can transition
// from "down" to "up" and verify the re-probe heals the cached flag.
//
// statusErr uses a sync.Mutex + plain error rather than atomic.Value
// because atomic.Value rejects typed-nil error; the route handlers are
// sequential per request so contention is negligible.
type fakeBackend struct {
	statusCalls atomic.Int32

	mu        sync.Mutex
	statusErr error
}

func (f *fakeBackend) currentErr() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statusErr
}

func (f *fakeBackend) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusErr = err
}

func (f *fakeBackend) Status(ctx context.Context) (*mpc.ClusterStatus, error) {
	f.statusCalls.Add(1)
	if err := f.currentErr(); err != nil {
		return nil, err
	}
	return &mpc.ClusterStatus{Ready: true, ConnectedPeers: 3, ExpectedPeers: 3, Mode: "consensus"}, nil
}

func (f *fakeBackend) Keygen(context.Context, string, mpc.KeygenRequest) (*mpc.KeygenResult, error) {
	return nil, errors.New("keygen unused in failopen tests")
}
func (f *fakeBackend) Sign(context.Context, mpc.SignRequest) (*mpc.SignResult, error) {
	return nil, errors.New("sign unused in failopen tests")
}
func (f *fakeBackend) Reshare(context.Context, string, mpc.ReshareRequest) error {
	return errors.New("reshare unused in failopen tests")
}
func (f *fakeBackend) GetWallet(context.Context, string) (*mpc.Wallet, error) {
	return nil, errors.New("getwallet unused in failopen tests")
}
func (f *fakeBackend) Encrypt(context.Context, string, []byte) (*mpc.EncryptResult, error) {
	return nil, errors.New("encrypt unused in failopen tests")
}
func (f *fakeBackend) Decrypt(context.Context, string, []byte) (*mpc.DecryptResult, error) {
	return nil, errors.New("decrypt unused in failopen tests")
}

// requireMPC must short-circuit signing routes with 503 and a structured
// error body when MPC is unreachable. Without this, a degraded KMS would
// quietly invoke MPC and surface 500s with cryptic ZAP errors instead of
// the well-known "secrets-only" mode signal callers branch on.
func TestRegisterKMSRoutes_SignReturns503WhenMPCDown(t *testing.T) {
	backend := &fakeBackend{}
	backend.setErr(errors.New("connection reset by peer"))

	mgr := keys.NewManager(backend, nil, "vault-1")
	mux := http.NewServeMux()
	mpcAvailable := false
	registerKMSRoutes(mux, mgr, backend, &mpcAvailable)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/kms/keys/v-1/sign", "application/json", strings.NewReader(`{"key_type":"bls","message":"aGVsbG8="}`))
	if err != nil {
		t.Fatalf("post sign: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "mpc unreachable" {
		t.Errorf("error field: got %q want %q", body["error"], "mpc unreachable")
	}
	if body["mode"] != "secrets-only" {
		t.Errorf("mode field: got %q want secrets-only", body["mode"])
	}
	if !strings.Contains(body["detail"], "connection reset by peer") {
		t.Errorf("detail field: got %q; want underlying error included", body["detail"])
	}
}

// keygen + rotate must also gate on requireMPC. A regression that
// exposes either of these endpoints to a down MPC is a 500 instead of a
// 503 — a different SLO / on-call signal — so this test pins both.
func TestRegisterKMSRoutes_KeygenAndRotateAlsoGated(t *testing.T) {
	backend := &fakeBackend{}
	backend.setErr(errors.New("dial tcp: i/o timeout"))

	mgr := keys.NewManager(backend, nil, "vault-1")
	mux := http.NewServeMux()
	mpcAvailable := false
	registerKMSRoutes(mux, mgr, backend, &mpcAvailable)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	keygenResp, err := http.Post(srv.URL+"/v1/kms/keys/generate", "application/json",
		strings.NewReader(`{"validator_id":"v-1","threshold":2,"parties":3}`))
	if err != nil {
		t.Fatalf("post generate: %v", err)
	}
	defer keygenResp.Body.Close()
	if keygenResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("generate status: got %d want 503", keygenResp.StatusCode)
	}

	rotateResp, err := http.Post(srv.URL+"/v1/kms/keys/v-1/rotate", "application/json",
		strings.NewReader(`{"new_threshold":3}`))
	if err != nil {
		t.Fatalf("post rotate: %v", err)
	}
	defer rotateResp.Body.Close()
	if rotateResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("rotate status: got %d want 503", rotateResp.StatusCode)
	}
}

// requireMPC re-probes MPC on each call so a pod that booted into
// degraded mode can recover transparently when MPC comes back. The
// healed mpcAvailable flag flips to true and subsequent calls skip the
// re-probe entirely. This is the second-half guarantee the operator
// runbook documents — without it, a single MPC blip would require a KMS
// pod restart to clear the degraded state.
func TestRegisterKMSRoutes_RecoversAfterMPCComesUp(t *testing.T) {
	backend := &fakeBackend{}
	backend.setErr(errors.New("temporary outage"))

	mgr := keys.NewManager(backend, nil, "vault-1")
	mux := http.NewServeMux()
	mpcAvailable := false
	registerKMSRoutes(mux, mgr, backend, &mpcAvailable)

	// Wrap with a recovery middleware so the inner mgr.SignWithBLS panic
	// (nil store, expected for this minimal test rig) doesn't kill the
	// test server. We only care that the request crossed requireMPC; the
	// status code is enough signal.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		mux.ServeHTTP(w, r)
	}))
	defer srv.Close()

	// First call: still down, expect 503 + a re-probe.
	resp1, err := http.Post(srv.URL+"/v1/kms/keys/v-1/sign", "application/json",
		strings.NewReader(`{"key_type":"bls","message":"aGVsbG8="}`))
	if err != nil {
		t.Fatalf("first post: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("first call: got %d want 503", resp1.StatusCode)
	}
	if got := backend.statusCalls.Load(); got != 1 {
		t.Fatalf("status probe count after first call: got %d want 1", got)
	}
	if mpcAvailable {
		t.Fatal("mpcAvailable must remain false after a failed re-probe")
	}

	// MPC comes back. Next call probes once, flips the flag, then runs
	// the actual signing handler (which fails inside the fake — the
	// route reaches mgr.SignWithBLS and returns 500 from the fake's
	// Sign error). Either way the request crossed requireMPC, which is
	// what we're pinning.
	backend.setErr(nil)
	resp2, err := http.Post(srv.URL+"/v1/kms/keys/v-1/sign", "application/json",
		strings.NewReader(`{"key_type":"bls","message":"aGVsbG8="}`))
	if err != nil {
		t.Fatalf("second post: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusServiceUnavailable {
		t.Fatalf("second call: got 503 after MPC recovered; want any non-503")
	}
	if got := backend.statusCalls.Load(); got != 2 {
		t.Fatalf("status probe count after recovery: got %d want 2", got)
	}
	if !mpcAvailable {
		t.Fatal("mpcAvailable must flip to true after a successful re-probe")
	}

	// Third call: flag is now true, requireMPC must skip the re-probe.
	resp3, err := http.Post(srv.URL+"/v1/kms/keys/v-1/sign", "application/json",
		strings.NewReader(`{"key_type":"bls","message":"aGVsbG8="}`))
	if err != nil {
		t.Fatalf("third post: %v", err)
	}
	resp3.Body.Close()
	if got := backend.statusCalls.Load(); got != 2 {
		t.Fatalf("status probe count must NOT increase after flag is up: got %d want 2", got)
	}
}

// healthHandler must report status=ok when secrets-only mode is the
// intended config (vaultID empty), and degrade to status=degraded when
// MPC was wired in but is unreachable.
func TestHealthHandler(t *testing.T) {
	cases := []struct {
		name         string
		vaultID      string
		mpcAvailable *bool
		wantStatus   string
		wantMPCField bool
	}{
		{"secrets-only mode", "", nil, "ok", false},
		{"mpc up", "vault-1", boolp(true), "ok", false},
		{"mpc down", "vault-1", boolp(false), "degraded", true},
		{"mpc nil flag treated as down", "vault-1", nil, "degraded", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := healthHandler(c.vaultID, c.mpcAvailable)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			if rr.Code != http.StatusOK {
				t.Errorf("status code: got %d want 200", rr.Code)
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body["status"] != c.wantStatus {
				t.Errorf("status field: got %q want %q", body["status"], c.wantStatus)
			}
			_, hasMPC := body["mpc"]
			if hasMPC != c.wantMPCField {
				t.Errorf("mpc field present: got %v want %v", hasMPC, c.wantMPCField)
			}
		})
	}
}

func boolp(v bool) *bool { return &v }

// nil pointer must short-circuit cleanly; this is the legacy code path
// (mpcAvailable wasn't passed in earlier versions). Keep this test as a
// guard for any future caller that passes nil.
func TestRegisterKMSRoutes_NilFlagFallsBackToProbe(t *testing.T) {
	backend := &fakeBackend{}
	backend.setErr(errors.New("down"))

	mgr := keys.NewManager(backend, nil, "vault-1")
	mux := http.NewServeMux()
	registerKMSRoutes(mux, mgr, backend, nil)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/kms/keys/v-1/sign", "application/json",
		strings.NewReader(`{"key_type":"bls","message":"aGVsbG8="}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("nil flag: got %d want 503", resp.StatusCode)
	}
}
