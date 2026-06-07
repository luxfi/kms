package mpcrek

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luxfi/kms/pkg/mpc"
)

// fakeDecrypter implements MPCDecrypter for tests.
type fakeDecrypter struct {
	plaintext []byte
	err       error
	closed    bool

	wantKeyID string
	gotKeyID  string
}

func (f *fakeDecrypter) Decrypt(_ context.Context, keyID string, _ []byte) (*mpc.DecryptResult, error) {
	f.gotKeyID = keyID
	if f.err != nil {
		return nil, f.err
	}
	return &mpc.DecryptResult{Plaintext: f.plaintext}, nil
}

func (f *fakeDecrypter) Close() { f.closed = true }

func withDialer(t *testing.T, fake MPCDecrypter) func() {
	t.Helper()
	prev := dialer
	dialer = func(_, _ string) (MPCDecrypter, error) { return fake, nil }
	return func() { dialer = prev }
}

func withDialErr(t *testing.T, err error) func() {
	t.Helper()
	prev := dialer
	dialer = func(_, _ string) (MPCDecrypter, error) { return nil, err }
	return func() { dialer = prev }
}

func TestBootstrap_ValidConfig_Returns32Bytes(t *testing.T) {
	rek := make([]byte, 32)
	for i := range rek {
		rek[i] = byte(i + 1)
	}
	fake := &fakeDecrypter{plaintext: rek}
	restore := withDialer(t, fake)
	defer restore()

	got, err := Bootstrap(context.Background(), Config{
		Endpoint: "mpc-0.lux-mpc.svc:9999",
		KeyID:    "kms/rek/v1",
		NodeID:   "kms-0",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("len(REK) = %d, want 32", len(got))
	}
	for i, b := range got {
		if b != byte(i+1) {
			t.Fatalf("REK byte %d = %#x, want %#x", i, b, i+1)
		}
	}
	if fake.gotKeyID != "kms/rek/v1" {
		t.Errorf("decrypt called with keyID=%q, want %q", fake.gotKeyID, "kms/rek/v1")
	}
	if !fake.closed {
		t.Error("MPC client was not closed after Bootstrap")
	}
}

func TestBootstrap_Validate(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty endpoint", Config{KeyID: "k"}},
		{"empty keyID", Config{Endpoint: "e"}},
		{"both empty", Config{}},
		{"whitespace endpoint", Config{Endpoint: "   ", KeyID: "k"}},
		{"whitespace keyID", Config{Endpoint: "e", KeyID: "  "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Bootstrap(context.Background(), tc.cfg)
			if !errors.Is(err, ErrUnconfigured) {
				t.Fatalf("err = %v, want ErrUnconfigured", err)
			}
		})
	}
}

func TestBootstrap_RejectsWrongLength(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"too short", 16},
		{"too long", 64},
		{"off by one", 31},
		{"off by one over", 33},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeDecrypter{plaintext: make([]byte, tc.n)}
			// Make non-zero so we don't also trip the zero check.
			for i := range fake.plaintext {
				fake.plaintext[i] = 0xAB
			}
			restore := withDialer(t, fake)
			defer restore()

			_, err := Bootstrap(context.Background(), Config{
				Endpoint: "e",
				KeyID:    "k",
			})
			if !errors.Is(err, ErrBadREKLength) {
				t.Fatalf("err = %v, want ErrBadREKLength", err)
			}
		})
	}
}

func TestBootstrap_RejectsAllZeroREK(t *testing.T) {
	fake := &fakeDecrypter{plaintext: make([]byte, 32)} // all zero
	restore := withDialer(t, fake)
	defer restore()

	_, err := Bootstrap(context.Background(), Config{
		Endpoint: "e",
		KeyID:    "k",
	})
	if !errors.Is(err, ErrZeroREK) {
		t.Fatalf("err = %v, want ErrZeroREK", err)
	}
}

func TestBootstrap_PropagatesDialError(t *testing.T) {
	dialErr := errors.New("connection refused")
	restore := withDialErr(t, dialErr)
	defer restore()

	_, err := Bootstrap(context.Background(), Config{
		Endpoint: "e",
		KeyID:    "k",
	})
	if err == nil || !errors.Is(err, dialErr) {
		t.Fatalf("err = %v, want wrap of %v", err, dialErr)
	}
}

func TestBootstrap_PropagatesDecryptError(t *testing.T) {
	decErr := errors.New("threshold quorum unmet")
	fake := &fakeDecrypter{err: decErr}
	restore := withDialer(t, fake)
	defer restore()

	_, err := Bootstrap(context.Background(), Config{
		Endpoint: "e",
		KeyID:    "k",
	})
	if err == nil || !errors.Is(err, decErr) {
		t.Fatalf("err = %v, want wrap of %v", err, decErr)
	}
}

func TestBootstrap_DefaultTimeout(t *testing.T) {
	// Default timeout 10s should not block tests; just confirm Bootstrap
	// completes when Timeout is unset.
	rek := make([]byte, 32)
	for i := range rek {
		rek[i] = 1
	}
	fake := &fakeDecrypter{plaintext: rek}
	restore := withDialer(t, fake)
	defer restore()

	got, err := Bootstrap(context.Background(), Config{
		Endpoint: "e",
		KeyID:    "k",
		// Timeout intentionally zero.
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("len(REK) = %d", len(got))
	}
}

func TestZero_OverwritesAllBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("b[%d] = %#x, want 0", i, v)
		}
	}
}

func TestZero_EmptySliceIsSafe(t *testing.T) {
	// Should not panic.
	Zero(nil)
	Zero([]byte{})
}

func TestZero_OnReturnedREK_ForensicCheck(t *testing.T) {
	// Round-trip: get a REK, zero it, verify it's all-zero.
	rek := make([]byte, 32)
	for i := range rek {
		rek[i] = 0xFF
	}
	fake := &fakeDecrypter{plaintext: rek}
	restore := withDialer(t, fake)
	defer restore()

	got, err := Bootstrap(context.Background(), Config{Endpoint: "e", KeyID: "k"})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	Zero(got)
	for i, v := range got {
		if v != 0 {
			t.Errorf("zeroed[%d] = %#x", i, v)
		}
	}
}

func TestBootstrap_NilResultFromDecrypter(t *testing.T) {
	// A misbehaving fake returns (nil, nil). Bootstrap must reject this.
	fake := &nilResultDecrypter{}
	restore := withDialer(t, fake)
	defer restore()

	_, err := Bootstrap(context.Background(), Config{Endpoint: "e", KeyID: "k"})
	if err == nil {
		t.Fatal("Bootstrap returned nil error on nil DecryptResult")
	}
}

type nilResultDecrypter struct{}

func (nilResultDecrypter) Decrypt(_ context.Context, _ string, _ []byte) (*mpc.DecryptResult, error) {
	return nil, nil
}
func (nilResultDecrypter) Close() {}
