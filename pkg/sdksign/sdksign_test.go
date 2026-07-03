// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sdksign

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/store"
	badger "github.com/luxfi/zapdb"
)

// fakeMPC records Sign delegations and returns a canned signature. It
// implements keys.MPCBackend (Signer + Encryptor). It does NOT fake
// threshold math — it only proves the manager delegated the right
// (walletID, keyType, message).
type fakeMPC struct {
	lastSign mpc.SignRequest
	signN    int
}

func (f *fakeMPC) Keygen(context.Context, string, mpc.KeygenRequest) (*mpc.KeygenResult, error) {
	return &mpc.KeygenResult{}, nil
}
func (f *fakeMPC) Sign(_ context.Context, req mpc.SignRequest) (*mpc.SignResult, error) {
	f.lastSign = req
	f.signN++
	return &mpc.SignResult{Signature: "canned-sig", R: "0xr", S: "0xs"}, nil
}
func (f *fakeMPC) Reshare(context.Context, string, mpc.ReshareRequest) error { return nil }
func (f *fakeMPC) GetWallet(context.Context, string) (*mpc.Wallet, error) {
	return &mpc.Wallet{}, nil
}
func (f *fakeMPC) Status(context.Context) (*mpc.ClusterStatus, error) {
	return &mpc.ClusterStatus{Ready: true}, nil
}
func (f *fakeMPC) Encrypt(context.Context, string, []byte) (*mpc.EncryptResult, error) {
	return &mpc.EncryptResult{}, nil
}
func (f *fakeMPC) Decrypt(context.Context, string, []byte) (*mpc.DecryptResult, error) {
	return &mpc.DecryptResult{}, nil
}

func newManager(t *testing.T) (*keys.Manager, *store.Store, *fakeMPC) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("zapdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st, err := store.New(db)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	f := &fakeMPC{}
	return keys.NewManager(f, st, "vault-1"), st, f
}

// TestSign_DelegatesToMPC proves Backend.Sign routes to the right MPC
// wallet for each scheme and propagates the signature. No key material
// is held locally.
func TestSign_DelegatesToMPC(t *testing.T) {
	mgr, st, f := newManager(t)
	if err := st.Put(&keys.ValidatorKeySet{
		ValidatorID:    "val-1",
		BLSWalletID:    "w-bls",
		CoronaWalletID: "w-corona",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	b := New(mgr)

	msg := []byte("header")
	res, err := b.Sign(context.Background(), "val-1", "bls", msg)
	if err != nil {
		t.Fatalf("bls sign: %v", err)
	}
	if f.lastSign.WalletID != "w-bls" || string(f.lastSign.Message) != "header" {
		t.Fatalf("bls delegated wrong: %+v", f.lastSign)
	}
	if res.Signature != "canned-sig" || res.R != "0xr" {
		t.Fatalf("bls result not propagated: %+v", res)
	}

	if _, err := b.Sign(context.Background(), "val-1", "corona", msg); err != nil {
		t.Fatalf("corona sign: %v", err)
	}
	if f.lastSign.WalletID != "w-corona" {
		t.Fatalf("corona delegated to wrong wallet: %+v", f.lastSign)
	}
	if f.signN != 2 {
		t.Fatalf("sign calls=%d want 2", f.signN)
	}
}

func TestSign_UnsupportedScheme(t *testing.T) {
	mgr, st, _ := newManager(t)
	_ = st.Put(&keys.ValidatorKeySet{ValidatorID: "val-1", BLSWalletID: "w"})
	b := New(mgr)
	if _, err := b.Sign(context.Background(), "val-1", "rsa", []byte("m")); err == nil {
		t.Fatalf("expected error for unsupported scheme")
	}
}

// TestVerify_Corona_Ed25519 exercises the REAL ed25519 verify path with a
// real keypair — a valid signature verifies, a tampered one does not.
func TestVerify_Corona_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	mgr, st, _ := newManager(t)
	if err := st.Put(&keys.ValidatorKeySet{
		ValidatorID:     "val-1",
		CoronaPublicKey: hex.EncodeToString(pub),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	b := New(mgr)

	msg := []byte("consensus-round-42")
	sig := ed25519.Sign(priv, msg)

	ok, err := b.Verify(context.Background(), "val-1", "corona", msg, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("valid signature must verify")
	}

	// Tamper the signature → must NOT verify (and no error).
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xFF
	ok, err = b.Verify(context.Background(), "val-1", "corona", msg, bad)
	if err != nil {
		t.Fatalf("verify(bad): %v", err)
	}
	if ok {
		t.Fatalf("tampered signature must NOT verify")
	}

	// Tamper the message → must NOT verify.
	ok, _ = b.Verify(context.Background(), "val-1", "corona", []byte("other"), sig)
	if ok {
		t.Fatalf("signature over a different message must NOT verify")
	}
}

// TestVerify_BLS_Delegated pins the documented capability boundary.
func TestVerify_BLS_Delegated(t *testing.T) {
	mgr, st, _ := newManager(t)
	_ = st.Put(&keys.ValidatorKeySet{ValidatorID: "val-1", BLSPublicKey: "abcd"})
	b := New(mgr)
	_, err := b.Verify(context.Background(), "val-1", "bls", []byte("m"), []byte("s"))
	if !errors.Is(err, ErrVerifyBLSDelegated) {
		t.Fatalf("bls verify err=%v want ErrVerifyBLSDelegated", err)
	}
}

func TestVerify_UnknownValidator(t *testing.T) {
	mgr, _, _ := newManager(t)
	b := New(mgr)
	if _, err := b.Verify(context.Background(), "nope", "corona", []byte("m"), []byte("s")); err == nil {
		t.Fatalf("expected error for unknown validator")
	}
}
