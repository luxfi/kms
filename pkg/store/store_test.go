package store

import (
	"testing"
	"time"

	"github.com/hanzoai/base/tests"
	"github.com/luxfi/kms/pkg/keys"
)

func testApp(t *testing.T) *tests.TestApp {
	t.Helper()
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Cleanup() })
	return app
}

func TestPutAndGet(t *testing.T) {
	s, err := New(testApp(t))
	if err != nil {
		t.Fatal(err)
	}

	ks := &keys.ValidatorKeySet{
		ValidatorID:       "val-1",
		BLSWalletID:       "bls-w-1",
		RingtailWalletID:  "rt-w-1",
		BLSPublicKey:      "04aabb",
		RingtailPublicKey: "edpub1",
		Threshold:         3,
		Parties:           5,
		Status:            "active",
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	if err := s.Put(ks); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get("val-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.BLSWalletID != "bls-w-1" {
		t.Errorf("expected bls-w-1, got %s", got.BLSWalletID)
	}
	if got.RingtailPublicKey != "edpub1" {
		t.Errorf("expected edpub1, got %s", got.RingtailPublicKey)
	}
}

func TestPutDuplicate(t *testing.T) {
	s, err := New(testApp(t))
	if err != nil {
		t.Fatal(err)
	}

	ks := &keys.ValidatorKeySet{ValidatorID: "val-1"}
	if err := s.Put(ks); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ks); err != ErrAlreadyExists {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestGetNotFound(t *testing.T) {
	s, err := New(testApp(t))
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.Get("nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	s, err := New(testApp(t))
	if err != nil {
		t.Fatal(err)
	}

	s.Put(&keys.ValidatorKeySet{ValidatorID: "val-1"})
	s.Put(&keys.ValidatorKeySet{ValidatorID: "val-2"})

	list := s.List()
	if len(list) != 2 {
		t.Errorf("expected 2, got %d", len(list))
	}
}

func TestUpdate(t *testing.T) {
	s, err := New(testApp(t))
	if err != nil {
		t.Fatal(err)
	}

	ks := &keys.ValidatorKeySet{ValidatorID: "val-1", Threshold: 3}
	s.Put(ks)

	ks.Threshold = 4
	if err := s.Update(ks); err != nil {
		t.Fatal(err)
	}

	got, _ := s.Get("val-1")
	if got.Threshold != 4 {
		t.Errorf("expected 4, got %d", got.Threshold)
	}
}

func TestUpdateNotFound(t *testing.T) {
	s, err := New(testApp(t))
	if err != nil {
		t.Fatal(err)
	}

	err = s.Update(&keys.ValidatorKeySet{ValidatorID: "nonexistent"})
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	s, err := New(testApp(t))
	if err != nil {
		t.Fatal(err)
	}

	s.Put(&keys.ValidatorKeySet{ValidatorID: "val-1"})
	if err := s.Delete("val-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("val-1"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}
