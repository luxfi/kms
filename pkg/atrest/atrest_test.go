package atrest

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	badger "github.com/luxfi/zapdb"
)

func testKey(b byte) []byte {
	k := make([]byte, KeyLen)
	for i := range k {
		k[i] = b
	}
	return k
}

func b64(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

func TestDecodeRejectsEveryUnusableKey(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", "is empty"},
		{"not base64", "not-base-64-!!", "not valid base64"},
		{"short", b64(make([]byte, 16)), "decodes to 16 bytes"},
		{"long", b64(make([]byte, 64)), "decodes to 64 bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(KeyEnv, c.in)
			if err == nil {
				t.Fatalf("Decode(%q) = nil error, want refusal", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not say %q", err, c.want)
			}
			if !strings.Contains(err.Error(), KeyEnv) {
				t.Fatalf("error %q does not name the knob %s", err, KeyEnv)
			}
		})
	}

	key, err := Decode(KeyEnv, b64(testKey(7)))
	if err != nil {
		t.Fatalf("Decode(valid) = %v", err)
	}
	if len(key) != KeyLen {
		t.Fatalf("len = %d, want %d", len(key), KeyLen)
	}
}

// An empty key must be reported as ErrNoKey specifically: callers refuse to
// serve on it, and a caller that cannot tell "absent" from "malformed" cannot
// give an operator the right instruction.
func TestDecodeEmptyIsErrNoKey(t *testing.T) {
	_, err := Decode(KeyEnv, "")
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty key error = %v, want ErrNoKey", err)
	}
	_, err = Decode(KeyEnv, "zzz")
	if errors.Is(err, ErrNoKey) {
		t.Fatal("malformed key reported as ErrNoKey; it is a different fix")
	}
}

// The deployment that shipped had a 32-byte key provisioned under the
// Infisical-era name and none under this one. The error has to name both, or
// the operator reads "no key configured" while looking straight at a key.
func TestKeyFromEnvNamesTheLegacyKeyItWillNotUse(t *testing.T) {
	t.Setenv(KeyEnv, "")
	t.Setenv(LegacyKeyEnv, "some-32-char-infisical-root-key!")

	_, err := KeyFromEnv()
	if err == nil {
		t.Fatal("KeyFromEnv() = nil error with no at-rest key set")
	}
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("error %v does not wrap ErrNoKey", err)
	}
	for _, want := range []string{KeyEnv, LegacyKeyEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %s", err, want)
		}
	}
}

func TestKeyFromEnvAcceptsAValidKey(t *testing.T) {
	t.Setenv(KeyEnv, b64(testKey(3)))
	key, err := KeyFromEnv()
	if err != nil {
		t.Fatalf("KeyFromEnv() = %v", err)
	}
	if len(key) != KeyLen {
		t.Fatalf("len = %d, want %d", len(key), KeyLen)
	}
}

// writePlaintextStore builds the thing this whole package exists to retire: a
// store written with no at-rest key at all.
func writePlaintextStore(t *testing.T, dir string, n int) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions(dir).WithLogger(nil))
	if err != nil {
		t.Fatalf("open plaintext store: %v", err)
	}
	err = db.Update(func(txn *badger.Txn) error {
		for i := range n {
			k := fmt.Sprintf("kms/secrets/svc/prod/CRED_%02d", i)
			if err := txn.Set([]byte(k), []byte(fmt.Sprintf("value-%02d", i))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed plaintext store: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close plaintext store: %v", err)
	}
}

// Open must not silently fall back to reading the plaintext store it finds —
// it must refuse, and the refusal must say how to migrate.
func TestOpenRefusesAPlaintextStoreAndSaysHowToMigrate(t *testing.T) {
	dir := t.TempDir()
	writePlaintextStore(t, dir, 3)

	db, err := Open(dir, testKey(1), nil)
	if err == nil {
		db.Close()
		t.Fatal("Open() accepted a store written without at-rest encryption")
	}
	for _, want := range []string{"kms-rekey", "WITHOUT at-rest encryption", dir} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestOpenRefusesAKeyOfTheWrongSize(t *testing.T) {
	if _, err := Open(t.TempDir(), nil, nil); err == nil {
		t.Fatal("Open(nil key) = nil error; a keyless open is the bug this package removes")
	}
	if _, err := Open(t.TempDir(), make([]byte, 16), nil); err == nil {
		t.Fatal("Open(16-byte key) = nil error")
	}
}

// The migration is the whole reason the refusal above is shippable: every
// record has to survive it, the destination must be unreadable without the key,
// and the source must come out untouched.
func TestRekeyMovesEveryRecordAndLeavesTheSourceAlone(t *testing.T) {
	const n = 25
	root := t.TempDir()
	src := filepath.Join(root, "plaintext")
	dst := filepath.Join(root, "encrypted")
	writePlaintextStore(t, src, n)

	key := testKey(9)
	moved, err := Rekey(src, dst, nil, key)
	if err != nil {
		t.Fatalf("Rekey() = %v", err)
	}
	if moved != n {
		t.Fatalf("Rekey() reported %d records, want %d", moved, n)
	}

	db, err := Open(dst, key, nil)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	got := map[string]string{}
	err = db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			v, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			got[string(item.KeyCopy(nil))] = string(v)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan migrated store: %v", err)
	}
	db.Close()

	if len(got) != n {
		t.Fatalf("migrated store holds %d records, want %d", len(got), n)
	}
	for i := range n {
		k := fmt.Sprintf("kms/secrets/svc/prod/CRED_%02d", i)
		if want := fmt.Sprintf("value-%02d", i); got[k] != want {
			t.Fatalf("record %s = %q, want %q", k, got[k], want)
		}
	}

	// Without the key the destination must be unreadable. This is the property
	// the whole finding turns on: a PVC snapshot or an S3 replica of these
	// files is worthless on its own.
	if opened, err := badger.Open(badger.DefaultOptions(dst).WithLogger(nil)); err == nil {
		opened.Close()
		t.Fatal("migrated store opened with NO key: it is not encrypted")
	} else if !errors.Is(err, badger.ErrEncryptionKeyMismatch) {
		t.Fatalf("keyless open failed with %v, want ErrEncryptionKeyMismatch", err)
	}

	// And the source is exactly as it was — a failed migration is recoverable.
	plain, err := badger.Open(badger.DefaultOptions(src).WithLogger(nil))
	if err != nil {
		t.Fatalf("source no longer opens as it did: %v", err)
	}
	var remaining int
	err = plain.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			remaining++
		}
		return nil
	})
	plain.Close()
	if err != nil {
		t.Fatalf("scan source: %v", err)
	}
	if remaining != n {
		t.Fatalf("source holds %d records after migration, want %d", remaining, n)
	}
}

func TestRekeyRefusesToWriteIntoAnExistingStore(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	writePlaintextStore(t, src, 2)
	writePlaintextStore(t, dst, 2)

	_, err := Rekey(src, dst, nil, testKey(4))
	if err == nil {
		t.Fatal("Rekey() overwrote an existing store")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("error %q does not explain the refusal", err)
	}
}

func TestRekeyRefusesAKeylessDestination(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	writePlaintextStore(t, src, 1)

	if _, err := Rekey(src, filepath.Join(root, "dst"), nil, nil); err == nil {
		t.Fatal("Rekey() wrote an unencrypted destination")
	}
	if _, err := Rekey(src, src, nil, testKey(2)); err == nil {
		t.Fatal("Rekey() accepted src == dst")
	}
}

// A store already encrypted moves onto a new key the same way, which is what
// makes routine key rotation possible at all.
func TestRekeyRotatesAnAlreadyEncryptedStore(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	plain := filepath.Join(root, "plain")
	writePlaintextStore(t, plain, 5)

	oldKey, newKey := testKey(1), testKey(2)
	if _, err := Rekey(plain, first, nil, oldKey); err != nil {
		t.Fatalf("initial Rekey() = %v", err)
	}
	if _, err := Rekey(first, second, oldKey, newKey); err != nil {
		t.Fatalf("rotating Rekey() = %v", err)
	}

	db, err := Open(second, newKey, nil)
	if err != nil {
		t.Fatalf("open rotated store: %v", err)
	}
	defer db.Close()
	if err := db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte("kms/secrets/svc/prod/CRED_04"))
		return err
	}); err != nil {
		t.Fatalf("record missing after rotation: %v", err)
	}

	if _, err := Open(second, oldKey, nil); err == nil {
		t.Fatal("rotated store still opens under the retired key")
	}
}

func TestSourceKeyFromEnvTreatsAbsentAsPlaintext(t *testing.T) {
	t.Setenv(SourceKeyEnv, "")
	key, err := SourceKeyFromEnv()
	if err != nil || key != nil {
		t.Fatalf("SourceKeyFromEnv() = %v, %v; want nil, nil for a plaintext source", key, err)
	}

	t.Setenv(SourceKeyEnv, b64(testKey(6)))
	key, err = SourceKeyFromEnv()
	if err != nil || len(key) != KeyLen {
		t.Fatalf("SourceKeyFromEnv() = %d bytes, %v", len(key), err)
	}
}

func TestIsEmptyDir(t *testing.T) {
	root := t.TempDir()
	empty, err := isEmptyDir(filepath.Join(root, "absent"))
	if err != nil || !empty {
		t.Fatalf("absent dir: %v, %v; want true, nil", empty, err)
	}
	made := filepath.Join(root, "made")
	if err := os.MkdirAll(made, 0o700); err != nil {
		t.Fatal(err)
	}
	if empty, err = isEmptyDir(made); err != nil || !empty {
		t.Fatalf("new dir: %v, %v; want true, nil", empty, err)
	}
	if err := os.WriteFile(filepath.Join(made, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if empty, err = isEmptyDir(made); err != nil || empty {
		t.Fatalf("populated dir: %v, %v; want false, nil", empty, err)
	}
}
