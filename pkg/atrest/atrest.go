// Package atrest owns the store's at-rest encryption key: how it is spelled,
// how it is validated, and how a store already written without one is moved
// onto it.
//
// It exists because a KMS that opens its store without a key is a filesystem
// with an HTTP API. Every byte — every credential the fleet syncs — then sits
// in cleartext in the SSTs and the value log, and the S3 replica ships those
// same cleartext files off-cluster. The blast radius of one PVC snapshot or one
// bucket read is the whole store, and no amount of correct JWT gating in front
// of it changes that.
//
// So the key is not optional and its absence is not a warning. A miswired key
// used to degrade to "no encryption" through a single log line that scrolled
// past at boot; the deployment it shipped in ran that way in production. The
// rule here is the opposite: a store that cannot be encrypted is not opened.
//
// # Where the key must live
//
// Not in this KMS. A store's own key cannot be a record in that store — a cold
// start could never read it. It comes from outside: a Secret provisioned out of
// band, or (preferred) the MPC-rooted REK, which is already how the ZAP secrets
// plane roots its per-secret DEKs. That is why this package takes a key rather
// than fetching one: the source of the key is a deployment decision, and this
// package must not become a second opinion about it.
package atrest

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	badger "github.com/luxfi/zapdb"
)

// KeyEnv is the ONE name for the store's at-rest key: 32 raw bytes, base64.
//
// LegacyKeyEnv is the Infisical-era name a Hanzo deployment still provisions.
// It is never read — its encoding is unspecified and it roots a different
// scheme entirely — but it is named in the error, because "a key is provisioned
// and the server ignores it" is the exact shape the misconfiguration took, and
// an operator staring at a populated Secret needs to be told which name counts.
const (
	KeyEnv       = "KMS_ENCRYPTION_KEY_B64"
	LegacyKeyEnv = "ROOT_ENCRYPTION_KEY"

	// SourceKeyEnv carries the key a store is currently encrypted under while
	// it is being moved onto a new one. Empty means the source is plaintext —
	// the migration every deployment that predates this package must run once.
	SourceKeyEnv = "KMS_REKEY_FROM_B64"

	// KeyLen is the key size ZapDB accepts for AES-256.
	KeyLen = 32
)

// ErrNoKey reports that no at-rest key is configured. Callers translate it into
// a refusal to serve; nothing may treat it as "encryption off".
var ErrNoKey = errors.New("no at-rest encryption key configured")

// Decode parses a base64 key. It is pure so the contract can be tested without
// reaching into the process environment: name is used only to make the error
// name the knob the operator has to fix.
func Decode(name, b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, fmt.Errorf("%s is empty: %w", name, ErrNoKey)
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64 (want %d raw bytes, base64-encoded)", name, KeyLen)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("%s decodes to %d bytes, want %d", name, len(key), KeyLen)
	}
	return key, nil
}

// KeyFromEnv resolves the at-rest key from the process environment.
func KeyFromEnv() ([]byte, error) {
	key, err := Decode(KeyEnv, os.Getenv(KeyEnv))
	if err != nil && errors.Is(err, ErrNoKey) && os.Getenv(LegacyKeyEnv) != "" {
		return nil, fmt.Errorf("%w — %s is set, but it is not this store's key: it is the "+
			"Infisical-era name and this server never reads it. Provision %s (%d raw bytes, base64)",
			err, LegacyKeyEnv, KeyEnv, KeyLen)
	}
	return key, err
}

// SourceKeyFromEnv resolves the key a store being migrated is currently under.
// Absent means plaintext, which is a legitimate source — unlike the destination,
// where absent is a refusal.
func SourceKeyFromEnv() ([]byte, error) {
	b64 := os.Getenv(SourceKeyEnv)
	if b64 == "" {
		return nil, nil
	}
	return Decode(SourceKeyEnv, b64)
}

// Open opens the store at dir under key, creating dir if it does not exist.
// logger may be nil to silence ZapDB's own output.
//
// The one error worth translating is ZapDB's "Encryption key mismatch": on a
// first rollout it does not mean the operator typed the wrong key, it means the
// store on disk predates encryption and has to be migrated. The raw message
// sends people looking for a lost key that never existed, so say what to run.
func Open(dir string, key []byte, logger badger.Logger) (*badger.DB, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("at-rest key is %d bytes, want %d", len(key), KeyLen)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", dir, err)
	}
	db, err := badger.Open(options(dir, key, logger))
	if err != nil {
		if errors.Is(err, badger.ErrEncryptionKeyMismatch) {
			return nil, fmt.Errorf("store at %s does not open under %s: it was written "+
				"WITHOUT at-rest encryption (or under a different key). Migrate it once with "+
				"`kms-rekey -from %s -to <newdir>` and point the data dir at the result; "+
				"the source store is opened read-only and left untouched", dir, KeyEnv, dir)
		}
		return nil, fmt.Errorf("open store at %s: %w", dir, err)
	}
	return db, nil
}

// options is the ONE place the store's ZapDB options are spelled, so a server
// open and a migration open cannot drift into different databases.
//
// The value log is sized for what this store actually is. ZapDB's default value
// log is 1GB and the active file is mapped at twice that — 2147483646 bytes,
// which is exactly the sparse file sitting on the Hanzo claim behind 476KB of
// real secrets. It is not free: an operator who read that file inside the pod
// filled the cgroup's page cache and OOM-killed a KMS that was using a few
// hundred MB. At 64MB the active file maps 128MB, small enough that reading it
// cannot evict a pod, and a store whose values are credentials — kilobytes each
// — never needs more.
func options(dir string, key []byte, logger badger.Logger) badger.Options {
	return badger.DefaultOptions(dir).
		WithLogger(logger).
		WithEncryptionKey(key).
		WithIndexCacheSize(64 << 20).
		WithValueLogFileSize(64 << 20)
}

// Rekey copies every record of the store at srcDir into a NEW store at dstDir
// encrypted under dstKey. srcKey is the key srcDir is currently under; nil for
// a plaintext store.
//
// It copies rather than converts. The source is opened READ-ONLY and is not
// written, so a migration that dies halfway leaves the live store exactly as it
// found it and the operator simply deletes the half-written destination. There
// is no in-place mode: an in-place re-encryption of the one store that holds
// every credential in the fleet has a failure mode with no recovery.
//
// The copy streams through a pipe. A store large enough to matter is larger
// than the pod's memory limit, and a migration that OOMs at 90% is a migration
// that never finishes.
//
// It returns the number of records in the destination, counted by scanning it
// after the load. That number is the operator's proof the migration is complete
// — "it exited 0" is not evidence that every credential came across.
func Rekey(srcDir, dstDir string, srcKey, dstKey []byte) (int, error) {
	if len(dstKey) != KeyLen {
		return 0, fmt.Errorf("destination key is %d bytes, want %d", len(dstKey), KeyLen)
	}
	if srcDir == dstDir {
		return 0, errors.New("source and destination are the same directory")
	}
	empty, err := isEmptyDir(dstDir)
	if err != nil {
		return 0, err
	}
	if !empty {
		return 0, fmt.Errorf("destination %s is not empty: refusing to write into an existing store", dstDir)
	}

	srcOpts := options(srcDir, srcKey, nil).WithReadOnly(true)
	if len(srcKey) == 0 {
		srcOpts = srcOpts.WithEncryptionKey(nil)
	}
	src, err := badger.Open(srcOpts)
	if err != nil {
		if errors.Is(err, badger.ErrEncryptionKeyMismatch) {
			return 0, fmt.Errorf("source store at %s does not open under the source key: "+
				"set %s to the key it is currently encrypted under, or leave it empty if "+
				"the store is plaintext", srcDir, SourceKeyEnv)
		}
		return 0, fmt.Errorf("open source %s read-only: %w", srcDir, err)
	}
	defer src.Close()

	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return 0, fmt.Errorf("create destination %s: %w", dstDir, err)
	}
	dst, err := badger.Open(options(dstDir, dstKey, nil))
	if err != nil {
		return 0, fmt.Errorf("open destination %s: %w", dstDir, err)
	}
	defer dst.Close()

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := src.Backup(pw, 0)
		// Closing with the error makes the reader fail too, so a source-side
		// failure can never look like a complete copy.
		done <- err
		pw.CloseWithError(err)
	}()

	if err := dst.Load(pr, 16); err != nil {
		return 0, fmt.Errorf("load into %s: %w", dstDir, err)
	}
	if err := <-done; err != nil {
		return 0, fmt.Errorf("read source %s: %w", srcDir, err)
	}
	return count(dst)
}

// count reports how many records a store holds, reading keys only — the values
// are never materialized, so counting a store of credentials cannot spill one.
func count(db *badger.DB) (int, error) {
	var n int
	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			n++
		}
		return nil
	})
	return n, err
}

// isEmptyDir reports whether dir is absent or holds no entries.
func isEmptyDir(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read destination %s: %w", filepath.Clean(dir), err)
	}
	return len(entries) == 0, nil
}
