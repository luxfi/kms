package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	badger "github.com/luxfi/zapdb"
)

var ErrSecretNotFound = errors.New("store: secret not found")

// Secret storage modes.
//
// A mode names the bytes on disk, so a reader can pick the right unwrap
// path from the record alone. It describes what Seal did — never what a
// future version intends to do.
const (
	// ModeStandard: AES-256-GCM payload under a per-secret DEK, and that
	// DEK wrapped with AES-256-GCM under the REK. Symmetric end to end.
	//
	// Both layers are AES-256, which stands up to Grover at ~128-bit
	// equivalent, so this envelope needs no post-quantum key agreement:
	// the REK is never transmitted and there is no public-key ciphertext
	// for an adversary to harvest. PQ belongs on the paths that DO move
	// key material — see pkg/zap/handshake.go for the wire.
	ModeStandard = "aes256-gcm"
)

// Key prefix for secrets in ZapDB.
var secretPrefix = []byte("kms/secrets/")

// Secret is an encrypted record stored in ZapDB. Plaintext is never stored.
//
//	DEK        = random 256-bit key
//	Ciphertext = AES-256-GCM(plaintext, DEK), AAD = path/name/env
//	WrappedDEK = AES-256-GCM(DEK, REK),       AAD = name
//
// The AAD on each layer is what stops a swap: a record moved to another
// path/name/env fails to open.
type Secret struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`        // e.g. "/ci", "/myservice/local"
	Env        string    `json:"env"`         // dev, test, main
	Ciphertext []byte    `json:"ciphertext"`  // AES-256-GCM under the DEK
	WrappedDEK []byte    `json:"wrapped_dek"` // AES-256-GCM under the REK
	Scheme     string    `json:"scheme"`      // ModeStandard
	KeyHandle  string    `json:"key_handle"`  // K-Chain key/policy handle
	PolicyID   string    `json:"policy_id"`   // access policy (who can decrypt)
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SecretStore manages encrypted secrets in ZapDB.
type SecretStore struct {
	db *badger.DB
}

// NewSecretStore creates a secret store backed by ZapDB.
func NewSecretStore(db *badger.DB) *SecretStore {
	return &SecretStore{db: db}
}

// secretKey returns the ZapDB key for a secret: kms/secrets/{path}/{env}/{name}
func secretKey(path, name, env string) []byte {
	return []byte(fmt.Sprintf("kms/secrets/%s/%s/%s", path, env, name))
}

// secretListPrefix returns the prefix for listing secrets at a path/env.
func secretListPrefix(path, env string) []byte {
	return []byte(fmt.Sprintf("kms/secrets/%s/%s/", path, env))
}

// Put stores an encrypted secret (upsert).
func (s *SecretStore) Put(secret *Secret) error {
	if secret.Scheme == "" {
		secret.Scheme = ModeStandard
	}
	raw, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(secretKey(secret.Path, secret.Name, secret.Env), raw)
	})
}

// Get retrieves an encrypted secret. Caller must decrypt via appropriate path.
func (s *SecretStore) Get(path, name, env string) (*Secret, error) {
	var secret Secret
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(secretKey(path, name, env))
		if err == badger.ErrKeyNotFound {
			return ErrSecretNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &secret)
		})
	})
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// List returns all secrets at a path/env (metadata + ciphertext, no plaintext).
func (s *SecretStore) List(path, env string) ([]*Secret, error) {
	var secrets []*Secret
	prefix := secretListPrefix(path, env)

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var sec Secret
				if err := json.Unmarshal(val, &sec); err != nil {
					return err
				}
				// For listing, strip ciphertext to reduce payload.
				secrets = append(secrets, &Secret{
					Name:      sec.Name,
					Path:      sec.Path,
					Env:       sec.Env,
					Scheme:    sec.Scheme,
					KeyHandle: sec.KeyHandle,
					PolicyID:  sec.PolicyID,
				})
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

// Delete removes a secret.
func (s *SecretStore) Delete(path, name, env string) error {
	key := secretKey(path, name, env)
	return s.db.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return ErrSecretNotFound
		}
		if err != nil {
			return err
		}
		return txn.Delete(key)
	})
}
