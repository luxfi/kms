package store

import (
	"errors"
	"time"

	"github.com/hanzoai/base/core"
)

const secretsCollection = "kms_secrets"

var ErrSecretNotFound = errors.New("store: secret not found")

// Secret is an encrypted secret stored in Base.
// Default: AES-256-GCM with ML-KEM wrapped DEK (fast, PQ-safe).
// Optional: TFHE ciphertext for threshold-gated reveal (requires t-of-n).
// Plaintext is never stored.
type Secret struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`       // e.g. "/ci", "/securegate/local"
	Env        string    `json:"env"`        // dev, test, main
	Ciphertext []byte    `json:"ciphertext"` // encrypted (aes-gcm or tfhe)
	KeyID      string    `json:"key_id"`     // wrapping key (ML-KEM) or FHE key set
	Scheme     string    `json:"scheme"`     // aes-gcm (default) or tfhe
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SecretStore manages FHE-encrypted secrets in Base.
type SecretStore struct {
	app core.App
}

// NewSecretStore creates a secret store backed by Base.
func NewSecretStore(app core.App) (*SecretStore, error) {
	s := &SecretStore{app: app}
	if err := s.ensureCollection(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SecretStore) ensureCollection() error {
	_, err := s.app.FindCollectionByNameOrId(secretsCollection)
	if err == nil {
		return nil
	}
	c := core.NewBaseCollection(secretsCollection)
	c.Fields.Add(
		&core.TextField{Name: "name", Required: true},
		&core.TextField{Name: "path", Required: true},
		&core.TextField{Name: "env", Required: true},
		&core.JSONField{Name: "ciphertext", MaxSize: 10 << 20}, // 10MB max
		&core.TextField{Name: "key_id"},
	)
	c.Indexes = []string{
		"CREATE UNIQUE INDEX idx_secret_path_name_env ON " + secretsCollection + " (path, name, env)",
	}
	return s.app.Save(c)
}

// Put stores an FHE-encrypted secret.
func (s *SecretStore) Put(secret *Secret) error {
	collection, err := s.app.FindCollectionByNameOrId(secretsCollection)
	if err != nil {
		return err
	}

	// Upsert: find existing or create new
	record, err := s.app.FindFirstRecordByFilter(secretsCollection,
		"path = {:path} AND name = {:name} AND env = {:env}",
		map[string]any{"path": secret.Path, "name": secret.Name, "env": secret.Env})
	if err != nil {
		record = core.NewRecord(collection)
	}

	record.Set("name", secret.Name)
	record.Set("path", secret.Path)
	record.Set("env", secret.Env)
	record.Set("ciphertext", secret.Ciphertext)
	record.Set("key_id", secret.KeyID)
	return s.app.Save(record)
}

// Get retrieves an FHE-encrypted secret (ciphertext only — decrypt via MPC).
func (s *SecretStore) Get(path, name, env string) (*Secret, error) {
	record, err := s.app.FindFirstRecordByFilter(secretsCollection,
		"path = {:path} AND name = {:name} AND env = {:env}",
		map[string]any{"path": path, "name": name, "env": env})
	if err != nil {
		return nil, ErrSecretNotFound
	}

	return &Secret{
		Name:       record.GetString("name"),
		Path:       record.GetString("path"),
		Env:        record.GetString("env"),
		Ciphertext: []byte(record.GetString("ciphertext")),
		KeyID:   record.GetString("key_id"),
	}, nil
}

// List returns all secrets at a path/env (ciphertext only).
func (s *SecretStore) List(path, env string) ([]*Secret, error) {
	records, err := s.app.FindRecordsByFilter(secretsCollection,
		"path = {:path} AND env = {:env}", "", 0, 0,
		map[string]any{"path": path, "env": env})
	if err != nil {
		return nil, err
	}

	secrets := make([]*Secret, 0, len(records))
	for _, r := range records {
		secrets = append(secrets, &Secret{
			Name:       r.GetString("name"),
			Path:       r.GetString("path"),
			Env:        r.GetString("env"),
			Ciphertext: []byte(r.GetString("ciphertext")),
			KeyID:   r.GetString("key_id"),
		})
	}
	return secrets, nil
}

// Delete removes a secret.
func (s *SecretStore) Delete(path, name, env string) error {
	record, err := s.app.FindFirstRecordByFilter(secretsCollection,
		"path = {:path} AND name = {:name} AND env = {:env}",
		map[string]any{"path": path, "name": name, "env": env})
	if err != nil {
		return ErrSecretNotFound
	}
	return s.app.Delete(record)
}
