package store

import (
	"errors"
	"time"

	"github.com/hanzoai/base/core"
)

const secretsCollection = "kms_secrets"

var ErrSecretNotFound = errors.New("store: secret not found")

// Secret storage modes.
const (
	// ModeStandard: AES-256-GCM payload + ML-KEM wrapped DEK.
	// Fast, PQ-safe. No threshold required. Default for all secrets.
	ModeStandard = "aead+mlkem"

	// ModeThresholdReveal: payload or DEK under T-Chain threshold FHE key.
	// Decrypt requires t-of-n validator cooperation via E2S protocol.
	// Use for high-value secrets, sealed recovery, conditional access.
	ModeThresholdReveal = "tfhe"

	// ModeConfidentialCompute: CKKS ciphertext for computation on encrypted data.
	// Use for ML inference on encrypted inputs.
	ModeConfidentialCompute = "ckks"
)

// Secret is an encrypted record stored in Base. Plaintext is never stored.
//
// Standard path (default):
//
//	DEK = random 256-bit key
//	Ciphertext = AES-256-GCM(plaintext, DEK)
//	WrappedDEK = ML-KEM-Encaps(DEK, recipientPK)
//	Policy, handles, receipts anchored on K-Chain
//
// Threshold reveal path (opt-in):
//
//	Ciphertext = TFHE-Encrypt(plaintext, collectivePK)
//	Decrypt requires T-Chain quorum (t-of-n E2S shares)
type Secret struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`        // e.g. "/ci", "/securegate/local"
	Env        string    `json:"env"`         // dev, test, main
	Ciphertext []byte    `json:"ciphertext"`  // AES-GCM ciphertext or TFHE ciphertext
	WrappedDEK []byte    `json:"wrapped_dek"` // ML-KEM encapsulated DEK (standard mode only)
	Scheme     string    `json:"scheme"`      // aead+mlkem (default), tfhe, ckks
	KeyHandle  string    `json:"key_handle"`  // K-Chain key/policy handle
	PolicyID   string    `json:"policy_id"`   // access policy (who can decrypt)
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SecretStore manages encrypted secrets in Base.
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
		&core.JSONField{Name: "ciphertext", MaxSize: 10 << 20},
		&core.JSONField{Name: "wrapped_dek", MaxSize: 8192},
		&core.TextField{Name: "scheme"},
		&core.TextField{Name: "key_handle"},
		&core.TextField{Name: "policy_id"},
	)
	c.Indexes = []string{
		"CREATE UNIQUE INDEX idx_secret_path_name_env ON " + secretsCollection + " (path, name, env)",
	}
	return s.app.Save(c)
}

// Put stores an encrypted secret (upsert).
func (s *SecretStore) Put(secret *Secret) error {
	if secret.Scheme == "" {
		secret.Scheme = ModeStandard
	}

	collection, err := s.app.FindCollectionByNameOrId(secretsCollection)
	if err != nil {
		return err
	}

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
	record.Set("wrapped_dek", secret.WrappedDEK)
	record.Set("scheme", secret.Scheme)
	record.Set("key_handle", secret.KeyHandle)
	record.Set("policy_id", secret.PolicyID)
	return s.app.Save(record)
}

// Get retrieves an encrypted secret. Caller must decrypt via appropriate path.
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
		WrappedDEK: []byte(record.GetString("wrapped_dek")),
		Scheme:     record.GetString("scheme"),
		KeyHandle:  record.GetString("key_handle"),
		PolicyID:   record.GetString("policy_id"),
	}, nil
}

// List returns all secrets at a path/env (metadata + ciphertext, no plaintext).
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
			Scheme:     r.GetString("scheme"),
			KeyHandle:  r.GetString("key_handle"),
			PolicyID:   r.GetString("policy_id"),
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
