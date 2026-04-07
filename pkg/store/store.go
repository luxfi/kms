// Package store provides key metadata persistence via Hanzo Base.
// SQLite embedded for local dev, Postgres for production.
// Encryption at rest handled by Base.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/hanzoai/base/core"
	"github.com/luxfi/kms/pkg/keys"
)

var (
	ErrNotFound      = errors.New("store: key set not found")
	ErrAlreadyExists = errors.New("store: key set already exists")
)

const collectionName = "kms_validator_keys"

// Store persists validator key set metadata via Base collection.
type Store struct {
	app  core.App
	mu   sync.RWMutex
	data map[string]*keys.ValidatorKeySet
}

// New creates a Store backed by a Base app's database.
func New(app core.App) (*Store, error) {
	s := &Store{
		app:  app,
		data: make(map[string]*keys.ValidatorKeySet),
	}
	if err := s.ensureCollection(); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// ensureCollection creates the kms_validator_keys collection if it doesn't exist.
func (s *Store) ensureCollection() error {
	_, err := s.app.FindCollectionByNameOrId(collectionName)
	if err == nil {
		return nil // already exists
	}
	collection := core.NewBaseCollection(collectionName)
	collection.Fields.Add(
		&core.TextField{Name: "validator_id", Required: true},
		&core.JSONField{Name: "data", MaxSize: 1 << 20}, // 1MB max
	)
	collection.Indexes = []string{
		"CREATE UNIQUE INDEX idx_kms_vid ON " + collectionName + " (validator_id)",
	}
	return s.app.Save(collection)
}

// load reads all records from the collection into memory.
func (s *Store) load() error {
	records, err := s.app.FindAllRecords(collectionName)
	if err != nil {
		// "no rows" / empty collection is expected on first run.
		// Any other error (schema mismatch, DB corruption) must surface.
		if strings.Contains(err.Error(), "no rows") || strings.Contains(err.Error(), "not found") {
			return nil
		}
		return fmt.Errorf("store: load records: %w", err)
	}
	for _, r := range records {
		vid := r.GetString("validator_id")
		raw := r.GetString("data")
		var ks keys.ValidatorKeySet
		if err := json.Unmarshal([]byte(raw), &ks); err != nil {
			log.Printf("store: WARNING: corrupt record validator_id=%q, skipping: %v", vid, err)
			continue
		}
		s.data[vid] = &ks
	}
	return nil
}

// Put saves a validator key set. Returns ErrAlreadyExists if the validator ID is taken.
func (s *Store) Put(ks *keys.ValidatorKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[ks.ValidatorID]; exists {
		return ErrAlreadyExists
	}
	s.data[ks.ValidatorID] = ks
	return s.persist(ks)
}

// Update replaces an existing validator key set.
func (s *Store) Update(ks *keys.ValidatorKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[ks.ValidatorID]; !exists {
		return ErrNotFound
	}
	s.data[ks.ValidatorID] = ks
	return s.persist(ks)
}

// Get retrieves a validator key set by validator ID.
func (s *Store) Get(validatorID string) (*keys.ValidatorKeySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ks, ok := s.data[validatorID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *ks
	return &cp, nil
}

// List returns all validator key sets.
func (s *Store) List() []*keys.ValidatorKeySet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*keys.ValidatorKeySet, 0, len(s.data))
	for _, ks := range s.data {
		cp := *ks
		result = append(result, &cp)
	}
	return result
}

// Delete removes a validator key set by validator ID.
func (s *Store) Delete(validatorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[validatorID]; !exists {
		return ErrNotFound
	}
	delete(s.data, validatorID)

	// Delete from DB
	record, err := s.app.FindFirstRecordByFilter(collectionName, "validator_id = {:vid}", map[string]any{"vid": validatorID})
	if err != nil {
		return nil // already gone
	}
	return s.app.Delete(record)
}

// persist upserts a key set into the Base collection.
func (s *Store) persist(ks *keys.ValidatorKeySet) error {
	raw, err := json.Marshal(ks)
	if err != nil {
		return err
	}

	// Try to find existing record
	record, err := s.app.FindFirstRecordByFilter(collectionName, "validator_id = {:vid}", map[string]any{"vid": ks.ValidatorID})
	if err != nil {
		// Create new record
		collection, err := s.app.FindCollectionByNameOrId(collectionName)
		if err != nil {
			return err
		}
		record = core.NewRecord(collection)
		record.Set("validator_id", ks.ValidatorID)
	}
	record.Set("data", string(raw))
	return s.app.Save(record)
}
