// Package store provides a JSON file-backed store for validator key metadata.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/luxfi/kms/pkg/keys"
)

var (
	ErrNotFound      = errors.New("store: key set not found")
	ErrAlreadyExists = errors.New("store: key set already exists")
)

// Store persists validator key set metadata to a JSON file.
type Store struct {
	path string
	mu   sync.RWMutex
	data map[string]*keys.ValidatorKeySet
}

// New creates a Store backed by the given file path.
// If the file exists, it is loaded. Otherwise an empty store is created.
func New(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: make(map[string]*keys.ValidatorKeySet),
	}
	if _, err := os.Stat(path); err == nil {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", path, err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &s.data); err != nil {
				return nil, fmt.Errorf("store: parse %s: %w", path, err)
			}
		}
	}
	return s, nil
}

// Put saves a validator key set. Returns ErrAlreadyExists if the validator ID is taken.
func (s *Store) Put(ks *keys.ValidatorKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[ks.ValidatorID]; exists {
		return ErrAlreadyExists
	}
	s.data[ks.ValidatorID] = ks
	return s.flush()
}

// Update replaces an existing validator key set.
func (s *Store) Update(ks *keys.ValidatorKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[ks.ValidatorID]; !exists {
		return ErrNotFound
	}
	s.data[ks.ValidatorID] = ks
	return s.flush()
}

// Get retrieves a validator key set by validator ID.
func (s *Store) Get(validatorID string) (*keys.ValidatorKeySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ks, ok := s.data[validatorID]
	if !ok {
		return nil, ErrNotFound
	}
	// Return a copy to prevent mutation.
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
	return s.flush()
}

func (s *Store) flush() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal: %w", err)
	}
	if err := os.WriteFile(s.path, raw, 0600); err != nil {
		return fmt.Errorf("store: write %s: %w", s.path, err)
	}
	return nil
}
