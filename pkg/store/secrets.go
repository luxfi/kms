package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"
)

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

// Key prefix for secrets in ZapDB.
var secretPrefix = []byte("kms/secrets/")

// Secret is an encrypted record stored in ZapDB. Plaintext is never stored.
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
	Path       string    `json:"path"`        // e.g. "/ci", "/myservice/local"
	Env        string    `json:"env"`         // dev, test, main
	Ciphertext []byte    `json:"ciphertext"`  // AES-GCM ciphertext or TFHE ciphertext
	WrappedDEK []byte    `json:"wrapped_dek"` // ML-KEM encapsulated DEK (standard mode only)
	Scheme     string    `json:"scheme"`      // aead+mlkem (default), tfhe, ckks
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
//
// The path is normalized to ONE spelling first, by the same normalizePath that
// Find already applies to a query. Without it a write and a read of the same
// secret disagree: the POST body carries a free-form path, so a caller writing
// "/svc" stored kms/secrets//svc/... while every GET — whose path comes from the
// URL, where the router has already collapsed the separator — looked up
// kms/secrets/svc/... . The write answered 201 and the read answered 404, so a
// consumer took an empty credential from a store that had reported success, and
// the stranded record was addressable only as %2Fsvc: invisible to the very
// spelling that created it. One normalizer for the query and for the key is what
// makes a write always readable back.
func secretKey(path, name, env string) []byte {
	return []byte(fmt.Sprintf("kms/secrets/%s/%s/%s", normalizePath(path), env, name))
}

// splitSecretKey inverts secretKey: it recovers the (path, env, name) triple a
// stored key encodes. name is the final segment, env the one before it, path
// everything in between — path may be empty (a secret at the store root), env
// and name may not.
//
// The split is exact for any key secretKey produced from an env and a name
// carrying no '/', which ValidCoord requires of every write. It stays
// ACTIONABLE even for a key that predates that guard: the triple it returns
// rejoins to the identical key, so whatever a listing reports can always be
// fetched and deleted verbatim.
func splitSecretKey(key string) (path, env, name string, ok bool) {
	rel, found := strings.CutPrefix(key, string(secretPrefix))
	if !found {
		return "", "", "", false
	}
	slash := strings.LastIndex(rel, "/")
	if slash < 0 {
		return "", "", "", false
	}
	name, head := rel[slash+1:], rel[:slash]
	slash = strings.LastIndex(head, "/")
	if slash < 0 {
		return "", "", "", false
	}
	env, path = head[slash+1:], head[:slash]
	if env == "" || name == "" {
		return "", "", "", false
	}
	return path, env, name, true
}

// ErrInvalidCoord rejects a write whose env or name would make the storage key
// ambiguous. It is returned only by Put — a lookup of an already-stored record
// stays permissive, since rejoining any triple reproduces the key it came from.
var ErrInvalidCoord = errors.New("store: env and name must be single segments (no '/', no control characters)")

// ValidCoord reports whether env and name are single key segments. env and name
// are the last two components of kms/secrets/{path}/{env}/{name}, so a '/' in
// either would let two different (path, env, name) triples spell the SAME key
// and make an enumeration's decode of that key ambiguous. Enforced on write, so
// the keyspace stays injective going forward.
func ValidCoord(env, name string) bool {
	for _, s := range [2]string{env, name} {
		if s == "" {
			return false
		}
		for _, r := range s {
			if r == '/' || r < 0x20 || r == 0x7f {
				return false
			}
		}
	}
	return true
}

// Put stores an encrypted secret (upsert).
func (s *SecretStore) Put(secret *Secret) error {
	if !ValidCoord(secret.Env, secret.Name) {
		return ErrInvalidCoord
	}
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

// Ref is a stored secret's full coordinate — the complete answer to "what is in
// this store". It has no value field, so an enumeration is structurally
// incapable of returning a secret, and it carries the path and env alongside
// the name so a listed record is never mistaken for a different environment's
// record of the same name. A Ref feeds straight back into Get and Delete.
type Ref struct {
	Path string `json:"path"`
	Env  string `json:"env"`
	Name string `json:"name"`
}

// Query selects a set of stored secrets. The ZERO Query selects every record:
// a store you cannot ask "what is in you" cannot be audited, rotated, or
// checked for coverage, so "everything" must be expressible.
type Query struct {
	// Path is a subtree root. It selects the secrets stored at this path AND
	// at every path beneath it; "" selects the whole store. Matching is on the
	// segment boundary, so "deploy" reaches "deploy/ci" but never "deployfoo".
	Path string

	// Env restricts the result to one environment. "" means EVERY environment.
	// There is deliberately no default env here: env is a component of the
	// storage key, so a listing that silently picked one would report an empty
	// store while another env held every record — indistinguishable, from the
	// outside, from a store that is genuinely empty.
	Env string
}

// Find returns the coordinates of every secret matching q, ordered by
// (path, env, name) so two runs over the same data are byte-identical and
// diffable.
//
// It scans KEYS ONLY (PrefetchValues=false): a value blob is never loaded, so
// no code path leads from an enumeration to a secret. Filtering happens on the
// decoded coordinate rather than on a single opaque byte prefix, which is what
// lets one query span sub-paths and environments — the key layout braids path
// and env into one string (kms/secrets/{path}/{env}/{name}), so a lone prefix
// scan can only ever answer for one exact (path, env) pair.
func (s *SecretStore) Find(q Query) ([]Ref, error) {
	root := normalizePath(q.Path)
	refs := []Ref{}
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // keys only — a listing never touches a value
		opts.Prefix = secretPrefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			// KeyCopy: Item.Key() is only valid for the current step.
			path, env, name, ok := splitSecretKey(string(it.Item().KeyCopy(nil)))
			if !ok {
				continue
			}
			if q.Env != "" && env != q.Env {
				continue
			}
			if !underPath(root, path) {
				continue
			}
			refs = append(refs, Ref{Path: path, Env: env, Name: name})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Env != b.Env {
			return a.Env < b.Env
		}
		return a.Name < b.Name
	})
	return refs, nil
}

// normalizePath reduces the spellings of one subtree — "deploy", "/deploy",
// "deploy/" — to a single value, so a query can never miss a record over a
// leading slash a caller happened to type.
func normalizePath(p string) string { return strings.Trim(p, "/") }

// underPath reports whether stored lies in the subtree rooted at root. Both
// sides are normalized, and the comparison is on the segment boundary so
// "deploy" reaches "deploy/ci" but never "deployfoo". An empty root is the
// whole store.
func underPath(root, stored string) bool {
	if root == "" {
		return true
	}
	s := normalizePath(stored)
	return s == root || strings.HasPrefix(s, root+"/")
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
