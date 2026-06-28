// Web-session auth for the embedded SPA.
//
// The SPA (frontend/) is a self-contained secrets-manager UI. Unlike the
// machine/secrets surface (/v1/kms/orgs/{org}/secrets), which authenticates
// IAM-signed bearer tokens, the human web session is local to lux-kms:
// users live in ZapDB with argon2id-hashed passwords, and the server mints
// its own HS256 session JWT. This keeps the UI standalone — no IAM, no
// Postgres, no Redis, no Node. The two auth realms coexist: IAM JWT for
// kms-get/CI, KMS session JWT for the browser.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/argon2"
	badger "github.com/luxfi/zapdb"
)

// ── domain entities (JSON-KV in ZapDB) ────────────────────────────────────

type webUser struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
	FirstName    string    `json:"firstName"`
	LastName     string    `json:"lastName"`
	SuperAdmin   bool      `json:"superAdmin"`
	PasswordHash string    `json:"-"` // argon2id PHC string; never serialized to clients
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type webOrg struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"createdAt"`
}

// keys
func userKey(id string) []byte        { return []byte("kms/users/" + id) }
func userEmailKey(email string) []byte { return []byte("kms/users/by-email/" + strings.ToLower(email)) }
func orgKey(id string) []byte         { return []byte("kms/orgs/" + id) }
func membershipKey(uid, oid string) []byte {
	return []byte(fmt.Sprintf("kms/memberships/%s/%s", uid, oid))
}
func membershipPrefix(uid string) []byte { return []byte("kms/memberships/" + uid + "/") }

var errUserExists = errors.New("user already exists")
var errUserNotFound = errors.New("user not found")

// webStore is a thin ZapDB-backed store for web-UI entities.
type webStore struct{ db *badger.DB }

func newWebStore(db *badger.DB) *webStore { return &webStore{db: db} }

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *webStore) putJSON(key []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error { return txn.Set(key, raw) })
}

func (s *webStore) getJSON(key []byte, v any) error {
	return s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error { return json.Unmarshal(val, v) })
	})
}

// CreateUser stores a user (with argon2id hash) + email index. Idempotent-safe:
// returns errUserExists if the email is taken.
func (s *webStore) CreateUser(email, password, firstName, lastName string, superAdmin bool) (*webUser, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return nil, errors.New("email and password required")
	}
	if _, err := s.UserByEmail(email); err == nil {
		return nil, errUserExists
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	u := &webUser{
		ID: newID(), Email: email, Username: email,
		FirstName: firstName, LastName: lastName, SuperAdmin: superAdmin,
		PasswordHash: hash, CreatedAt: now, UpdatedAt: now,
	}
	// persist record + email→id index
	if err := s.putJSON(userKey(u.ID), withHash(u)); err != nil {
		return nil, err
	}
	if err := s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(userEmailKey(email), []byte(u.ID))
	}); err != nil {
		return nil, err
	}
	return u, nil
}

// userRecord is the on-disk shape (includes the hash, which webUser hides via json:"-").
type userRecord struct {
	webUser
	PasswordHash string `json:"passwordHash"`
}

func withHash(u *webUser) *userRecord  { return &userRecord{webUser: *u, PasswordHash: u.PasswordHash} }

func (s *webStore) UserByID(id string) (*webUser, error) {
	var rec userRecord
	if err := s.getJSON(userKey(id), &rec); err != nil {
		return nil, errUserNotFound
	}
	u := rec.webUser
	u.PasswordHash = rec.PasswordHash
	return &u, nil
}

func (s *webStore) UserByEmail(email string) (*webUser, error) {
	var id string
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(userEmailKey(email))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error { id = string(val); return nil })
	})
	if err != nil {
		return nil, errUserNotFound
	}
	return s.UserByID(id)
}

// CountUsers reports whether any user exists (drives first-run admin signup).
func (s *webStore) CountUsers() int {
	n := 0
	_ = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = []byte("kms/users/by-email/")
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			n++
		}
		return nil
	})
	return n
}

func (s *webStore) CreateOrg(name string) (*webOrg, error) {
	o := &webOrg{ID: newID(), Name: name, Slug: slugify(name), CreatedAt: time.Now().UTC()}
	if err := s.putJSON(orgKey(o.ID), o); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *webStore) OrgByID(id string) (*webOrg, error) {
	var o webOrg
	if err := s.getJSON(orgKey(id), &o); err != nil {
		return nil, errors.New("org not found")
	}
	return &o, nil
}

func (s *webStore) AddMembership(uid, oid, role string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(membershipKey(uid, oid), []byte(role))
	})
}

// OrgsForUser returns the orgs the user belongs to.
func (s *webStore) OrgsForUser(uid string) ([]*webOrg, error) {
	var ids []string
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = membershipPrefix(uid)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			k := string(it.Item().Key())
			ids = append(ids, k[len(membershipPrefix(uid)):])
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]*webOrg, 0, len(ids))
	for _, id := range ids {
		if o, err := s.OrgByID(id); err == nil {
			out = append(out, o)
		}
	}
	return out, nil
}

// ── argon2id password hashing (PHC string; never plaintext) ───────────────

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

func hashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyPassword(pw, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version, m, t, p int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// ── session JWT (HS256, KMS-local) ────────────────────────────────────────

type webClaims struct {
	jwt.Claims
	UserID string `json:"uid"`
	OrgID  string `json:"oid,omitempty"`
}

type webAuth struct{ secret []byte }

func newWebAuth(secret []byte) *webAuth { return &webAuth{secret: secret} }

// mint issues a session token. orgID empty = pre-org-selection token.
func (a *webAuth) mint(userID, orgID string, ttl time.Duration) (string, error) {
	sig, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.HS256, Key: a.secret}, nil)
	if err != nil {
		return "", err
	}
	now := time.Now()
	cl := webClaims{
		Claims: jwt.Claims{
			Issuer: "lux-kms", Subject: userID,
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID: userID, OrgID: orgID,
	}
	return jwt.Signed(sig).Claims(cl).Serialize()
}

func (a *webAuth) verify(raw string) (*webClaims, error) {
	tok, err := jwt.ParseSigned(raw, []gojose.SignatureAlgorithm{gojose.HS256})
	if err != nil {
		return nil, err
	}
	var cl webClaims
	if err := tok.Claims(a.secret, &cl); err != nil {
		return nil, err
	}
	if err := cl.Validate(jwt.Expected{Issuer: "lux-kms", Time: time.Now()}); err != nil {
		return nil, err
	}
	return &cl, nil
}
