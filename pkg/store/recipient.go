package store

// Sealing a secret FOR someone, so that the process which enrols a credential
// cannot read one.
//
// Seal and Open (crypto.go) both take the same master key: whoever can write a
// secret can read every secret. That is one capability wearing two names, and
// where the master lives — an environment variable, a mounted file, a config —
// is where every secret effectively lives too.
//
// SealTo splits it in half. The DEK is encapsulated to a RECIPIENT's public key
// instead of wrapped under a shared one, so:
//
//   - enrolling needs `age1pq1…`, the public half, which can sit anywhere,
//     be copied, be committed, be read by anyone, and grants nothing;
//   - opening needs the identity, `AGE-SECRET-KEY-PQ-1…`, which lives in ONE
//     place and never has to leave it.
//
// The payload is sealed exactly as Seal does it — same AEAD, same AAD binding
// path/name/env, same envelope bytes. Only the DEK's custody differs, which is
// the whole point: one payload codec, two ways to hold the key that opens it.
//
// The KEM is X-Wing (X25519 + ML-KEM-768) over age's HPKE. Hybrid, so a break
// of either half alone leaves the secret sealed, and a recipient today is still
// a recipient after a quantum computer exists.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/crypto/encryption"
)

// ModeRecipient encapsulates the DEK to a recipient's public key rather than
// wrapping it under a shared master.
//
// The string is ON DISK. It is format, not naming — a row already written under
// it cannot be respelled — so it says what the envelope is: an AEAD payload
// whose key is X-Wing encapsulated.
const ModeRecipient = "aead+xwing"

// ErrNotRecipientSealed is what a secret from some other scheme gets. It is a
// refusal and never a fallthrough: trying the master key on a recipient-sealed
// secret would fail as an authentication error three frames down, which reads
// as a damaged record rather than as the wrong key entirely.
var ErrNotRecipientSealed = errors.New("crypto: secret is not sealed to a recipient")

// ErrNoRecipient means no recipient was configured. Sealing under no recipient
// would have to fall back to something, and the something would be the shared
// key this exists to stop using.
var ErrNoRecipient = errors.New("crypto: no recipient")

// aad binds a payload to its coordinate, so a ciphertext moved to another name
// no longer opens. Both schemes bind identically, because it describes WHERE a
// secret is and not how its key is held.
func aad(path, name, env string) []byte { return []byte(path + "/" + name + "/" + env) }

// SealTo seals plaintext for one recipient, named by its public key
// (`age1pq1…`). The recipient is recorded on the secret as its KeyHandle, so a
// store can hold secrets for several recipients at once and a reader can tell
// which identity opens which — which is what makes rotation a migration rather
// than an outage.
//
// The caller should zero plaintext once it returns.
func SealTo(recipient, path, name, env string, plaintext []byte) (*Secret, error) {
	if recipient == "" {
		return nil, ErrNoRecipient
	}
	to, err := encryption.ParseXWingRecipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("crypto: recipient: %w", err)
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("crypto: rand dek: %w", err)
	}
	defer zero(dek)

	ct, err := aeadSeal(dek, aad(path, name, env), plaintext)
	if err != nil {
		return nil, fmt.Errorf("crypto: seal plaintext: %w", err)
	}
	wrap, err := encryption.EncryptWithXWing(dek, to)
	if err != nil {
		return nil, fmt.Errorf("crypto: encapsulate dek: %w", err)
	}

	now := time.Now().UTC()
	return &Secret{
		Name:       name,
		Path:       path,
		Env:        env,
		Ciphertext: ct,
		WrappedDEK: wrap,
		Scheme:     ModeRecipient,
		KeyHandle:  recipient,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// OpenWith inverts SealTo, using the recipient's identity
// (`AGE-SECRET-KEY-PQ-1…`). This is the one function in the estate that turns a
// stored credential back into a credential, so wherever this is called is the
// boundary the plaintext lives inside.
//
// The caller must zero the returned slice after use.
func OpenWith(identity string, secret *Secret) ([]byte, error) {
	if secret == nil {
		return nil, ErrBadEnvelope
	}
	if secret.Scheme != ModeRecipient {
		return nil, fmt.Errorf("%w: scheme is %q", ErrNotRecipientSealed, secret.Scheme)
	}
	me, err := encryption.ParseXWingIdentity(identity)
	if err != nil {
		return nil, fmt.Errorf("crypto: identity: %w", err)
	}

	dek, err := encryption.DecryptWithXWing(secret.WrappedDEK, me)
	if err != nil {
		return nil, fmt.Errorf("crypto: decapsulate the dek for %q (this identity is not its recipient, or the record is damaged): %w", secret.Name, err)
	}
	defer zero(dek)

	pt, err := aeadOpen(dek, aad(secret.Path, secret.Name, secret.Env), secret.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: open plaintext: %w", err)
	}
	return pt, nil
}

// Recipient mints a new recipient: the identity to keep and the public key to
// hand out. The identity is returned as a string and never written anywhere by
// this package, because the one decision that matters about it is where it is
// kept, and that belongs to the caller.
func Recipient() (identity, recipient string, err error) {
	id, err := encryption.GenerateXWingIdentity()
	if err != nil {
		return "", "", fmt.Errorf("crypto: mint a recipient: %w", err)
	}
	return id.String(), id.Recipient().String(), nil
}

// zero clears key material once it is no longer needed. It is not a guarantee
// against a determined memory reader; it shortens the window.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
