// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package encryption

import (
	"bytes"
	"fmt"
	"io"

	"github.com/luxfi/age"
)

// XWingRecipient implements age.Recipient using X-Wing hybrid KEM
// (X25519 + ML-KEM-768, NIST FIPS 203). This is the canonical
// post-quantum recipient for all Lux encryption.
//
// Wraps age's native HybridRecipient which uses the same construction
// (HPKE with MLKEM768-X25519).
type XWingRecipient struct {
	r *age.HybridRecipient
}

// XWingIdentity implements age.Identity using X-Wing hybrid KEM.
// It can decrypt messages encrypted to the corresponding XWingRecipient.
type XWingIdentity struct {
	i *age.HybridIdentity
}

// Compile-time interface checks.
var (
	_ age.Recipient = (*XWingRecipient)(nil)
	_ age.Identity  = (*XWingIdentity)(nil)
)

// GenerateXWingIdentity creates a new X-Wing keypair for age encryption.
func GenerateXWingIdentity() (*XWingIdentity, error) {
	i, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, fmt.Errorf("xwing keygen: %w", err)
	}
	return &XWingIdentity{i: i}, nil
}

// ParseXWingIdentity parses an X-Wing identity from its Bech32 encoding
// (AGE-SECRET-KEY-PQ-1...).
func ParseXWingIdentity(s string) (*XWingIdentity, error) {
	i, err := age.ParseHybridIdentity(s)
	if err != nil {
		return nil, fmt.Errorf("xwing parse identity: %w", err)
	}
	return &XWingIdentity{i: i}, nil
}

// ParseXWingRecipient parses an X-Wing recipient from its Bech32 encoding
// (age1pq1...).
func ParseXWingRecipient(s string) (*XWingRecipient, error) {
	r, err := age.ParseHybridRecipient(s)
	if err != nil {
		return nil, fmt.Errorf("xwing parse recipient: %w", err)
	}
	return &XWingRecipient{r: r}, nil
}

// Recipient returns the public XWingRecipient for this identity.
func (id *XWingIdentity) Recipient() *XWingRecipient {
	return &XWingRecipient{r: id.i.Recipient()}
}

// Unwrap implements age.Identity.
func (id *XWingIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return id.i.Unwrap(stanzas)
}

// String returns the Bech32-encoded secret key (AGE-SECRET-KEY-PQ-1...).
func (id *XWingIdentity) String() string {
	return id.i.String()
}

// Wrap implements age.Recipient.
func (r *XWingRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return r.r.Wrap(fileKey)
}

// String returns the Bech32-encoded public key (age1pq1...).
func (r *XWingRecipient) String() string {
	return r.r.String()
}

// EncryptWithXWing encrypts data to one or more X-Wing recipients.
func EncryptWithXWing(data []byte, recipients ...*XWingRecipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("xwing encrypt: no recipients")
	}

	// Convert to age.Recipient slice.
	rs := make([]age.Recipient, len(recipients))
	for i, r := range recipients {
		rs[i] = r
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		return nil, fmt.Errorf("xwing encrypt: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("xwing encrypt write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("xwing encrypt close: %w", err)
	}
	return buf.Bytes(), nil
}

// DecryptWithXWing decrypts data using one or more X-Wing identities.
func DecryptWithXWing(data []byte, identities ...*XWingIdentity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("xwing decrypt: no identities")
	}

	// Convert to age.Identity slice.
	ids := make([]age.Identity, len(identities))
	for i, id := range identities {
		ids[i] = id
	}

	r, err := age.Decrypt(bytes.NewReader(data), ids...)
	if err != nil {
		return nil, fmt.Errorf("xwing decrypt: %w", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, fmt.Errorf("xwing decrypt read: %w", err)
	}
	return buf.Bytes(), nil
}
