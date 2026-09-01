// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package encryption provides encryption utilities for Lux projects.
package encryption

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/luxfi/age"
)

// DecryptPrivateKeyWithPassword decrypts an age-encrypted private key using a password.
// This is extracted from the MPC package to provide a centralized implementation.
func DecryptPrivateKeyWithPassword(encryptedData []byte, password string) ([]byte, error) {
	// Create an age identity (decryption key) from the password
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, fmt.Errorf("failed to create age identity: %w", err)
	}

	// Decrypt the data
	decrypter, err := age.Decrypt(strings.NewReader(string(encryptedData)), identity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Read the decrypted data
	var decryptedData bytes.Buffer
	if _, err := io.Copy(&decryptedData, decrypter); err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return decryptedData.Bytes(), nil
}

// EncryptDataWithPassword encrypts data using age encryption with a password.
func EncryptDataWithPassword(data []byte, password string) ([]byte, error) {
	// Create an age recipient from the password
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, fmt.Errorf("failed to create age recipient: %w", err)
	}

	// Encrypt the data
	var encrypted bytes.Buffer
	encrypter, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypter: %w", err)
	}

	if _, err := encrypter.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write encrypted data: %w", err)
	}

	if err := encrypter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close encrypter: %w", err)
	}

	return encrypted.Bytes(), nil
}

// IsAgeEncrypted checks if data appears to be age-encrypted.
func IsAgeEncrypted(data []byte) bool {
	// Age encrypted files typically start with "age-encryption.org"
	return bytes.HasPrefix(data, []byte("age-encryption.org"))
}

// DecryptFile decrypts an age-encrypted file.
func DecryptFile(encryptedPath string, password string) ([]byte, error) {
	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}

	if !IsAgeEncrypted(data) {
		// File is not encrypted, return as-is
		return data, nil
	}

	return DecryptPrivateKeyWithPassword(data, password)
}
