// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mnemonic loads a BIP-39 bootstrap mnemonic from KMS over
// native ZAP. It is the one canonical path every Lux-derived service
// uses to resolve the bootstrap mnemonic: luxd, netrunner, lux/cli,
// and any descending L1's bootstrap. No file mount, no projected
// volume, no per-consumer copy of the env-vs-KMS precedence chain.
//
// Why this lives in luxfi/kms and not luxfi/keys:
//
// The mnemonic loader composes luxfi/keys (BIP-39 semantics +
// ServiceIdentity) with the KMS wire transport (envelope + zapclient).
// Putting it in luxfi/keys would force keys to import kms — but kms
// already imports keys (zapserver authenticates ServiceIdentity
// envelopes), so that edge would close an import cycle. Hosting the
// loader in kms keeps the dependency acyclic:
//
//	kms/pkg/mnemonic → luxfi/keys        (ServiceIdentity, BIP-39)
//	kms/pkg/mnemonic → kms/pkg/envelope  (IdentityHeader, Signer)
//	kms/pkg/mnemonic → kms/pkg/zapclient (DialWithConfig, GetAt)
//	luxfi/keys       ⇏ kms               (never — no back edge)
//
// Separation of concerns:
//
//   - zap (the protocol)         → github.com/luxfi/zap
//   - kms/pkg/zapclient          → opaque GetAt over native ZAP
//   - kms/pkg/envelope           → signed-envelope identity surface
//   - luxfi/keys.ServiceIdentity → mnemonic-derived signer (ML-DSA-65)
//   - this package               → BIP-39 validation + the env-vs-KMS
//     precedence chain
//
// Precedence (env wins; KMS is the production fallback):
//
//  1. MNEMONIC env var               local dev + CI test seam
//  2. KMS at (addr, env, path)       native ZAP from KMS
package mnemonic

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	bip39 "github.com/luxfi/go-bip39"
	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
	"github.com/luxfi/kms/pkg/zapclient"
)

// Reader is the minimum surface LoadFromKMS needs from a KMS client.
// The real *zapclient.Client satisfies it; tests inject fakes via the
// dialKMS seam below.
type Reader interface {
	GetAt(ctx context.Context, path, name, env string) (string, error)
	Close()
}

// dialKMS is the production seam. Tests override it to inject a fake
// without touching the network.
//
// identity is REQUIRED for the production path (the KMS server's
// consensus-auth gate rejects envelopes without a signed identity).
// Passing nil dials anonymously — accepted only by legacy KMS peers
// that have explicitly disabled the auth gate (dev / loopback only),
// and by the bootstrap loader where no identity exists yet (the
// mnemonic being loaded is itself the root every later identity
// derives from).
var dialKMS = func(ctx context.Context, addr string, identity *keys.ServiceIdentity) (Reader, error) {
	cfg := zapclient.Config{PeerAddr: addr}
	if identity != nil {
		cfg.IdentityHeader = envelope.IdentityHeader{
			NodeID:      identity.NodeID,
			FullDigest:  identity.FullDigest,
			ServicePath: identity.ServicePath,
			PublicKey:   identity.PublicKey,
		}
		// *keys.ServiceIdentity satisfies envelope.Signer (Sign binds
		// the FullDigest into the prehash).
		cfg.Signer = identity
	}
	c, err := zapclient.DialWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Load returns the BIP-39 mnemonic for the calling service. MNEMONIC
// env wins when set; otherwise dials KMS over native ZAP at addr and
// reads the secret at path under env.
//
//	ctx      cancellable context
//	addr     KMS host:port (e.g. "kms.default.svc:9999")
//	env      KMS env scope ("mainnet" | "testnet" | "devnet")
//	path     KMS secret path (e.g. "/mnemonic" or "/foo/master")
//	identity ServiceIdentity to sign the secret-opcode envelope. May
//	         be nil for the env-win short-circuit (the KMS dial is
//	         never reached), for legacy peers, and for the bootstrap
//	         loader; required for production peers whose consensus-auth
//	         gate is engaged.
//
// Returns the validated BIP-39 phrase. The caller is responsible for
// keeping it on the goroutine stack and not logging / persisting it.
func Load(ctx context.Context, addr, env, path string, identity *keys.ServiceIdentity) (string, error) {
	if e := strings.TrimSpace(os.Getenv("MNEMONIC")); e != "" {
		if !bip39.IsMnemonicValid(e) {
			return "", errors.New("MNEMONIC env is not a valid BIP-39 phrase")
		}
		return e, nil
	}
	return LoadFromKMS(ctx, addr, env, path, identity)
}

// LoadFromKMS is the production-only path (no MNEMONIC env
// short-circuit). Useful when a caller wants to force the KMS read
// regardless of ambient env — e.g., a regression test pinning the
// production code path.
//
// identity is the *keys.ServiceIdentity threaded into the ZAP dial:
// its public block becomes the envelope IdentityHeader and the same
// identity signs every secret-opcode envelope. Pass nil only when
// dialling a legacy KMS peer with the consensus-auth gate disabled, or
// from the bootstrap loader (dev / loopback fakes — see the dialKMS
// seam).
func LoadFromKMS(ctx context.Context, addr, env, path string, identity *keys.ServiceIdentity) (string, error) {
	if addr == "" {
		return "", errors.New("mnemonic: KMS addr is required")
	}
	if env == "" {
		return "", errors.New("mnemonic: KMS env is required")
	}
	if path == "" {
		return "", errors.New("mnemonic: KMS path is required")
	}

	c, err := dialKMS(ctx, addr, identity)
	if err != nil {
		return "", fmt.Errorf("dial KMS %s: %w", addr, err)
	}
	defer c.Close()

	dir, name := SplitSecretPath(path)
	v, err := c.GetAt(ctx, dir, name, env)
	if err != nil {
		return "", fmt.Errorf("read mnemonic (path=%q name=%q env=%q): %w",
			dir, name, env, err)
	}
	m := strings.TrimSpace(v)
	if m == "" {
		return "", fmt.Errorf("mnemonic at %q is empty", path)
	}
	if !bip39.IsMnemonicValid(m) {
		return "", errors.New("mnemonic from KMS is not a valid BIP-39 phrase")
	}
	return m, nil
}

// SplitSecretPath turns "/foo/bar/baz" into ("/foo/bar/", "baz"). When
// there is no '/' or only a leading one, the directory is "" and the
// whole remainder is the name (e.g., "/mnemonic" → ("", "mnemonic")).
//
// Exported so every consumer addresses secrets with the same
// convention — one and only one addressing scheme across mnemonic,
// staking keys, gas-payer keys, etc.
func SplitSecretPath(full string) (dir, name string) {
	full = strings.TrimSpace(full)
	full = strings.TrimPrefix(full, "/")
	i := strings.LastIndex(full, "/")
	if i < 0 {
		return "", full
	}
	return "/" + full[:i+1], full[i+1:]
}
