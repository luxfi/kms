// Command casibase-import re-wraps Casibase-era secrets under the new
// MPC-rooted REK and writes them into the lux-kms-go ZapDB.
//
// # Why this exists
//
// As of 2026-05-15 the do-sfo3-hanzo-k8s cluster holds ~50 KMSSecrets
// in the Casibase Node-Fastify KMS (`hanzoai/kms:1.0.7`). Their on-disk
// envelope is Casibase's own format, sealed under the
// `ROOT_ENCRYPTION_KEY` env var on the Casibase pod. lux-kms-go uses a
// different envelope (`pkg/store/crypto.go` AES-256-GCM, REK from MPC).
// The two key domains are independent — there is no automatic rotation
// path between them.
//
// This tool is the one-shot bridge: read every Casibase secret, decrypt
// under the OLD key (operator supplies it on stdin or via file), re-seal
// under the NEW MPC-rooted REK, write into ZapDB.
//
// # Usage
//
//	$ kubectl exec -n hanzo deploy/casibase-kms -- /api/v3/secrets/raw?... \
//	    > casibase-dump.json
//	$ casibase-import \
//	    --in casibase-dump.json \
//	    --old-key-file ./casibase-root.key \
//	    --data-dir /data/kms \
//	    --dry-run
//	$ casibase-import --in casibase-dump.json \
//	    --old-key-file ./casibase-root.key \
//	    --data-dir /data/kms
//
// MPC_REK_ENDPOINT + MPC_REK_KEY_ID must be set (same env contract as
// the KMS server). The tool fetches the NEW REK exactly once, the same
// way kmsd does at boot, so the re-wrap target is the live cluster's
// REK epoch.
//
// # Why this is a tool, not a server feature
//
// 1. It's one-shot: after the migration the Casibase pod is scaled to
//    zero and this code is dead. Folding it into the server would
//    leave permanent attack surface (a "decrypt-under-legacy-key" API)
//    for a one-week event.
// 2. The OLD key has to be supplied by an operator. There's no safe
//    way to embed that in the server — the only correct flow is for
//    a human to mount it transiently into a one-shot pod, run this
//    tool, and remove the secret.
// 3. The Casibase envelope format is foreign. Decoupling it as its
//    own binary means the kmsd code does not have to maintain a
//    second envelope code path.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/store/mpcrek"
	badger "github.com/luxfi/zapdb"
)

// casibaseDump is the on-wire shape from `GET /api/v3/secrets/raw`.
// Each entry is one secret; ciphertext is base64'd, OldKeyID identifies
// the Casibase envelope variant if Casibase ever shipped multiple.
//
// This struct mirrors the Casibase v1.0.7 export format. If the format
// changes, update the JSON tags accordingly.
type casibaseDump struct {
	Secrets []casibaseSecret `json:"secrets"`
}

type casibaseSecret struct {
	Workspace  string `json:"workspaceSlug"`
	SecretPath string `json:"secretPath"`
	SecretKey  string `json:"secretKey"`
	Env        string `json:"environment"`
	// CiphertextB64 is the base64 of the Casibase-format envelope. This
	// is NOT compatible with pkg/store.Open — it must be decoded by
	// decryptCasibase below before re-sealing.
	CiphertextB64 string `json:"ciphertextB64"`
}

func main() {
	in := flag.String("in", "", "path to casibase JSON dump (required)")
	oldKeyFile := flag.String("old-key-file", "", "path to base64-encoded Casibase ROOT_ENCRYPTION_KEY (required)")
	dataDir := flag.String("data-dir", "/data/kms", "ZapDB data directory to write into")
	dryRun := flag.Bool("dry-run", false, "decode and verify only; do not write")
	flag.Parse()

	if *in == "" || *oldKeyFile == "" {
		flag.Usage()
		os.Exit(2)
	}

	dump, err := readDump(*in)
	if err != nil {
		log.Fatalf("casibase-import: read dump: %v", err)
	}
	log.Printf("casibase-import: loaded %d secrets from %s", len(dump.Secrets), *in)

	oldKey, err := readOldKey(*oldKeyFile)
	if err != nil {
		log.Fatalf("casibase-import: read old key: %v", err)
	}
	defer mpcrek.Zero(oldKey)

	// Fetch the NEW REK from MPC. Same env contract as kmsd boot.
	newREK, err := bootstrapNewREK()
	if err != nil {
		log.Fatalf("casibase-import: bootstrap new REK: %v", err)
	}
	defer mpcrek.Zero(newREK)

	var db *badger.DB
	var secStore *store.SecretStore
	if !*dryRun {
		opts := badger.DefaultOptions(*dataDir)
		db, err = badger.Open(opts)
		if err != nil {
			log.Fatalf("casibase-import: open zapdb %s: %v", *dataDir, err)
		}
		defer db.Close()
		secStore = store.NewSecretStore(db)
	}

	var ok, failed int
	for _, s := range dump.Secrets {
		plaintext, err := decryptCasibase(oldKey, s)
		if err != nil {
			log.Printf("casibase-import: FAIL decrypt workspace=%s path=%s name=%s: %v",
				s.Workspace, s.SecretPath, s.SecretKey, err)
			failed++
			continue
		}

		// Re-seal under the new MPC-rooted REK using pkg/store.Seal.
		// AAD bindings (path / name / env) and per-secret DEK come for
		// free; we just produce the new envelope.
		path := s.SecretPath
		if path == "" {
			path = "/" + s.Workspace
		}
		env := s.Env
		if env == "" {
			env = "default"
		}
		secret, err := store.Seal(newREK, path, s.SecretKey, env, plaintext)
		// Zero plaintext immediately after Seal returns.
		mpcrek.Zero(plaintext)
		if err != nil {
			log.Printf("casibase-import: FAIL seal workspace=%s name=%s: %v", s.Workspace, s.SecretKey, err)
			failed++
			continue
		}

		if *dryRun {
			log.Printf("casibase-import: OK (dry-run) workspace=%s path=%s name=%s env=%s",
				s.Workspace, path, s.SecretKey, env)
		} else {
			if err := secStore.Put(secret); err != nil {
				log.Printf("casibase-import: FAIL put workspace=%s name=%s: %v", s.Workspace, s.SecretKey, err)
				failed++
				continue
			}
			log.Printf("casibase-import: OK workspace=%s path=%s name=%s env=%s",
				s.Workspace, path, s.SecretKey, env)
		}
		ok++
	}

	log.Printf("casibase-import: done — %d ok, %d failed (dry-run=%v)", ok, failed, *dryRun)
	if failed > 0 {
		os.Exit(1)
	}
}

func readDump(path string) (*casibaseDump, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d casibaseDump
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return &d, nil
}

func readOldKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Strip trailing newlines.
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	k, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("key length %d, want 32", len(k))
	}
	return k, nil
}

func bootstrapNewREK() ([]byte, error) {
	endpoint := os.Getenv("MPC_REK_ENDPOINT")
	if endpoint == "" {
		return nil, errors.New("MPC_REK_ENDPOINT is required (same env contract as kmsd)")
	}
	keyID := os.Getenv("MPC_REK_KEY_ID")
	if keyID == "" {
		keyID = "kms/rek/v1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return mpcrek.Bootstrap(ctx, mpcrek.Config{
		Endpoint: endpoint,
		KeyID:    keyID,
		NodeID:   "casibase-import",
		Timeout:  10 * time.Second,
	})
}

// decryptCasibase decodes a Casibase v1.0.7 envelope under the OLD
// ROOT_ENCRYPTION_KEY. SCAFFOLDED: the Casibase wire format is not
// documented in this tree. To finish, replace this function body with
// the format-correct decoder. The Casibase source is at
// hanzoai/kms@1.0.7 (Node-Fastify); the encryption code lives in its
// `src/services/secret/encrypt.ts`. As of 2026-05-15 the deployed
// envelope is AES-256-GCM with a 12-byte nonce and 16-byte tag inside
// a custom binary header.
//
// Replace stub with one of:
//   - Direct base64 + AES-GCM under oldKey (if no Casibase header).
//   - Casibase header parse + AES-GCM under oldKey.
//
// The Open contract: take the OLD key + the dumped record, return
// plaintext bytes. On any failure (bad tag, wrong key, malformed
// header) return a non-nil error and the caller skips this record.
func decryptCasibase(oldKey []byte, s casibaseSecret) ([]byte, error) {
	if len(oldKey) != 32 {
		return nil, fmt.Errorf("old key length %d, want 32", len(oldKey))
	}
	_ = s.CiphertextB64 // silence unused until the decoder lands

	// TODO(operator): decode the Casibase envelope. See package doc.
	return nil, errors.New("casibase decoder not yet implemented — see decryptCasibase godoc")
}
