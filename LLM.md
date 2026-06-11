# KMS — AI Assistant Knowledge Base

**Project**: Lux Key Management Service (KMS)
**Organization**: Lux Network

## One KMS per org. Env is a field, not a hostname.

There is one KMS endpoint per org. Every caller — devnet, testnet,
mainnet — points at the same `kms.lux.network` for Lux (or
`kms.hanzo.ai` for Hanzo, Zoo, Pars). The env (`dev` / `test` /
`main`) is a field on each secret, passed as `?env=` on GET/DELETE
and the `env` JSON field on POST. No `kms.dev.*` / `kms.test.*`
hostnames; that shape is removed.

## Mnemonic + key derivation

One BIP39 mnemonic is shared across all Lux-derived L1s (Lux, Hanzo,
Zoo, Pars). Each chain reads it from `providers/<org>/deploy-mnemonic`
under its own org-scoped JWT — same bytes, different KMS paths, N
independent auth boundaries. Each tenant is jurisdictionally separate
and holds its own mnemonic in `providers/<org>/*`. See
`~/work/lux/CLAUDE.md` §"Mnemonic + Key Derivation" for the
canonical reference (paths, derivation formula, IAM apps required).

The IAM apps `lux-kms`, `hanzo-kms`, `zoo-kms`, `pars-kms` (all owner
admin, organization=<org>) MUST carry `client_credentials` in
`grant_types`. The canonical `/v1/kms/auth/login` forwards to IAM's
`/login/oauth/access_token` with that grant_type; if the app is
missing it, login returns 401 "invalid credentials". Fix by updating
the IAM `application.grant_types` JSON to include the value and
restart the IAM pod (it caches application records in-memory).

## MPC-rooted Root Encryption Key (2026-06-07)

The master-key split-brain that paused the Casibase→lux-kms-go cluster
rewrite is resolved by sourcing the Root Encryption Key (REK) from a
luxfi/mpc threshold cluster instead of a static K8s Secret env var.

### Boundary

```
KMS pod (one process)
  ↑ on boot, ONCE
  ↑ mpcrek.Bootstrap (pkg/store/mpcrek)
  ↑ → pkg/mpc.ZapClient.Decrypt(keyID="kms/rek/v1")
  ↑
luxfi/mpc cluster (t-of-n)
  - stores the wrapped REK as its own threshold record
  - returns the unwrapped 32-byte REK over the AEAD-sealed ZAP wire
    (X25519+ML-KEM-768 hybrid handshake)
```

The unwrapped REK lives only in the KMS pod's heap from boot to
shutdown. `defer mpcrek.Zero(rek)` in `main()` overwrites the slice on
the way out (best-effort — Go GC offers no harder guarantee). The
existing AES-256-GCM envelope (`pkg/store/crypto.go`) is untouched: it
still wraps every per-secret DEK under that 32-byte REK with AAD binding
path/name/env.

### Env contract (cmd/kms)

- `MPC_REK_ENDPOINT` — CSV of MPC `host:port`. When set, kmsd FAILS
  CLOSED on any bootstrap failure (no fallback to env-var REK; that
  would re-open the split-brain).
- `MPC_REK_KEY_ID` — MPC-side identifier, default `kms/rek/v1`. Bump
  per epoch on reshare.
- `MPC_REK_TIMEOUT` — Go duration, default `10s`.
- `KMS_MASTER_KEY_B64` — LEGACY 32-byte master key (base64). Used only
  when `MPC_REK_ENDPOINT` is unset. Slated for removal after every
  deployment migrates.

### Casibase migration (`cmd/casibase-import`)

The ~50 secrets in `hanzo/kms` (Casibase Node-Fastify
`ghcr.io/hanzoai/kms:1.0.7`) are sealed under the Casibase
`ROOT_ENCRYPTION_KEY` env var. lux-kms-go uses an incompatible envelope
under an MPC-rooted REK. The one-shot bridge is `cmd/casibase-import`:

```
$ kubectl exec -n hanzo deploy/casibase-kms -- /api/v3/secrets/raw?... > dump.json
$ MPC_REK_ENDPOINT=mpc-0.lux-mpc.svc:9999,... casibase-import \
    --in dump.json \
    --old-key-file ./casibase-root.key \
    --data-dir /data/kms \
    --dry-run            # verify decode first
$ casibase-import --in dump.json --old-key-file ./casibase-root.key --data-dir /data/kms
```

Status: SCAFFOLDED. The new-side (Seal under MPC-rooted REK, Put into
ZapDB) is complete. The Casibase decoder stub
(`cmd/casibase-import/main.go::decryptCasibase`) returns `not yet
implemented` until the Casibase v1.0.7 envelope format is decoded — see
the function's godoc for the extension point. The Casibase encryption
code at `hanzoai/kms@1.0.7:src/services/secret/encrypt.ts` is the
reference; once decoded here, the tool decrypts under the supplied OLD
key and re-seals under the live cluster's REK epoch.

### Re-key (REK rotation)

Out of scope for this PR. Design hook:

1. Operator triggers MPC reshare ceremony for `kms/rek/v(N+1)`.
2. Run `cmd/rek-rotate` (future): bootstrap epoch N + epoch N+1, walk
   every record in ZapDB, Open under N, Seal under N+1, Put.
3. Roll KMS pods with `MPC_REK_KEY_ID=kms/rek/v(N+1)`.

Replica coordination during the migration window: every replica fetches
the same epoch N+1 from MPC (the cluster is the single source of
truth), so cross-replica consistency is automatic. There is no leader
election in KMS; the migration tool runs once from any pod or any
out-of-cluster operator with the MPC bearer.

### What this PR does NOT change

- The per-secret AES-256-GCM envelope shape (`pkg/store/crypto.go`).
- The ZapDB-at-rest encryption (`KMS_ENCRYPTION_KEY_B64`, separate
  knob, controls Badger-level encryption — orthogonal to the
  application envelope).
- The IAM JWT validation at the HTTP edge.
- The ZAP secrets-server wire shape (`pkg/zapserver`, `pkg/zapclient`).

### LP-103 bearer-mint (still future)

The published `pkg/zap/handshake.go` does not yet check `OpAuthHello`,
and the in-tree `pkg/mpc/zap_client.go` does not yet mint one. The
KMS↔MPC ZAP wire is currently authenticated at the K8s NetworkPolicy
layer, not the application layer. LP-103 introduces the bearer-on-
handshake check; it is a separate PR. When it lands, `mpcrek.Bootstrap`
gains a bearer parameter and `MPC_REK_ENDPOINT` becomes
mutual-auth-only. The wire-level upgrade is forward-compatible: until
MPC requires the bearer (`ZAP_AUTH_REQUIRED=true`) the existing
unauthenticated dial continues to work.

## v1.9.0 — pkg/iamclient + ZAP bearer-on-handshake (LP-103)

Pairs with luxfi/mpc v1.14.0 pkg/zapauth. KMS mints an OAuth2
client_credentials JWT against Hanzo IAM, caches per audience with
60-second early refresh, attaches it via OpAuthHello (0x00EF) BEFORE
the existing X25519+ML-KEM-768 handshake.

Env vars (all optional; if KMS_ZAP_AUTH_ENABLED unset/false the
client behaves exactly as v1.8.x):

  KMS_ZAP_AUTH_ENABLED      true|false (default false)
  KMS_IAM_URL               e.g. http://iam.lux.svc:8000
  KMS_IAM_CLIENT_ID         default "kms"
  KMS_IAM_CLIENT_SECRET     from KMS-projected universal-auth Secret
  KMS_ZAP_AUDIENCE          default "mpc"

When enabled, mpc.NewZapClientWith dials, then sends OpAuthHello;
a non-2xx-shaped {"ok":true} reply fails NewZapClient — operators
must roll MPC to v1.14.0+ before flipping the flag.

## Fail-open MPC boot (v1.8.2+)

KMS no longer log.Fatalf's when MPC is unreachable at boot. If
`MPC_VAULT_ID` is set but the ZAP probe fails, KMS:
- logs a warning,
- runs in secrets-only mode (secrets-server, IAM SSO, secret routes
  fully functional),
- responds 503 on `/v1/kms/keys/*` with body
  `{"error":"mpc unreachable","mode":"secrets-only","detail":"..."}`,
- reports `status=degraded` on `/healthz` (still HTTP 200 — readiness
  must not flap a working secrets surface out of rotation).

Each request to `/v1/kms/keys/*` re-probes MPC, so the same pod
recovers transparently when MPC comes back; no restart needed.

## Project Overview

KMS is an MPC-backed key management service for the Lux Network. It manages validator keys, threshold signing, secret storage, and key rotation using distributed Multi-Party Computation.

**No Infisical. No PostgreSQL. No Node.js.** The active server is a pure Go binary in `cmd/kms/` backed by `luxfi/mpc` for threshold cryptography and `luxfi/zapdb` for storage.

## Architecture

```
Client (ATS/BD/TA) → KMS (Go, :8080) → MPC (CGGMP21/FROST, via ZAP)
                               │
                          ZapDB (embedded)
                               │
                          ZapDB Replicator
                               │
                          S3 (age-encrypted)
```

### Storage: ZapDB (not SQLite, not PostgreSQL)

KMS uses `luxfi/zapdb` as its embedded storage engine. ZapDB is a Badger-derived LSM key-value store with built-in encrypted replication to S3.

**Why ZapDB over Base/SQLite:**
- Built-in `Replicator` with incremental + snapshot backup to S3 (no sidecar, no plugin)
- Age encryption on all replicated data; the active envelope is AES-256-GCM with X25519 key wrapping. X-Wing / ML-KEM-768 hybrid wrapping is roadmap, not in production.
- No WAL locking issues with single-writer — ZapDB handles concurrency natively
- Redis-compatible bindings available (`zapdb/bindings/`) for cache interop
- Eliminates the `hanzoai/base` dependency and its SQLite/Postgres abstraction layer

**S3 replication layout:**
```
s3://lux-kms-backups/kms/{node-id}/
  ├── snap/{timestamp}.zap.age     # hourly full snapshots
  └── inc/{version}.zap.age        # 1s incremental backups
```

### Signing: MPC (not standalone crypto)

All key operations delegate to the MPC service at `~/work/lux/mpc/`. KMS never holds private key material — it holds metadata (validator IDs, wallet IDs, public keys, policy) and delegates all cryptographic operations to MPC.

**Two transport paths to MPC:**
- **ZAP (preferred, in-cluster):** `pkg/mpc/zap_client.go` — binary protocol over `luxfi/zap`, opcodes 0x0001-0x0031
- **HTTP (fallback, cross-cluster):** `pkg/mpc/client.go` — REST API over HTTP

**MPC operations:**
| Operation | Protocol | Opcode | HTTP Endpoint |
|-----------|----------|--------|---------------|
| Status | — | 0x0001 | GET /v1/status |
| Keygen | CGGMP21/FROST | 0x0010 | POST /v1/vaults/{id}/wallets |
| Sign | CGGMP21/FROST | 0x0011 | POST /v1/transactions |
| Reshare | CGGMP21/FROST | 0x0012 | POST /v1/wallets/{id}/reshare |
| GetWallet | — | 0x0020 | GET /v1/wallets/{id} |
| Encrypt | AES-GCM/TFHE | 0x0030 | POST /v1/fhe/encrypt |
| Decrypt | AES-GCM/TFHE | 0x0031 | POST /v1/fhe/decrypt |

### Auth: Hanzo IAM (JWKS validation)

KMS validates JWTs from Hanzo IAM via JWKS endpoint. All key management routes require superuser auth. Secret routes use per-principal access control.

### Encryption: KMS-native Transit Engine (EaaS)

The `pkg/store/crypto.go` implements envelope encryption:
- Per-secret random 256-bit DEK
- DEK wrapped under master key (AES-256-GCM)
- v2 path: ML-KEM-768 wrapping (PQ-safe)
- Threshold schemes: TFHE (secret reveal), CKKS (ML compute)

## Active code paths

| Path | Language | Purpose |
|------|----------|---------|
| `kms.go` | Go | **Canonical client API** — `kms.{Get,GetSecrets,LoadEnv}` |
| `cmd/kms/` | Go | Server entrypoint |
| `pkg/keys/` | Go | Key lifecycle (generate, sign, rotate) — delegates to MPC |
| `pkg/attestation/` | Go | Composite confidential-attestation gate for epoch-key release (mirrors luxcpp/crypto/attestation C ABI) |
| `pkg/mpc/` | Go | MPC client (ZAP + HTTP transports to luxfi/mpc daemon) |
| `pkg/store/` | Go | ZapDB-backed metadata + secret store |
| `pkg/zapclient/` | Go | Low-level ZAP client (used by root `kms` package) |
| `pkg/zapserver/` | Go | ZAP server exposing SecretStore over luxfi/zap |
| `k8s/` | YAML | K8s manifests (StatefulSet + Service) |

## Canonical client usage

```go
import "github.com/luxfi/kms"

// One line at process start — populates os.Setenv with every secret.
func main() {
    kms.LoadEnv()
    db := os.Getenv("DATABASE_URL")
    run(db)
}

// Programmatic fetch:
v, err   := kms.Get(ctx, "DATABASE_URL")
all, err := kms.GetSecrets(ctx)
```

**Defaults** (override via env vars):

| Var | Default | Purpose |
|-----|---------|---------|
| `KMS_ADDR` | `zap.kms.svc.cluster.local:9999` | KMS host:port |
| `KMS_PATH` | `/` | secret path prefix |
| `KMS_ENV` | `default` | secret environment slug |

Transport is always native ZAP — there is no HTTP fallback in the Go client.

### Legacy code (not used by Go server)

| Path | Status | Notes |
|------|--------|-------|
| `backend/` | Legacy | Old Node.js/Fastify backend (from Infisical fork) |
| `frontend/` | Legacy | Old React dashboard |

## Key concepts

- **Validator Key Set**: A pair of MPC wallets (BLS secp256k1 + Corona ed25519) for a single validator
- **MPC DKG**: Distributed Key Generation — no single party ever holds the full private key
- **Threshold signing**: K-of-N parties must cooperate to produce a signature
- **Key rotation**: Reshare keys with new threshold or participant set without changing public key
- **ZapDB Replicator**: In-process encrypted streaming backup to S3 (incremental 1s + snapshot 1h)

## API routes

```
POST   /v1/kms/keys/generate      Generate validator key set (via MPC DKG)
GET    /v1/kms/keys                List all key sets
GET    /v1/kms/keys/{id}           Get key set by ID
POST   /v1/kms/keys/{id}/sign     Sign (key_type: "bls" or "Corona", delegates to MPC)
POST   /v1/kms/keys/{id}/rotate   Reshare with new threshold/participants (via MPC)
GET    /v1/kms/status              KMS + MPC cluster status
GET    /healthz                    Health check
POST   /v1/kms/auth/login          Machine identity auth (IAM client_credentials)
GET    /v1/kms/secrets/{name}       Raw secret fetch
```

### ZAP transport (in-cluster, no HTTP)

```
OpSecretGet    0x0040   { path, name, env }         → { value: base64 }
OpSecretPut    0x0041   { path, name, env, value }   → { ok: true }
OpSecretList   0x0042   { path, env }               → { names: [] }
OpSecretDelete 0x0043   { path, name, env }         → { ok: true }
```

## Configuration (env vars)

| Var | Default | Purpose |
|-----|---------|---------|
| `MPC_ADDR` | (empty) | ZAP address (host:port); empty = mDNS discovery (dev only) |
| `MPC_VAULT_ID` | (required) | MPC vault ID for validator keys |
| `KMS_NODE_ID` | `kms-0` | ZAP node ID |
| `ZAP_PORT` | `9999` | ZAP secrets-server listen port (0 = disable) |
| `KMS_MASTER_KEY_B64` | — | 32-byte master key (base64) for SecretStore envelope |
| `KMS_DATA_DIR` | `/data/kms` | ZapDB data directory |
| `IAM_ENDPOINT` | `https://hanzo.id` | Hanzo IAM for auth |
| `REPLICATE_S3_ENDPOINT` | — | S3 endpoint for ZapDB replication |
| `REPLICATE_S3_BUCKET` | `lux-kms-backups` | S3 bucket |
| `REPLICATE_AGE_RECIPIENT` | — | Age public key for backup encryption |
| `REPLICATE_AGE_IDENTITY` | — | Age private key for restore decryption |

## K8s Deployment

StatefulSet (replicas=1) with PVC for ZapDB data. ZapDB Replicator runs in-process (no sidecar).

**Ports:**
- 8080: HTTP API (health, keys, secrets, auth)
- 9999: ZAP secrets server (in-cluster binary transport)

**Volumes:**
- `/data/kms`: ZapDB data directory (PVC, 5Gi)

**Connections:**
- MPC daemon: via ZAP (in-cluster) or HTTP (cross-cluster)
- S3: ZapDB Replicator (incremental + snapshot, age-encrypted)
- IAM: JWKS validation over HTTPS

## Integration

- **Auth**: Hanzo IAM JWT tokens (JWKS validation)
- **Callers**: ATS, BD, TA (all Go services)
- **Crypto**: luxfi/mpc (CGGMP21 for ECDSA, FROST for EdDSA)
- **Transport**: ZAP (luxfi/zap) for MPC communication and secret serving
- **Storage**: ZapDB (luxfi/zapdb) embedded — no external database
- **Replication**: ZapDB Replicator in-process (S3 + age encryption)
- **No lux/base fork**: KMS imports `luxfi/zapdb` directly for storage

## Dependencies

- `github.com/luxfi/zapdb` — embedded KV store with S3 replication
- `github.com/luxfi/zap` — binary transport protocol (MPC + secrets)
- `github.com/luxfi/age` — age encryption for S3 backups
- `github.com/luxfi/mpc` — MPC daemon (external service, not imported)
