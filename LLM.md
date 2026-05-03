# KMS — AI Assistant Knowledge Base

**Last Updated**: 2026-05-02
**Project**: Lux Key Management Service (KMS)
**Organization**: Lux Network

## v1.9.0 — pkg/iamclient + ZAP bearer-on-handshake (LP-103)

Pairs with luxfi/mpc v1.14.0 pkg/zapauth. KMS mints an OAuth2
client_credentials JWT against Hanzo IAM, caches per audience with
60-second early refresh, attaches it via OpAuthHello (0x00EF) BEFORE
the existing X25519+ML-KEM-768 handshake.

Env vars (all optional; if KMS_ZAP_AUTH_ENABLED unset/false the
client behaves exactly as v1.8.x):

  KMS_ZAP_AUTH_ENABLED      true|false (default false)
  KMS_IAM_URL               e.g. http://liquid-iam.liquidity.svc:8000
  KMS_IAM_CLIENT_ID         default "liquid-kms"
  KMS_IAM_CLIENT_SECRET     from KMS-projected universal-auth Secret
  KMS_ZAP_AUDIENCE          default "liquid-mpc"

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

- **Validator Key Set**: A pair of MPC wallets (BLS secp256k1 + Ringtail ed25519) for a single validator
- **MPC DKG**: Distributed Key Generation — no single party ever holds the full private key
- **Threshold signing**: K-of-N parties must cooperate to produce a signature
- **Key rotation**: Reshare keys with new threshold or participant set without changing public key
- **ZapDB Replicator**: In-process encrypted streaming backup to S3 (incremental 1s + snapshot 1h)

## API routes

```
POST   /v1/kms/keys/generate      Generate validator key set (via MPC DKG)
GET    /v1/kms/keys                List all key sets
GET    /v1/kms/keys/{id}           Get key set by ID
POST   /v1/kms/keys/{id}/sign     Sign (key_type: "bls" or "ringtail", delegates to MPC)
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
