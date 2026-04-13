# Lux KMS — AI Assistant Knowledge Base

**Last Updated**: 2026-03-25
**Project**: Lux Key Management Service (KMS)
**Organization**: Lux Network

## Project Overview

Lux KMS is an MPC-backed key management service for the Lux Network. It manages validator keys, threshold signing, and key rotation using distributed Multi-Party Computation.

**No Infisical. No PostgreSQL. No Node.js.** The active server is a pure Go binary in `cmd/kms/` backed by `luxfi/mpc` for threshold cryptography.

## Architecture

```
Client (ATS/BD/TA) → Lux KMS (Go, :8080) → Lux MPC (CGGMP21/FROST, via ZAP)
                                │
                         Hanzo Base DB
                         (SQLite local / Postgres prod)
```

### Active code paths

| Path | Language | Purpose |
|------|----------|---------|
| `cmd/kms/` | Go | Server entrypoint |
| `pkg/server/` | Go | HTTP API (chi router) |
| `pkg/keys/` | Go | Key lifecycle (generate, sign, rotate) |
| `pkg/mpc/` | Go | MPC client (calls luxfi/mpc daemon) |
| `pkg/store/` | Go | Base-backed metadata store (SQLite/Postgres) |
| `k8-operator/` | Go | K8s operator for KmsSecret/KmsDynamicSecret/KmsPushSecret CRDs |

### Legacy code (not used by Go server)

| Path | Status | Notes |
|------|--------|-------|
| `backend/` | Legacy | Old Node.js/Fastify backend (from Infisical fork) |
| `frontend/` | Legacy | Old React dashboard |
| `nginx/` | Legacy | Not used — we use hanzoai/ingress |
| `helm-charts/` | Legacy | Old Helm charts for Infisical deployment |
| `compose.*.yml` | Legacy | Docker compose for old stack |

## Key concepts

- **Validator Key Set**: A pair of MPC wallets (BLS secp256k1 + Ringtail ed25519) for a single validator
- **MPC DKG**: Distributed Key Generation — no single party ever holds the full private key
- **Threshold signing**: K-of-N parties must cooperate to produce a signature
- **Key rotation**: Reshare keys with new threshold or participant set without changing public key

## API routes

```
POST   /v1/keys/generate      Generate validator key set
GET    /v1/keys                List all key sets
GET    /v1/keys/{id}           Get key set by ID
POST   /v1/keys/{id}/sign     Sign (key_type: "bls" or "ringtail")
POST   /v1/keys/{id}/rotate   Reshare with new threshold/participants
GET    /v1/status              KMS + MPC status
GET    /healthz                Health check
```

## Configuration (env vars)

- `MPC_ADDR` — ZAP address (host:port); empty = mDNS discovery (dev only)
- `MPC_VAULT_ID` — MPC vault ID (required)
- `KMS_NODE_ID` — ZAP node ID (default `kms-0`)

## Integration

- Auth: Hanzo IAM JWT tokens (JWKS validation)
- Callers: ATS, BD, TA (all hanzoai/base Go services)
- Crypto: luxfi/mpc (CGGMP21 for ECDSA, FROST for EdDSA)
- Transport: ZAP (luxfi/zap) for MPC communication — no HTTP to MPC daemon
- Deployment: K8s Deployment (replicas=1 for SQLite) + PVC for data persistence
- Multi-replica requires PostgreSQL backend (BASE_DB_URL env var)
- Replication: in-process via `hanzoai/base/plugins/replicate` (no sidecar). Set `REPLICATE_S3_ENDPOINT` to enable.
- Base module: v0.40.3+ (replicate plugin added in v0.40.0)
- Local dev replace: `github.com/hanzoai/replicate => /Users/z/work/hanzo/replicate`
- No lux/base fork exists -- both lux/kms and hanzo/kms import `github.com/hanzoai/base` directly
