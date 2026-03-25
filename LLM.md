# Lux KMS — AI Assistant Knowledge Base

**Last Updated**: 2026-03-25
**Project**: Lux Key Management Service (KMS)
**Organization**: Lux Network

## Project Overview

Lux KMS is an MPC-backed key management service for the Lux Network. It manages validator keys, threshold signing, and key rotation using distributed Multi-Party Computation.

**No Infisical. No PostgreSQL. No Node.js.** The active server is a pure Go binary in `cmd/kms/` backed by `luxfi/mpc` for threshold cryptography.

## Architecture

```
Client (ATS/BD/TA) → Lux KMS (Go, :8080) → Lux MPC (CGGMP21/FROST, :8081)
                                │
                         JSON file store
                         (keys.json)
```

### Active code paths

| Path | Language | Purpose |
|------|----------|---------|
| `cmd/kms/` | Go | Server entrypoint |
| `pkg/server/` | Go | HTTP API (chi router) |
| `pkg/keys/` | Go | Key lifecycle (generate, sign, rotate) |
| `pkg/mpc/` | Go | MPC client (calls luxfi/mpc daemon) |
| `pkg/store/` | Go | JSON file-backed metadata store |
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
POST   /api/v1/keys/generate      Generate validator key set
GET    /api/v1/keys                List all key sets
GET    /api/v1/keys/{id}           Get key set by ID
POST   /api/v1/keys/{id}/sign     Sign (key_type: "bls" or "ringtail")
POST   /api/v1/keys/{id}/rotate   Reshare with new threshold/participants
GET    /api/v1/status              KMS + MPC status
GET    /healthz                    Health check
```

## Configuration (env vars)

- `KMS_LISTEN` — HTTP listen address (default `:8080`)
- `MPC_URL` — MPC daemon URL (default `http://mpc-api.lux-mpc.svc.cluster.local:8081`)
- `MPC_TOKEN` — MPC API auth token
- `MPC_VAULT_ID` — MPC vault ID (required)
- `KMS_STORE_PATH` — metadata store path (default `/data/kms/keys.json`)

## Integration

- Auth: Hanzo IAM JWT tokens (JWKS validation)
- Callers: ATS, BD, TA (all hanzoai/base Go services)
- Crypto: luxfi/mpc (CGGMP21 for ECDSA, FROST for EdDSA)
- Deployment: K8s Deployment + PVC, no database
