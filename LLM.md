# KMS

**Project**: Lux Key Management Service (KMS)
**Organization**: Lux Network

## The store does not open without an at-rest key — READ BEFORE DEPLOYING

`KMS_ENCRYPTION_KEY_B64` is now a boot precondition. A missing or malformed
key used to degrade to an unencrypted ZapDB behind one log line, and the Hanzo
deployment ran that way: `KEYREGISTRY` 28 bytes (the empty registry) and
`kms/secrets/…` keys greppable straight out of the SSTs. One volume snapshot,
one node with disk access, or any process that can read the data directory is
every credential the fleet syncs. The JWT gate in front of it never protected
the bytes.

That deployment has S3 replication OFF (`REPLICATE_S3_ENDPOINT` unset — the
boot log says so), so the cleartext stays on the claim. Turning replication on
before the store is encrypted would ship those same cleartext files
off-cluster; do the migration first.

**The deploy is gated on two operator steps, in this order.** An image built
from this commit will refuse to start without them — that is the point, but it
means a tag bump alone takes the fleet's secret sync down.

1. **Provision the key, outside this KMS.** A store's own key cannot be a
   record in that store — a cold start could never read it. Use a Secret
   provisioned out of band (or the MPC-rooted REK, which is already how the ZAP
   secrets plane roots its per-secret DEKs):

       head -c 32 /dev/urandom | base64      # -> KMS_ENCRYPTION_KEY_B64

   `ROOT_ENCRYPTION_KEY` is NOT this key. It is the Infisical-era name the Hanzo
   deployment still provisions; nothing reads it. The boot refusal names it so
   an operator does not read "no key configured" while looking at a populated
   Secret.

2. **Migrate the store once, with the server stopped.** ZapDB takes a directory
   lock, and a store read while it is written yields a copy missing records.

       KMS_ENCRYPTION_KEY_B64=<new> \
         kms-rekey -from /var/lib/cloud/kms -to /var/lib/cloud/kms-encrypted

   The source is opened read-only and never written, so a migration that dies
   halfway leaves the live store untouched — delete the half-written
   destination and run it again. It prints the record count; compare it before
   pointing `KMS_DATA_DIR` at the result, and delete nothing until you have.
   Rotation of an already-encrypted store is the same command with
   `KMS_REKEY_FROM_B64` set to the retired key — there is no separate rotate
   path to keep in sync.

Verification that the migration actually encrypted anything, on the new dir:
`KEYREGISTRY` grows past 28 bytes (a data key is registered), and
`grep -c kms/secrets *.sst` answers 0 where the old dir answered non-zero.

## v1.12.14 — the list could not see secrets that exist

`GET /v1/kms/orgs/hanzo/secrets` answered `200 {"names":[]}` while
`GET .../secrets/deploy/UNIVERSE_PIN_TOKEN?env=prod` answered `200` with a
value. Same token, same org, same path: reads worked, enumeration returned
nothing. That is why a stale, invalid `UNIVERSE_PIN_TOKEN` sat in KMS unnoticed
and broke continuous deployment for a day — every build published an image and
pinned nothing, with no signal anywhere. **You cannot audit, rotate, or verify
the coverage of a store you cannot enumerate.**

Cause: a secret is keyed `kms/secrets/{path}/{env}/{name}`, which braids path
and env into one string, and the listing was a single prefix scan over
`kms/secrets/{path}/{env}/`. One opaque byte prefix can only answer for one
exact (path, env) pair, so the listing had three separate ways to come back
empty while the record sat right there — and all three answered 200:

1. `env` silently defaulted to `default`; the fleet writes `prod`.
2. `path` matched exactly, so a secret one segment deeper was invisible.
3. any unrecognized query parameter was silently dropped, so `?prefix=deploy`
   (and the operator's own `?environment=`) filtered nothing.

Fix: one primitive, `store.Find(store.Query{Path, Env})`, that scans KEYS ONLY
and filters on the decoded coordinate — which is what lets a query span
sub-paths and environments at all. Both framings of the store (the HTTP list and
ZAP `OpSecretList`) call it, so they cannot disagree about what the store holds.

    path   subtree root, RECURSIVE ("deploy" reaches "deploy/ci", never
           "deployfoo"); omitted = the whole store
    env    filter; omitted = EVERY environment. There is no default: env is a
           key component, so silently picking one reports an empty store while
           another env holds every record
    unknown parameter -> 400, never a silently different question

The response now carries each record's full `{path, env, name}` coordinate and
echoes the query it ran, so an empty result says which path and env were
actually searched instead of reading as "this store is empty". `names` is
unchanged for existing clients.

`Put` now rejects an env or name containing `/` (400, `ErrInvalidCoord`): they
are the last two key segments, so a `/` in either lets two coordinates spell one
key and makes the decode ambiguous. The keyspace stays injective going forward;
lookups stay permissive, since rejoining any triple reproduces its own key.

The invariant that was missing is now a test — `cmd/kms/secrets_list_roundtrip_test.go`:
**write a secret, assert the list returns it**, plus one case per axis above,
delete-tracking, and cross-env isolation.

Not fixed here, same defect class, separate deployable: cloud's `apps/kms`
(`store.list`, `SELECT ... WHERE path=? AND env=?`) is also exact-coordinate
with a silent `default` env. Its `List` is additionally consumed by the credz
credential broker to enumerate an app's scope, so making it recursive widens
that scope — it needs its own review, not a drive-by.

## v1.12.9 — HTTP secret list (surface parity with ZAP)

The ZAP wire has carried `OpSecretList` (0x0042, `{path, env}` -> `{names}`)
since it was written; HTTP had get/put/delete and **no list**, so the two
framings of the same store disagreed about what you could ask it. A client that
wanted to enumerate had to open a ZAP connection or give up — the hanzo browser
extension gave up and pinned itself to Infisical `/api/v3` paths instead.

    GET /v1/kms/orgs/{org}/secrets?path=&env=   ->  {"names": [...]}

Same envelope the ZAP op returns. The pattern has no trailing segment, so
ServeMux routes the bare collection there and anything below it to the existing
`{rest...}` handler. That split is the whole risk: invert it and list swallows
every get, or get 400s on the bare collection for want of a slash.
`TestSecretRoutes_ListAndGetDoNotShadow` asserts both directions, and that an
empty result is `[]` not `null`.

The full HTTP secret surface is now get / list / put / delete — orthogonal to
the ZAP ops 0x0040-0x0043, one store behind both.

## v1.12.5 — deleted the env-var fetch route (secrets are never process env)

- **Hole (HIGH, CRITICAL on live `lux-kms-go`):** `GET /v1/kms/secrets/{name}` was
  registered **unwrapped** — no auth middleware — and did `os.Getenv(name)`, returning
  the raw value. Any caller reaching `:8080` past the network boundary (NetworkPolicy
  gap, port-forward, pod compromise, SSRF) could `curl .../v1/kms/secrets/KMS_MASTER_KEY_B64`
  with **no Authorization header** and read the root REK that protects every per-secret
  DEK — plus `MPC_TOKEN`, `KMS_ENCRYPTION_KEY_B64`, and (in the `k8s/` variant) the S3
  backup keys. On the live `lux-kms-go/kms` statefulset `KMS_MASTER_KEY_B64` IS populated
  (verified: 32-byte key present in `kms-secrets`), so the leak was **live master-key
  exposure gated only by the network** → CRITICAL.
- **Fix: deleted the route** (it had **zero callers** — the kms-operator reads via the
  org-scoped path/ZAP, the `kms` Go client uses ZAP; process env was never a secret
  source). The three org-scoped secret routes were extracted into `registerSecretRoutes`
  (mirrors `registerKMSRoutes`/`registerOIDCRoutes`/`registerWebUI`) so the exact exposed
  route set is testable. Secrets now flow **only** through `/v1/kms/orgs/{org}/secrets/*`
  (JWT-gated, `requireOrgJWT`) and the ZAP wire. Regression `TestSecretRoutes_NoEnvVarLeak`
  fails if any route ever echoes process env again (unauth → 404, admin → 404, canary
  value never in body). Stale `kms.go` doc comment referencing the route corrected.
- Contrast: the Hanzo white-label fork (`hanzo/kms`) KEPT its `/v1/kms/secrets/{name}`
  because it has real SDK consumers, and gated it (admin-only + `safeEnvName` + audit,
  test `TestRed2_EnvVarReadRequiresAdmin`). Lux has no such consumers → delete, don't gate.

## 2026-07-15 — KMS↔MPC wire fix (v1.12.3) + authorizer-coupling caveat

- **v1.12.3** (wire-fix commit `7105376`) realigns the KMS↔MPC ZAP signing wire to the mpcd
  contract: `SignRequest{vault_id,wallet_id,payload}`, snake_case `KeygenResult`, and
  `ZapClient.call()` surfaces a daemon `{"error":…}` as a REAL error — killing the false-green
  empty-signature-with-nil-error path. Cross-repo guard `pkg/mpc/wire_contract_test.go`.
  End-to-end proven on the zoo ring (ephemeral pod: keygen made a degree-2 wallet, sign
  verified). `luxfi/kms:v1.12.3` image is built.
- **`lux-kms-go` (ns `lux-kms-go`, statefulset `kms`, currently `v1.11.11`) upgrade to v1.12.3
  is STAGED.** It is secrets-only (`MPC_VAULT_ID` empty, `ZAP_PORT=0`) with a legacy
  `KMS_MASTER_KEY_B64` REK → it does NOT MPC-sign, so it is NOT exposed to the false-green bug.
- **CAVEAT (complecting):** v1.12.3 bundles the wire fix with the native `/v1/sdk` enveloped-
  secrets plane (commit `d557576`), whose consensus authorizer (`buildConsensusAuthorizer`,
  "refusing to boot fail-open") fires whenever a REK/master key is loaded — and in v1.12.3
  that gate is `masterKey != nil`, INDEPENDENT of `ZAP_PORT` (v1.11.11 gated it behind ZAP,
  which is why lux-kms-go boots today). So any KMS with a legacy `KMS_MASTER_KEY_B64` and no
  `KMS_CONSENSUS_VALIDATORS`/`KMS_CONSENSUS_OPERATORS` (or `KMS_CONSENSUS_FILE`) will crashloop
  on v1.12.3. Deploy plan for a live KMS keeping its master key: set consensus authority first,
  then roll; or migrate the REK to `MPC_REK_ENDPOINT`. The security-critical wire fix would
  ideally be decoupled from the authorizer so it can ship to secrets-only KMSes without
  standing up `/v1/sdk` authority.

## One KMS per org. Env is a field, not a hostname.

There is one KMS endpoint per org. Every caller — devnet, testnet,
mainnet — points at the same `kms.lux.cloud` for Lux (or
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

The Root Encryption Key (REK) comes from a luxfi/mpc threshold cluster
rather than a static K8s Secret env var, which is what resolved the
master-key split-brain.

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

### Re-key (REK rotation)

`cmd/kms-rekey` is the one tool that moves a store between keys, and
rotation is the job it already does — read every record under the old
key, write it under the new one, into a fresh directory:

1. Operator triggers the MPC reshare ceremony for `kms/rek/v(N+1)`.
2. Stop the server (ZapDB takes a directory lock) and run `kms-rekey`
   with epoch N as the source key and N+1 as the destination.
3. Roll KMS pods with `MPC_REK_KEY_ID=kms/rek/v(N+1)`.

It reads `KMS_REKEY_FROM_B64` / `KMS_ENCRYPTION_KEY_B64` rather than
bootstrapping two MPC epochs itself; supplying those from the ceremony
is the operator's step. A second binary for REK rotation would be a
second way to do the one thing this one does.

Replica coordination during the migration window: every replica fetches
the same epoch N+1 from MPC (the cluster is the single source of
truth), so cross-replica consistency is automatic. There is no leader
election in KMS; the migration tool runs once from any pod or any
out-of-cluster operator with the MPC bearer.

### What the REK is NOT

Four things sit next to the REK and are separate from it:

- The per-secret AES-256-GCM envelope shape (`pkg/store/crypto.go`) —
  the REK wraps the DEKs, it is not the DEK.
- ZapDB-at-rest encryption (`KMS_ENCRYPTION_KEY_B64`) — Badger-level,
  orthogonal to the application envelope, its own knob.
- IAM JWT validation at the HTTP edge.
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
  KMS_IAM_CLIENT_ID         default "lux-kms"
  KMS_IAM_CLIENT_SECRET     from KMS-projected universal-auth Secret
  KMS_ZAP_AUDIENCE          default "lux-mpc"

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

## /v1/sdk — enveloped secrets + threshold-sign surface (HTTP)

The SDK-facing native secrets plane. It exposes the SAME
verify→authorize→dispatch core as the in-cluster ZAP wire
(`pkg/zapserver`) over HTTP — one implementation, two framings
(`Server.dispatch` is the shared op→handler router; `Server.Register`
frames it on ZAP, `Server.HTTPHandler` frames it on HTTP). Mounted at
`/v1/sdk/` by kmsd whenever the REK is loaded, independent of `ZAP_PORT`.

- **One endpoint**: `POST /v1/sdk/secrets`. The body is a signed
  `envelope.Envelope`; the OPERATION is the SIGNED `op` field, never the
  URL — so no URL framing can escalate a read identity into a write.
- **The envelope IS the credential** — no bearer token on this surface.
  Every request is ML-DSA-65-signed by a mnemonic-derived
  `keys.ServiceIdentity`; verified for signature + wall-clock freshness
  (±5m) + replay (per-`(NodeID,nonce)` ledger) before dispatch.
- **Consensus-native authz** (`InProcessAuthorizer`): validators may read
  (`OpSecretGet` 0x0040 / `OpSecretList` 0x0042 / `OpVerify` 0x0051);
  operators additionally may write (`OpSecretPut` 0x0041 — also the
  rotate op, upsert / `OpSecretDelete` 0x0043 / `OpSign` 0x0050). Same
  fail-closed authorizer + nonce ledger as ZAP; kmsd refuses to boot
  without them.
- **Threshold sign** (`OpSign`/`OpVerify`) dispatches to a
  `zapserver.SignBackend` (wired by `pkg/sdksign` over the MPC-backed
  `keys.Manager`). KMS holds NO full key material — signing is t-of-n in
  luxfi/mpc. Verify is a local public-key check: ed25519 (corona) via
  stdlib; secp256k1 (bls) is delegated to the chain/precompile layer
  (`sdksign.ErrVerifyBLSDelegated`) — a documented boundary, not a stub.
- **Status mapping**: OK→200, not-found→404, forbid→403 (replay masked as
  generic `forbidden`), error→400, oversize→413 (4 MiB cap), handler
  failure→500 (no internal detail leaked).

Verified in `pkg/zapserver/http_test.go` (18 httptest cases) +
`pkg/sdksign/*_test.go` (real ed25519 roundtrip). Live t-of-n signing is
the MPC integration boundary (KMS-side auth contract is what's proven
here).

## Project Overview

KMS is an MPC-backed key management service for the Lux Network. It manages validator keys, threshold signing, secret storage, and key rotation using distributed Multi-Party Computation.

**No legacy fork. No PostgreSQL. No Node.js.** The active server is a pure Go binary in `cmd/kms/` backed by `luxfi/mpc` for threshold cryptography and `luxfi/zapdb` for storage.

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

## Build (CI) — go.sum re-tag staleness

The `Dockerfile` builds the server with `GOFLAGS=-mod=mod` (NOT vendor):
`go mod vendor` strips supranational/blst's C headers (blst.h), and the
CGO sqlcipher build needs them, so the module cache (full trees) is used
instead of the in-tree `vendor/`. `Dockerfile.operator` builds with
`CGO_ENABLED=0` and CAN use `-mod=vendor` (blst's cgo file is excluded).

Because CI sets `GOPRIVATE=github.com/luxfi/*`, it fetches luxfi modules
**direct from GitHub** (not the public proxy). When a luxfi tag is
force-moved (re-tagged to a different commit) after kms's go.sum was
written, `go mod download` fails with `checksum mismatch / SECURITY
ERROR`: go.sum has the OLD tree hash, GitHub now serves the new commit.
This is NOT an attack — it's a re-tag. Fix = update the one h1 line in
go.sum to the authoritative current hash (NEVER bypass the check).
Verify from a PRISTINE GOMODCACHE with `GOWORK=off`; the local
`~/work/lux/go.work` + VCS cache can mask the drift by resolving the
old commit. (June 2026: keys@v1.1.0 and age@v1.5.0 were both re-tagged
via the "vendor: sync … docs" lineage.)

## keys ↔ kms cycle (phantom tag) — does NOT block the build

`luxfi/keys` (v1.0.9+) require `luxfi/kms@v1.9.12` and `@v1.11.3` — tags
that were never published (kms jumps v1.9.10→v1.9.13→v1.11.0…). This is
a release-ordering accident, NOT a code cycle: the package graph is
acyclic — `go list -deps ./pkg/zapclient` has zero luxfi/keys
(pkg/envelope is interface-decoupled; keys appears only in its _test.go
files). kms building itself never fetches the phantom: Go resolves the
kms module's own packages from the local tree, and MVS upgrades any
consumer past the phantom to a real kms tag. The server (cmd/kms uses
the in-repo `pkg/keys`) and operator compile ZERO external luxfi/keys —
no keys content ships in either image.

## Web UI (the go:embed SPA) — shipped

`cmd/kms/main.go` `//go:embed all:web` serves the Vite SPA from the one Go
binary (UI + `/v1` API same-origin). The full surface is implemented as 16
area-groups, each an `api_<area>.go` with a `register<Area>API(mux, db)`
registered in `main.go`: Identities, OrgMembers, GroupsScim, Tokens,
SecretMeta, DynRotation, SyncsConn, Pki, Ssh, Pam, AiMcp, KmsKmip, Approvals,
AuditScan, AuthConfig, Misc — on top of the Core/Project/Secrets MVP tiers.
All persist to ZapDB (Badger KV); secrets keep the AES-256-GCM envelope under
the MPC-rooted REK (`pkg/store/crypto.go`). Passwords are hashed (argon2id),
never plaintext. Routes are `/v1`-only. e2e green, deployed.

Canonical image: `ghcr.io/luxfi/kms` (Lux) and its Hanzo white-label fork
`ghcr.io/hanzoai/kms` (same Go source, branded by domain). Built by CI from
the `Dockerfile` (Go → one binary). NO Postgres, NO Redis, NO Node,
NO Infisical, NO SPA — the service is the API.
