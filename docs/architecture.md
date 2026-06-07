# KMS architecture — MPC-rooted Root Encryption Key

## Threat model

- Adversary: anyone with `kubectl exec`, anyone who can dump pod env or
  read a static K8s Secret, anyone who can read the KMS pod's heap via
  core file or pprof.
- Goal: prevent any of the above from recovering the AEAD key that
  protects per-secret DEKs in ZapDB.
- Out of scope: a fully-compromised KMS process (it has plaintext in
  memory by design) and a fully-compromised MPC quorum.

## Construction

```
                     +-----------------------------+
                     |   luxfi/mpc cluster         |
                     |   (t-of-n; default 2-of-3)  |
                     |                             |
                     |   stores wrapped REK at     |
                     |   keyID="kms/rek/v<epoch>"  |
                     |                             |
                     |   share set persisted in    |
                     |   each MPC node's BadgerDB  |
                     |   under encdb (ChaCha20)    |
                     +-------------+---------------+
                                   ^
                                   | ZAP wire (OpDecrypt 0x0031)
                                   | over X25519+ML-KEM-768 AEAD
                                   |
                          +--------+--------+
                          |  KMS pod (boot) |
                          |                 |
                          | mpcrek.Bootstrap|
                          | (single fetch)  |
                          +--------+--------+
                                   |
                                   v
              +--------------------+------------------+
              |  pkg/store.Seal / Open                |
              |                                       |
              |  per-secret AES-256-GCM envelope:     |
              |    DEK := rand(32)                    |
              |    ct  := AES-GCM(DEK, plaintext,     |
              |                   AAD=path/name/env)  |
              |    wrap:= AES-GCM(REK, DEK,           |
              |                   AAD=name)           |
              +--------------------+------------------+
                                   |
                                   v
                          +--------+--------+
                          |   ZapDB (PVC)   |
                          |   on-disk LSM   |
                          |                 |
                          |   each Secret = |
                          |     {ct, wrap,  |
                          |      meta...}   |
                          +-----------------+
```

## Security argument

### Assumptions

1. AES-256-GCM is IND-CCA2 in the multi-user / multi-key setting up to
   the standard birthday bound at 2^32 messages per key (Bellare-Tackmann
   CRYPTO 2016). Each per-secret DEK encrypts exactly one plaintext, so
   the inner layer is well below the bound.
2. The REK is unpredictable from the adversary's view: it was sampled
   in an MPC-internal DKG and is held as t-of-n shares; recovering it
   without t cooperating shareholders requires solving the underlying
   threshold hardness assumption (CGGMP21 ECDSA / FROST EdDSA — discrete
   log on secp256k1 / ed25519).
3. The MPC ZAP wire is AEAD-sealed under an X25519+ML-KEM-768 hybrid
   handshake. Both layers are post-quantum-hardened.

### Claims

- Confidentiality at rest. A snapshot of the ZapDB PVC reveals only
  `(ct, wrap)` pairs. Without the REK, `wrap` is an AES-GCM ciphertext
  the adversary cannot open; without the unwrapped DEK, `ct` is
  unopenable.
- Replay / swap resistance. The AAD on each layer binds the envelope
  to its name and (path, name, env). A swap of `wrap_A` into record
  `B` fails AEAD verification.
- No env-var attack surface in MPC mode. With `MPC_REK_ENDPOINT` set,
  the REK is never in pod env, K8s Secrets, kubeconfig, or kubectl
  exec'd shells. It exists only on the t-of-n MPC nodes (as shares)
  and transiently in the KMS pod's heap.

### Non-claims

- The KMS pod's heap is not a vault. A `gcore` dump of a running KMS
  pod recovers the REK. Mitigations: pod security context drops all
  capabilities, no debugfs, no ptrace, K8s NetworkPolicy isolates the
  pod, and `mpcrek.Zero` overwrites the REK on graceful shutdown.
- An adversary who compromises t MPC nodes can recover the REK. That
  is the threshold-trust assumption, not a flaw of this design.

## Wire details

### REK fetch (mpcrek.Bootstrap)

- Endpoint: CSV of MPC `host:port` (e.g. all replicas).
- Method: `mpc.ZapClient.Decrypt(ctx, keyID, nil)`. The empty
  ciphertext means "decrypt the stored record under keyID via your own
  t-of-n share set", as opposed to "decrypt this caller-supplied
  ciphertext".
- Response: `mpc.DecryptResult{Plaintext: <32 bytes>}`.
- Rejections: any non-32-byte plaintext; an all-zero plaintext (rejected
  via `crypto/subtle.ConstantTimeCompare`).
- Timeout: 10 s default; configurable via `MPC_REK_TIMEOUT`.

### Per-secret envelope (pkg/store.Seal)

Unchanged from pre-MPC. Documented here for completeness:

```
DEK   = rand(32)
Nonce = rand(12)
Ciphertext  = 0x01 || Nonce || AES-GCM-Seal(DEK,  Nonce, plaintext, AAD=path/name/env)
WrappedDEK  = 0x01 || Nonce'|| AES-GCM-Seal(REK,  Nonce', DEK,       AAD=name)
```

`pkg/store.Open` verifies AAD on both layers and zeroes DEK after use.

## Operational notes

- Replicas. All KMS replicas fetch the same epoch from MPC; the
  cluster is the single source of truth. No leader election needed.
- Cluster size. Default 3-of-5 for production (matches the
  `lux-mpc` consensus-mode StatefulSet). 2-of-3 acceptable for non-
  production. Operator chooses on MPC bootstrap.
- Backups. ZapDB Replicator continues to back up to S3 with age
  encryption (`REPLICATE_*` env). The backup is double-wrapped: each
  Secret in the backup blob is already AES-GCM under the MPC-rooted
  REK; the blob is then age-encrypted with the operator's public key.
  A leak of the S3 bucket reveals nothing without BOTH the age
  identity AND the MPC quorum.
- Re-key cadence. Manual, on incident or quarterly. Run
  `cmd/rek-rotate` (future) with both old and new epoch live, then
  roll deployments.
