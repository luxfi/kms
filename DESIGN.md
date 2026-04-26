# P-Chain Atomic Key Rotation for MPC-Backed Validator Staking Keys

## Problem Statement

Validator staking on Lux requires three bound keys per NodeID:
- **TLS key** (staking certificate) -- establishes NodeID
- **BLS key** (aggregate signatures) -- ProofOfPossession in AddPermissionlessValidatorTx
- **RT key** (post-quantum / ML-DSA-65) -- RTProofOfPossession for Q-Chain validators

When these keys are managed by MPC threshold signing, two operations exist:
1. **Reshare/Refresh** -- same committee, rotated shares. Public key unchanged. No P-chain update needed.
2. **Rekey** -- committee size change, key migration, or compromise response. Public key changes. P-chain registration must update atomically.

The atomicity constraint: there must never be a window where the validator is offline (old key deregistered, new key not yet registered) or where two conflicting committees can sign for the same validator.

### When P-Chain Update IS Required

| Trigger | BLS Key Changes | RT Key Changes | TLS Key Changes |
|---------|----------------|----------------|-----------------|
| Routine reshare (same t-of-n) | No | No | No |
| Committee resize (3-of-5 to 4-of-7) | Yes | Yes | No |
| Initial migration (solo key to MPC) | Yes | Yes | Possibly |
| Emergency replacement (compromise) | Yes | Yes | Possibly |

### Invariants

1. At most one valid signing committee exists for a given NodeID at any time.
2. If the new key registration fails, the old key remains valid and the old committee retains signing authority.
3. BLS and RT keys rotate together -- never independently.
4. The old committee is deauthorized only after the new committee's registration is confirmed on-chain.

---

## Key Lifecycle State Machine

```
                          ┌──────────────────┐
                          │                  │
           ┌──────────────┤    Unmanaged     │
           │  migrate      │  (solo key)      │
           │              └──────────────────┘
           │
           v
    ┌──────────────┐     reshare (same pubkey)
    │              │◄──────────────────────────┐
    │    Active    │                            │
    │  (t-of-n)   ├───────────────────────────►│
    │              │                            │
    └──────┬───────┘                            │
           │                                    │
           │  rekey requested                   │
           │  (committee change                 │
           │   or compromise)                   │
           v                                    │
    ┌──────────────┐                            │
    │  Rekeying    │  new DKG runs              │
    │  (DKG)       │  old committee still       │
    │              │  authoritative              │
    └──────┬───────┘                            │
           │                                    │
           │  DKG succeeds                      │
           │                                    │
           v                                    │
    ┌──────────────┐                            │
    │  Pending     │  new HybridPoP computed    │
    │  Registration│  P-chain tx submitted      │
    │              │  old committee still signs  │
    └──────┬───────┘                            │
           │                                    │
           │  P-chain tx confirmed              │
           │                                    │
           v                                    │
    ┌──────────────┐                            │
    │  Activating  │  epoch boundary reached    │
    │              │  new committee starts       │
    │              │  signing consensus msgs     │
    └──────┬───────┘                            │
           │                                    │
           │  old committee deauthorized        │
           │  old shares securely wiped         │
           │                                    │
           └────────────────────────────────────┘
                    back to Active

    ─── Failure paths ───

    Rekeying --[DKG fails]--> Active (old committee unchanged)
    Pending  --[tx rejected]--> Active (old committee, new shares wiped)
    Activating --[epoch timeout]--> Rollback to old committee, alert
```

States:
- **Unmanaged**: Key exists outside MPC (file-based, HSM, etc.). Entry point for migration.
- **Active**: One MPC committee holds shares. Normal signing operations proceed.
- **Rekeying**: New DKG is running. Old committee remains authoritative. If DKG fails, return to Active.
- **PendingRegistration**: New keys exist but are not yet registered on P-chain. Old committee signs. New committee cannot sign consensus messages.
- **Activating**: P-chain has accepted the new keys. Waiting for epoch boundary to hand off signing authority.
- **Active** (again): New committee is sole authority. Old shares wiped.

---

## P-Chain Transaction Sequence

### Permissioned Chains (L1 Validators)

For L1 validators, the P-chain provides `RegisterL1ValidatorTx`, `SetL1ValidatorWeightTx`, and `DisableL1ValidatorTx`. The rotation sequence:

```
Time ─────────────────────────────────────────────────────────►

Old Committee (t1-of-n1)     New Committee (t2-of-n2)
        │                            │
   1. Continue signing               │
        │                            │
   2. Initiate DKG ─────────────────►│ DKG runs
        │                            │ New BLS + RT keys generated
        │                            │
   3. Old committee signs            │ New committee: keys exist,
      RegisterL1ValidatorTx          │ signing DISABLED
      with new BLS PoP + RT PoP     │
        │                            │
   4. Wait for tx confirmation       │
      on P-chain (poll every 2s,     │
      timeout 5 minutes)             │
        │                            │
   5. P-chain confirms ─────────────►│ Signing ENABLED
        │                            │
   6. Old committee signs            │ New committee begins
      SetL1ValidatorWeightTx         │ signing consensus
      weight=0 for old validator     │
      (or DisableL1ValidatorTx)      │
        │                            │
   7. Old shares wiped ──────────────│ Sole authority
        │                            │
      DECOMMISSIONED                 │ Active
```

### Primary Network Validators

Primary network validators use `AddPermissionlessValidatorTx` which binds BLS key via `signer.Signer` (ProofOfPossession). The key is bound for the validator's staking period. Rotation requires:

1. Wait for current staking period to end (or use the re-staking window).
2. Re-register with `AddPermissionlessValidatorTx` using new HybridProofOfPossession.
3. No gap -- the new registration's start time equals old registration's end time.

For emergency rotation on primary network, the only option is to `DisableL1ValidatorTx` (if L1) or wait for staking period expiry (if permissionless). This is a protocol limitation, not a design choice.

### Q-Chain Validators (Hybrid BLS + RT)

Q-Chain validators require `HybridProofOfPossession` binding both BLS and RT keys. The rotation transaction must contain both proofs atomically. The MPC daemon generates both key types in a single DKG session (CGGMP21 for BLS, FROST for RT) and produces the combined `HybridProofOfPossession`.

---

## Operator CRD Extensions

### New Fields on MpcSpec

```rust
/// MPC configuration
pub struct MpcSpec {
    // ... existing fields ...

    /// Key lifecycle management
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_lifecycle: Option<KeyLifecycleSpec>,
}

/// Key lifecycle specification for MPC-backed validator keys
pub struct KeyLifecycleSpec {
    /// Current key state (set by controller, read-only for users)
    /// Values: Unmanaged, Active, Rekeying, PendingRegistration, Activating
    pub state: String,

    /// Active committee configuration
    pub active_committee: CommitteeSpec,

    /// Pending committee (populated during rekey, cleared on activation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_committee: Option<CommitteeSpec>,

    /// Rekey policy
    #[serde(default)]
    pub rekey_policy: RekeyPolicy,
}

/// MPC committee specification
pub struct CommitteeSpec {
    /// Threshold (t in t-of-n)
    pub threshold: u32,

    /// Total parties
    pub parties: u32,

    /// MPC wallet ID (references key material in MPC daemon)
    pub wallet_id: String,

    /// BLS public key (hex, set after DKG)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bls_public_key: Option<String>,

    /// RT public key (hex, set after DKG)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rt_public_key: Option<String>,

    /// P-chain validation ID (set after registration tx confirms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_id: Option<String>,
}

/// Rekey policy controls when and how rekeying is triggered
pub struct RekeyPolicy {
    /// Allow automatic rekey when committee spec changes
    #[serde(default)]
    pub auto_rekey: bool,

    /// Require manual approval before P-chain registration
    #[serde(default = "default_true")]
    pub require_approval: bool,

    /// Timeout for DKG phase (seconds, default 300)
    #[serde(default = "default_dkg_timeout")]
    pub dkg_timeout_seconds: u64,

    /// Timeout for P-chain tx confirmation (seconds, default 300)
    #[serde(default = "default_tx_timeout")]
    pub tx_timeout_seconds: u64,
}
```

### New Fields on LuxNetworkStatus

```rust
pub struct LuxNetworkStatus {
    // ... existing fields ...

    /// Per-validator key rotation status
    #[serde(default)]
    pub key_rotations: BTreeMap<String, KeyRotationStatus>,
}

pub struct KeyRotationStatus {
    /// Current state
    pub state: String,

    /// Timestamp of last state transition
    pub last_transition: String,

    /// Active BLS public key (hex)
    pub active_bls_key: Option<String>,

    /// Active RT public key (hex)
    pub active_rt_key: Option<String>,

    /// Pending BLS public key during rotation (hex)
    pub pending_bls_key: Option<String>,

    /// Error message if rotation failed
    pub error: Option<String>,

    /// Number of failed attempts
    pub failed_attempts: u32,
}
```

---

## Failure Modes and Recovery

### F1: DKG Failure (Rekeying -> Active rollback)

**Cause**: Network partition, node crash, or timeout during DKG.
**Detection**: DKG timeout (default 5 minutes) expires without all parties completing.
**Recovery**: Controller sets state back to Active. Old committee unchanged. New partial shares discarded by MPC daemon. No P-chain state affected.
**Operator action**: None. Controller retries on next reconcile if the desired committee spec still differs.

### F2: P-Chain Transaction Rejected (PendingRegistration -> Active rollback)

**Cause**: Insufficient balance, invalid PoP, concurrent registration, nonce conflict.
**Detection**: P-chain API returns error or tx not confirmed within timeout.
**Recovery**: Controller sets state back to Active. New committee shares preserved but signing disabled. Controller may retry with corrected tx parameters.
**Data cleanup**: If retry count exceeds 3, new committee shares are wiped and state returns to Active with old committee.

### F3: Epoch Activation Timeout (Activating -> Rollback)

**Cause**: New committee nodes not ready, network partition prevents consensus messages.
**Detection**: No consensus messages signed by new committee within 2 epochs (20 minutes at 10-minute epoch boundaries).
**Recovery**: Controller reverts to old committee. Submits DisableL1ValidatorTx for the new registration. Old committee resumes signing.
**Severity**: High. Requires investigation. Alerts fire.

### F4: Old Committee Compromise (Emergency Rekey)

**Cause**: Key material exposure detected.
**Detection**: External signal (security team, monitoring).
**Recovery**: Skip approval gate. Run DKG immediately. Submit registration tx with priority fee. Set weight=0 on old validator immediately after new registration confirms. Do not wait for epoch boundary.
**Trade-off**: Brief period (~30s) where both committees could theoretically sign. Acceptable because the compromised committee is being replaced, not the honest one.

### F5: Controller Crash Mid-Rotation

**Cause**: Controller pod restart during any rotation phase.
**Detection**: On startup, controller reads current state from CRD status.
**Recovery**: State machine is idempotent. Each state has a clear next action. Controller picks up where it left off:
- Rekeying: Check if DKG completed (poll MPC daemon). If yes, advance. If no, wait or timeout.
- PendingRegistration: Check if tx confirmed on P-chain. If yes, advance. If no, resubmit.
- Activating: Check if new committee is signing. If yes, advance. If no, wait or rollback.

### F6: Split Brain (Two Controllers)

**Cause**: Leader election failure.
**Prevention**: Controller uses K8s leader election (Lease). Only one controller writes status.
**Detection**: If two controllers write conflicting states, the CRD resourceVersion check causes one to fail.
**Recovery**: Failed controller retries with fresh read.

---

## MPC Daemon Changes

### New API Endpoints

```
POST /api/v1/keygen/validator
  Request:  { walletId, threshold, parties, nodeIds, keyTypes: ["bls", "rt"] }
  Response: { walletId, blsPublicKey, rtPublicKey, blsProofOfPossession, rtProofOfPossession }

POST /api/v1/sign/validator-registration
  Request:  { walletId, txBytes }
  Response: { signedTxBytes }

POST /api/v1/committee/deauthorize
  Request:  { walletId }
  Response: { wiped: true }

GET  /api/v1/committee/status/{walletId}
  Response: { state, threshold, parties, blsPublicKey, rtPublicKey, canSign }
```

### Key Generation Changes

The existing dual keygen (CGGMP21 for ECDSA + FROST for EdDSA) must be extended:

1. **BLS keygen**: The MPC daemon runs distributed BLS key generation. Each node holds a share of the BLS private key. The combined public key and proof of possession are computed from threshold shares. This uses the `luxfi/crypto/bls` package's `SignProofOfPossession` method.

2. **RT keygen**: The MPC daemon runs distributed ML-DSA-65 key generation. Each node holds a share. The combined public key and proof of possession follow the same pattern as BLS using the Ringtail threshold package.

3. **Atomic dual keygen**: Both BLS and RT keygen run in the same session (like existing ECDSA+EdDSA). Both must succeed or both fail. The result is a `HybridProofOfPossession` containing both proofs.

### Signing Authority Fence

New field in key metadata stored by MPC daemon:

```go
type ValidatorKeyMeta struct {
    WalletID        string `json:"walletId"`
    BLSPublicKey    []byte `json:"blsPublicKey"`
    RTPublicKey     []byte `json:"rtPublicKey"`
    ValidationID    string `json:"validationId"`    // P-chain validation ID
    SigningEnabled  bool   `json:"signingEnabled"`  // false until P-chain confirms
    FencedAt        int64  `json:"fencedAt"`        // unix timestamp when deauthorized
    CommitteeGen    uint64 `json:"committeeGen"`    // monotonic generation counter
}
```

The `SigningEnabled` flag prevents a new committee from signing consensus messages before P-chain registration confirms. The `FencedAt` timestamp prevents an old committee from signing after deauthorization. Both are enforced in the MPC daemon's signing handler -- if either guard rejects, the signing request returns an error.

The `CommitteeGen` counter is monotonically increasing. When the operator creates a new committee, it increments the generation. The MPC daemon only accepts signing requests where the request's generation matches the key metadata's generation.

---

## Implementation Phases

### Phase 1: State Machine in Operator (Week 1-2)

- Add `KeyLifecycleSpec` and `KeyRotationStatus` to CRD.
- Implement state machine transitions in `reconcile_network`.
- No actual MPC integration. States transition based on manual annotation updates.
- Deliverable: CRD schema, state machine tests.

### Phase 2: MPC Daemon Validator Keygen (Week 3-4)

- Add BLS threshold DKG to MPC daemon (using `luxfi/crypto/bls` threshold API).
- Add RT threshold DKG to MPC daemon (using `luxfi/ringtail/threshold`).
- Add `HybridProofOfPossession` generation from threshold shares.
- Add signing authority fence (`SigningEnabled`, `CommitteeGen`).
- Deliverable: `/api/v1/keygen/validator` endpoint, unit tests with 3-node local cluster.

### Phase 3: P-Chain Transaction Builder (Week 5-6)

- Build `RegisterL1ValidatorTx` / `AddPermissionlessValidatorTx` construction from MPC-generated keys.
- P-chain tx submission and confirmation polling.
- Wire into operator reconcile loop (Rekeying -> PendingRegistration -> Activating transitions).
- Deliverable: Integration test: full rotation on devnet.

### Phase 4: Epoch Handoff and Cleanup (Week 7-8)

- Implement epoch-boundary activation (coordinate with Quasar EpochManager).
- Old committee deauthorization and share wiping.
- Emergency rekey fast path (skip approval, priority fees).
- Deliverable: E2E test: committee resize 3-of-5 to 4-of-7 on testnet with zero downtime.

### Phase 5: Production Hardening (Week 9-10)

- Failure injection testing (kill MPC node mid-DKG, kill controller mid-registration).
- Alerting integration (PagerDuty for stuck rotations, failed DKGs).
- Runbook for manual intervention.
- Dashboard UI for rotation status visibility.
- Deliverable: Production deployment on mainnet validators.

---

## Decisions

**Decision**: Two-phase registration with old-committee-signs-new-registration.
**Rationale**: The old committee is still authoritative, so it signs the P-chain tx that registers the new committee's keys. This avoids needing any out-of-band signing authority.
**Trade-off**: Requires old committee to be available during rotation. If old committee is completely unavailable (all nodes lost), manual key recovery from Shamir backup is required. Acceptable because total committee loss is a separate disaster recovery scenario.

**Decision**: Signing authority fence in MPC daemon, not in operator.
**Rationale**: The MPC daemon is the only component that actually produces signatures. Fencing at the signing layer is the only way to guarantee no unauthorized signatures. The operator controls when fences are raised/lowered, but enforcement is in the daemon.
**Trade-off**: MPC daemon becomes stateful about P-chain registration status. Adds coupling. Acceptable because the alternative (trusting the operator to never make mistakes) is worse.

**Decision**: No concurrent rotations. One rotation per NodeID at a time.
**Rationale**: Concurrent rotations create combinatorial failure modes. Sequential rotations are simpler and the time cost (minutes) is negligible for an operation that happens at most monthly.
**Trade-off**: If rotating 100 validators, they rotate sequentially. At ~5 minutes per rotation, that is ~8 hours. For fleet-wide rotation, we batch by subnet and run subnets in parallel. Acceptable.
