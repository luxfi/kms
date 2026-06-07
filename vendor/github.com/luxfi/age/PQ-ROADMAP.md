# Post-Quantum Roadmap for luxfi/age

## Current: X25519 Recipients (v1.x)
- Standard age X25519 (Curve25519) recipients
- Adequate for operational data with limited shelf life
- NOT post-quantum safe

## Phase 2: X-Wing Hybrid Recipients (v2.x)
- X-Wing = X25519 + ML-KEM-768 (NIST FIPS 203)
- Hybrid: if quantum never arrives, X25519 still works
- If quantum arrives, ML-KEM-768 protects
- Implementation: new recipient type `xwing` in age
- Key format: `age1xwing1<bech32-encoded X25519+ML-KEM public key>`
- Backward compatible: old recipients still work

## Phase 3: Pure ML-KEM Recipients (v3.x)
- Pure ML-KEM-768 or ML-KEM-1024 recipients
- When X25519 is considered deprecated
- Key format: `age1mlkem1<bech32-encoded ML-KEM public key>`

## Dependencies
- `hanzoai/age` — Hanzo ecosystem fork (same roadmap)
- `lux/crypto` — ML-KEM implementation
- NIST FIPS 203 (ML-KEM) — finalized August 2024
- X-Wing draft: https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-05.html

## References
- LP-102: Encrypted SQLite Replication Standard
- HIP-0302: Hanzo Replicate
- ZIP-0803: Zoo Encrypted SQLite Replication
