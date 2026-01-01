# Lux KMS - AI Assistant Knowledge Base

**Last Updated**: 2025-11-12
**Project**: Lux Key Management Service (KMS)
**Organization**: Lux Network

## Project Overview

Lux KMS is an open-source, enterprise-grade key management platform providing centralized cryptographic key management, HSM integration, and comprehensive security controls. It serves as the foundation for secure data encryption, digital signatures, and compliance across the Lux ecosystem.

## Architecture Overview

### Core Components

```
┌──────────────────────────────────────────┐
│         Frontend (React/TypeScript)       │
├──────────────────────────────────────────┤
│         Backend API (Node.js/Fastify)     │
├──────────────────────────────────────────┤
│            KMS Service Layer              │
│  ┌──────────────────────────────────┐    │
│  │  - Key Generation & Storage      │    │
│  │  - Crypto Operations             │    │
│  │  - Access Control               │    │
│  │  - Audit Logging                │    │
│  └──────────────────────────────────┘    │
├──────────────────────────────────────────┤
│     Storage Layer (PostgreSQL/Redis)      │
├──────────────────────────────────────────┤
│    HSM/Root Key Provider (PKCS#11)       │
└──────────────────────────────────────────┘
```

### Key Management Hierarchy

- **Root Key**: Protected by HSM or environment variable
- **Organization KEK**: Key Encryption Keys per organization
- **Project KEK**: Project-specific encryption keys
- **Data Keys**: Actual encryption/signing keys

## Essential Commands

### Development Setup
```bash
# Backend development
cd backend
npm install
npm run dev

# Frontend development
cd frontend
npm install
npm run dev

# Documentation
cd docs
pnpm install
pnpm dev  # Start Mintlify docs server

# Docker Compose (full stack)
docker compose -f docker-compose.dev.yml up

# Run tests
npm test
npm run test:e2e
```

### Production Deployment
```bash
# Build containers
docker build -f Dockerfile.standalone-kms -t lux-kms .

# Deploy with Docker Compose
docker compose -f docker-compose.prod.yml up -d

# Kubernetes deployment
kubectl apply -f k8-operator/

# Helm deployment
helm install lux-kms ./helm-charts/kms
```

## Key Technologies

### Backend Stack
- **Runtime**: Node.js with TypeScript
- **Framework**: Fastify (high-performance web framework)
- **Database**: PostgreSQL (primary), Redis (cache)
- **ORM**: Knex.js with migrations
- **Crypto**: Native crypto module + custom implementations
- **HSM**: PKCS#11 interface support

### Frontend Stack
- **Framework**: React 18 with TypeScript
- **State Management**: React Query
- **UI Components**: Radix UI, Tailwind CSS
- **Internationalization**: i18next (12 languages)
- **Build Tool**: Vite

### Security Stack
- **Encryption Algorithms**:
  - Symmetric: AES-128-GCM, AES-256-GCM
  - Asymmetric: RSA-2048, RSA-4096, ECC-P256, ECC-P384
- **Signing Algorithms**:
  - RSA-PSS (SHA-256/384/512)
  - RSA-PKCS#1 v1.5 (SHA-256/384/512)
  - ECDSA (SHA-256/384/512)
- **Key Derivation**: PBKDF2, Argon2
- **HSM Support**: AWS CloudHSM, Thales Luna, SoftHSM

## Service Architecture Details

### KMS Service (`/backend/src/services/kms/`)

#### Core Files
- `kms-service.ts`: Main service logic for key operations
- `kms-types.ts`: TypeScript type definitions
- `kms-fns.ts`: Utility functions and helpers
- `kms-key-dal.ts`: Database access layer for keys
- `kms-root-config-dal.ts`: Root key configuration DAL
- `internal-kms-dal.ts`: Internal KMS operations

#### Key Operations
1. **Key Generation**: Software or HSM-based generation
2. **Encryption/Decryption**: AES-GCM and RSA operations
3. **Signing/Verification**: RSA and ECC signatures
4. **Key Rotation**: Automatic and manual rotation
5. **Key Import/Export**: Secure key material transfer

### External KMS Integration (`/backend/src/ee/services/external-kms/`)

#### Supported Providers
- **AWS KMS**: Full integration with AWS Key Management Service
- **GCP KMS**: Google Cloud KMS integration
- **Azure Key Vault**: Microsoft Azure integration (planned)

### HSM Service (`/backend/src/ee/services/hsm/`)

#### HSM Configuration
- PKCS#11 interface support
- Session management and pooling
- Key wrapping/unwrapping
- Hardware-backed crypto operations

## API Endpoints

### Key Management
- `POST /api/v1/kms/keys` - Create new key
- `GET /api/v1/kms/keys` - List keys
- `GET /api/v1/kms/keys/{keyId}` - Get key metadata
- `PATCH /api/v1/kms/keys/{keyId}` - Update key
- `DELETE /api/v1/kms/keys/{keyId}` - Delete key

### Cryptographic Operations
- `POST /api/v1/kms/keys/{keyId}/encrypt` - Encrypt data
- `POST /api/v1/kms/keys/{keyId}/decrypt` - Decrypt data
- `POST /api/v1/kms/keys/{keyId}/sign` - Sign data
- `POST /api/v1/kms/keys/{keyId}/verify` - Verify signature
- `POST /api/v1/kms/keys/{keyId}/generate-data-key` - Generate DEK

### KMIP Protocol
- `POST /api/v1/kmip` - KMIP protocol endpoint
- Supports KMIP 2.0+ operations

## Security Features

### Access Control
- **RBAC**: Role-based access control with predefined roles
- **ABAC**: Attribute-based policies for fine-grained control
- **MFA**: Multi-factor authentication support
- **API Keys**: Service account authentication
- **OAuth/SAML**: Enterprise SSO integration

### Audit & Compliance
- **Comprehensive Logging**: Every operation logged with context
- **Compliance Reports**: PCI-DSS, SOC2, HIPAA reporting
- **Key Usage Tracking**: Monitor key operations
- **Anomaly Detection**: Unusual access pattern alerts

### Data Protection
- **Encryption at Rest**: All keys encrypted in storage
- **Encryption in Transit**: TLS 1.3 for all communications
- **Key Isolation**: Separate keys per project/environment
- **Crypto-shredding**: Secure key deletion

## Development Patterns

### Database Migrations
```bash
# Create new migration
npm run migration:create -- create_kms_keys_table

# Run migrations
npm run migration:up

# Rollback
npm run migration:down
```

### Testing Strategy
```typescript
// Unit test example
describe('KMS Service', () => {
  it('should generate AES-256 key', async () => {
    const key = await kmsService.generateKey({
      algorithm: 'AES-256-GCM',
      keyUsage: 'ENCRYPT_DECRYPT'
    });
    expect(key.algorithm).toBe('AES-256-GCM');
  });
});

// E2E test example
describe('KMS API', () => {
  it('should encrypt and decrypt data', async () => {
    const { keyId } = await createKey();
    const { ciphertext } = await encrypt(keyId, 'test');
    const { plaintext } = await decrypt(keyId, ciphertext);
    expect(plaintext).toBe('test');
  });
});
```

## Configuration

### Environment Variables
```bash
# Core Configuration
PORT=8080
DATABASE_URL=postgresql://user:pass@localhost/kms
REDIS_URL=redis://localhost:6379

# Security
ENCRYPTION_KEY=base64-encoded-32-byte-key
ROOT_ENCRYPTION_KEY=base64-encoded-32-byte-key
JWT_SECRET=your-jwt-secret

# HSM Configuration (optional)
HSM_ENABLED=true
HSM_TYPE=pkcs11
HSM_LIBRARY_PATH=/usr/lib/softhsm/libsofthsm2.so
HSM_SLOT=0
HSM_PIN=1234

# External KMS (optional)
AWS_KMS_ENABLED=true
AWS_KMS_REGION=us-east-1
AWS_KMS_KEY_ID=arn:aws:kms:...
```

## Deployment Considerations

### Performance Optimization
- **Connection Pooling**: Database and Redis pools configured
- **Caching Strategy**: LRU cache for frequently used keys
- **Async Operations**: Non-blocking crypto operations
- **Load Balancing**: Horizontal scaling support

### High Availability
- **Database Replication**: Read replicas for scaling
- **Redis Cluster**: Distributed cache
- **HSM Clustering**: Multiple HSM nodes
- **Zero-downtime Deployments**: Rolling updates

### Monitoring
- **Metrics**: Prometheus metrics exposed at `/metrics`
- **Health Checks**: `/health` and `/readiness` endpoints
- **Logging**: Structured JSON logging
- **Tracing**: OpenTelemetry support

## Common Tasks

### Generate New Key
```javascript
const key = await kmsService.generateKmsKey({
  orgId: 'org_123',
  projectId: 'proj_456',
  name: 'app-encryption-key',
  encryptionAlgorithm: SymmetricKeyAlgorithm.AES_GCM_256,
  keyUsage: KmsKeyUsage.ENCRYPT_DECRYPT,
  description: 'Application data encryption'
});
```

### Rotate Key
```javascript
await kmsService.rotateKey({
  keyId: 'key_789',
  algorithm: SymmetricKeyAlgorithm.AES_GCM_256
});
```

### External KMS Integration
```javascript
// Configure AWS KMS
await kmsService.configureExternalKms({
  provider: 'AWS',
  config: {
    region: 'us-east-1',
    keyId: 'arn:aws:kms:...'
  }
});
```

## Documentation Structure

### Main Documentation (`/docs/`)
- Uses Mintlify for documentation generation
- MDX format with React components
- Organized by feature areas
- API reference auto-generated

### Key Documentation Files
- `/docs/documentation/platform/kms/overview.mdx` - KMS overview
- `/docs/documentation/platform/kms/hsm-integration.mdx` - HSM setup
- `/docs/documentation/platform/kms/kmip.mdx` - KMIP protocol
- `/docs/content/docs/index.mdx` - Comprehensive documentation (newly created)

## Troubleshooting

### Common Issues

1. **HSM Connection Failed**
   - Check PKCS#11 library path
   - Verify HSM PIN/credentials
   - Ensure HSM slot is correct

2. **Key Generation Failed**
   - Verify root key configuration
   - Check database connectivity
   - Ensure sufficient entropy

3. **Performance Issues**
   - Check cache hit rates
   - Monitor database query times
   - Verify connection pool settings

## FHE (Fully Homomorphic Encryption) Support

### Current Status: Partial Implementation

**Added Types (2025-12-28):**
- `KmsKeyUsage.FHE_COMPUTATION` - New key usage type for FHE operations
- `FheKeyAlgorithm.TFHE_BINARY` - TFHE boolean gate operations
- `FheKeyAlgorithm.TFHE_INTEGER` - TFHE integer operations
- `TThresholdConfig` - Configuration for t-of-n threshold decryption

**API Surface for FHE Keys:**
```typescript
// Generate FHE key pair
generateFheKeyPair(dto: TGenerateFheKeyPairDTO): Promise<{ publicKey: Buffer; keyId: string }>

// Get public key
getFhePublicKey(keyId: string): Promise<Buffer>

// Threshold decryption (t-of-n)
fheThresholdDecrypt(dto: TFheThresholdDecryptDTO): Promise<Buffer>

// Partial decryption (single party's contribution)
fhePartialDecrypt(dto: TFhePartialDecryptDTO): Promise<Buffer>

// Key rotation (reshare without revealing)
rotateFheKey(dto: TRotateFheKeyDTO): Promise<string>
```

### Implementation TODOs

**Phase 1: Core FHE Key Management**
- [ ] Add FHE key generation in `kms-service.ts`
- [ ] Add FHE key storage schema (migration)
- [ ] Wire FHE algorithms in `kms-fns.ts` verification
- [ ] Add CMEK router endpoints for FHE

**Phase 2: Threshold FHE (Shamir Secret Sharing)**
- [ ] Create `threshold-fhe/` service directory
- [ ] Implement Shamir secret sharing for key splitting
- [ ] Implement partial decryption protocol
- [ ] Implement share aggregation
- [ ] Add key resharing for rotation

**Phase 3: Integration with lux/tfhe**
- [ ] Connect to `@luxfi/tfhe` for actual FHE operations
- [ ] Wire WASM or native TFHE backend
- [ ] Performance optimization for gate operations

### Architecture Notes

FHE keys differ from traditional keys:
1. **Public key** - Used for encryption only (anyone can encrypt)
2. **Secret key** - Split into shares for threshold decryption
3. **Bootstrap key** - For homomorphic operations (public)
4. **Key switching key** - For parameter changes (public)

Threshold FHE enables t-of-n decryption where:
- Total n parties each hold a key share
- Any t parties can collaborate to decrypt
- No single party can decrypt alone
- Key can be reshared without revealing secret

### Related Files
- `/backend/src/services/kms/kms-types.ts` - FHE type definitions
- `/backend/src/services/cmek/cmek-types.ts` - CMEK FHE API types
- Future: `/backend/src/services/threshold-fhe/` - Threshold FHE service

## Recent Updates (2025-12-28)

### FHE Key Type Support
- Added `FHE_COMPUTATION` to `KmsKeyUsage` enum
- Added `FheKeyAlgorithm` enum with TFHE variants
- Added `TThresholdConfig` for t-of-n threshold setups
- Added FHE-specific DTO types for key generation, decryption, rotation
- Updated CMEK types to include FHE algorithms

## Recent Updates (2025-11-12)

### Documentation Enhancements
- Created comprehensive KMS documentation at `/docs/content/docs/index.mdx`
- Covers all aspects: architecture, key management, crypto operations, HSM, access control, rotation, backup, API reference, security practices, and audit logging
- Added detailed code examples and configuration samples
- Documented migration strategies and troubleshooting guides

### Build System
- Set up pnpm-based documentation build
- Configured Mintlify for documentation generation
- Added package.json for docs directory

## Context for AI Assistants

This file (`LLM.md`) is symlinked as:
- `AGENTS.md`
- `CLAUDE.md`
- `QWEN.md`
- `GEMINI.md`

All files reference the same knowledge base. Updates here propagate to all AI systems.

## Rules for AI Assistants

1. **ALWAYS** update LLM.md with significant discoveries
2. **NEVER** commit symlinked files (.AGENTS.md, CLAUDE.md, etc.) - they're in .gitignore
3. **NEVER** create random summary files - update THIS file
4. **USE** TypeScript/Node.js patterns consistent with existing codebase
5. **FOLLOW** security best practices for cryptographic operations
6. **TEST** all code changes with appropriate unit/e2e tests
7. **DOCUMENT** API changes in OpenAPI spec and MDX files

---

**Note**: This file serves as the single source of truth for all AI assistants working on this project.