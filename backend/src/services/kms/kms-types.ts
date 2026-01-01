import { Knex } from "knex";

import { SymmetricKeyAlgorithm } from "@app/lib/crypto/cipher";
import { AsymmetricKeyAlgorithm, SigningAlgorithm } from "@app/lib/crypto/sign/types";

export enum KmsDataKey {
  Organization,
  SecretManager
  // CertificateManager
}

export enum KmsType {
  External = "external",
  Internal = "internal"
}

export enum KmsKeyUsage {
  ENCRYPT_DECRYPT = "encrypt-decrypt",
  SIGN_VERIFY = "sign-verify",
  // FHE key usage - for fully homomorphic encryption operations
  // Supports threshold decryption where multiple parties hold key shares
  FHE_COMPUTATION = "fhe-computation"
}

// Re-export FheKeyAlgorithm from cipher/types to avoid circular deps
// The canonical definition is in @app/lib/crypto/cipher/types
export { FheKeyAlgorithm } from "@app/lib/crypto/cipher/types";

// Threshold FHE types for t-of-n decryption
export type TThresholdConfig = {
  // Threshold (t) - minimum parties required for decryption
  threshold: number;
  // Total parties (n) - total number of key shares
  totalParties: number;
  // Party identifiers
  partyIds: string[];
}

export type TEncryptWithKmsDataKeyDTO =
  | { type: KmsDataKey.Organization; orgId: string }
  | { type: KmsDataKey.SecretManager; projectId: string };
// akhilmhdh: not implemented yet
// | {
//     type: KmsDataKey.CertificateManager;
//     projectId: string;
//   };

export type TGenerateKMSDTO = {
  orgId: string;
  projectId?: string;
  encryptionAlgorithm?: SymmetricKeyAlgorithm | AsymmetricKeyAlgorithm;
  keyUsage?: KmsKeyUsage;
  isReserved?: boolean;
  name?: string;
  description?: string;
  tx?: Knex;
};

export type TEncryptWithKmsDTO = {
  kmsId: string;
  plainText: Buffer;
};

export type TGetPublicKeyDTO = {
  kmsId: string;
};

export type TSignWithKmsDTO = {
  kmsId: string;
  data: Buffer;
  signingAlgorithm: SigningAlgorithm;
  isDigest: boolean;
};

export type TVerifyWithKmsDTO = {
  kmsId: string;
  data: Buffer;
  signature: Buffer;
  signingAlgorithm: SigningAlgorithm;
  isDigest: boolean;
};

export type TEncryptionWithKeyDTO = {
  key: Buffer;
  plainText: Buffer;
};

export type TDecryptWithKmsDTO = {
  kmsId: string;
  cipherTextBlob: Buffer;
};

export type TDecryptWithKeyDTO = {
  key: Buffer;
  cipherTextBlob: Buffer;
};

export type TUpdateProjectSecretManagerKmsKeyDTO = {
  projectId: string;
  kms: { type: KmsType.Internal } | { type: KmsType.External; kmsId: string };
};

export enum RootKeyEncryptionStrategy {
  Software = "SOFTWARE",
  HSM = "HSM"
}
export type TGetKeyMaterialDTO = {
  kmsId: string;
};

export type TImportKeyMaterialDTO = {
  key: Buffer;
  algorithm: SymmetricKeyAlgorithm;
  name?: string;
  isReserved: boolean;
  projectId: string;
  orgId: string;
  keyUsage: KmsKeyUsage;
};

// ============================================================================
// FHE Key Management Types
// ============================================================================

/**
 * Generate an FHE key pair
 * Returns public key and internal keyId for later operations
 */
export type TGenerateFheKeyPairDTO = {
  orgId: string;
  projectId: string;
  name?: string;
  description?: string;
  algorithm: FheKeyAlgorithm;
  // Optional threshold config for t-of-n decryption
  thresholdConfig?: TThresholdConfig;
};

/**
 * Get public key for an FHE key
 */
export type TGetFhePublicKeyDTO = {
  keyId: string;
};

/**
 * FHE threshold decryption request
 * Requires t-of-n partial decryptions to complete
 */
export type TFheThresholdDecryptDTO = {
  keyId: string;
  ciphertext: Buffer;
  // Partial decryptions from threshold parties
  partialDecryptions?: Array<{
    partyId: string;
    partialResult: Buffer;
  }>;
};

/**
 * Request partial decryption from this KMS instance
 * Used in threshold FHE where each party produces a partial result
 */
export type TFhePartialDecryptDTO = {
  keyId: string;
  ciphertext: Buffer;
  partyId: string;
};

/**
 * Rotate FHE key (reshare without revealing secret)
 */
export type TRotateFheKeyDTO = {
  keyId: string;
  // New threshold config (optional - keeps existing if not provided)
  newThresholdConfig?: TThresholdConfig;
};
