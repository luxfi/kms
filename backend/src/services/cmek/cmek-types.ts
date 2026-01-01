import { FheKeyAlgorithm, SymmetricKeyAlgorithm } from "@app/lib/crypto/cipher";
import { AsymmetricKeyAlgorithm, SigningAlgorithm } from "@app/lib/crypto/sign";
import { OrderByDirection } from "@app/lib/types";

import { KmsKeyUsage, TThresholdConfig } from "../kms/kms-types";

export type TCmekKeyEncryptionAlgorithm = SymmetricKeyAlgorithm | AsymmetricKeyAlgorithm | FheKeyAlgorithm;

export type TCreateCmekDTO = {
  orgId: string;
  projectId: string;
  name: string;
  description?: string;
  encryptionAlgorithm: TCmekKeyEncryptionAlgorithm;
  keyUsage: KmsKeyUsage;
};

export type TUpdabteCmekByIdDTO = {
  keyId: string;
  name?: string;
  isDisabled?: boolean;
  description?: string;
};

export type TListCmeksByProjectIdDTO = {
  projectId: string;
  offset?: number;
  limit?: number;
  orderBy?: CmekOrderBy;
  orderDirection?: OrderByDirection;
  search?: string;
};

export type TCmekEncryptDTO = {
  keyId: string;
  plaintext: string;
};

export type TCmekDecryptDTO = {
  keyId: string;
  ciphertext: string;
};

export enum CmekOrderBy {
  Name = "name"
}

export type TCmekListSigningAlgorithmsDTO = {
  keyId: string;
};

export type TCmekGetPublicKeyDTO = {
  keyId: string;
};

export type TCmekSignDTO = {
  keyId: string;
  data: string;
  signingAlgorithm: SigningAlgorithm;
  isDigest: boolean;
};

export type TCmekVerifyDTO = {
  keyId: string;
  data: string;
  signature: string;
  signingAlgorithm: SigningAlgorithm;
  isDigest: boolean;
};

// ============================================================================
// FHE Key Management Types (CMEK API)
// ============================================================================

/**
 * Create an FHE key pair via CMEK API
 */
export type TCreateFheCmekDTO = {
  orgId: string;
  projectId: string;
  name: string;
  description?: string;
  algorithm: FheKeyAlgorithm;
  thresholdConfig?: TThresholdConfig;
};

/**
 * Get FHE public key via CMEK API
 */
export type TCmekGetFhePublicKeyDTO = {
  keyId: string;
};

/**
 * Request threshold decryption via CMEK API
 * For non-threshold keys, performs direct decryption
 * For threshold keys, returns partial decryption or aggregates if enough partials provided
 */
export type TCmekFheDecryptDTO = {
  keyId: string;
  ciphertext: string; // base64 encoded
  // For threshold decryption - partial results from other parties
  partialDecryptions?: Array<{
    partyId: string;
    partialResult: string; // base64 encoded
  }>;
};

/**
 * Rotate FHE key via CMEK API
 */
export type TCmekRotateFheKeyDTO = {
  keyId: string;
  newThresholdConfig?: TThresholdConfig;
};
