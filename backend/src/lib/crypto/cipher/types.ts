import { z } from "zod";

import { AsymmetricKeyAlgorithm } from "../sign/types";

// Supported symmetric encrypt/decrypt algorithms
export enum SymmetricKeyAlgorithm {
  AES_GCM_256 = "aes-256-gcm",
  AES_GCM_128 = "aes-128-gcm"
}
export const SymmetricKeyAlgorithmEnum = z.enum(Object.values(SymmetricKeyAlgorithm) as [string, ...string[]]).options;

// FHE-specific key algorithms
// Defined here to avoid circular dependencies with kms-types
export enum FheKeyAlgorithm {
  // TFHE (Torus Fully Homomorphic Encryption) - boolean gates and integers
  TFHE_BINARY = "tfhe-binary",
  TFHE_INTEGER = "tfhe-integer"
}
export const FheKeyAlgorithmEnum = z.enum(Object.values(FheKeyAlgorithm) as [string, ...string[]]).options;

// All allowed encryption key algorithms including FHE
export const AllowedEncryptionKeyAlgorithms = z.enum([
  ...Object.values(SymmetricKeyAlgorithm),
  ...Object.values(AsymmetricKeyAlgorithm),
  ...Object.values(FheKeyAlgorithm)
] as [string, ...string[]]).options;

export type TSymmetricEncryptionFns = {
  encrypt: (text: Buffer, key: Buffer) => Buffer;
  decrypt: (blob: Buffer, key: Buffer) => Buffer;
};
