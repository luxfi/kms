// External KMS provider model - enterprise feature removed
import { z } from "zod";

export enum KmsProviders {
  AWS = "aws",
  GCP = "gcp",
  AZURE = "azure",
  HSM = "hsm",
  LOCAL = "local"
}

export const ExternalKmsAwsSchema = z.object({
  type: z.literal(KmsProviders.AWS),
  credential: z.object({
    region: z.string(),
    accessKeyId: z.string().optional(),
    secretAccessKey: z.string().optional()
  }),
  encryptionKeyId: z.string().optional()
});

export const ExternalKmsGcpSchema = z.object({
  type: z.literal(KmsProviders.GCP),
  credential: z.object({
    projectId: z.string(),
    keyName: z.string(),
    keyRing: z.string(),
    locationId: z.string()
  })
});

export type TExternalKmsProviderFns = {
  encrypt: (data: Buffer) => Promise<{ encryptedBlob: Buffer }>;
  decrypt: (data: Buffer) => Promise<{ data: Buffer }>;
  generateDataKey: () => Promise<{ plaintext: Buffer; ciphertext: Buffer }>;
  cleanup: () => Promise<void>;
};