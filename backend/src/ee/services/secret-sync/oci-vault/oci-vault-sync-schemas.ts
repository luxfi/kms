import { z } from "zod";
import { SecretSync } from "@app/services/secret-sync/secret-sync-enums";
import {
  BaseSecretSyncSchema,
  GenericCreateSecretSyncFieldsSchema,
  GenericUpdateSecretSyncFieldsSchema
} from "@app/services/secret-sync/secret-sync-schemas";

export enum OCIVaultSyncMethod {
  UserAPIKey = "user-api-key"
}

export const OCIVaultSyncConnectionCredentialsSchema = z.object({
  tenancyOcid: z.string().trim().min(1, "Tenancy OCID required"),
  userOcid: z.string().trim().min(1, "User OCID required"),
  fingerprint: z.string().trim().min(1, "Fingerprint required"),
  privateKey: z.string().trim().min(1, "Private Key required"),
  region: z.string().trim().min(1, "Region required"),
  compartmentOcid: z.string().trim().min(1, "Compartment OCID required"),
  vaultOcid: z.string().trim().min(1, "Vault OCID required")
});

const BaseOCIVaultSyncSchema = BaseSecretSyncSchema(
  SecretSync.OCIVault,
  { canImportSecrets: false }
).extend({ 
  destination: z.literal(SecretSync.OCIVault) 
});

export const OCIVaultSyncSchema = BaseOCIVaultSyncSchema.extend({
  destinationConfig: OCIVaultSyncConnectionCredentialsSchema
});

export const SanitizedOCIVaultSyncSchema = BaseOCIVaultSyncSchema.extend({
  destinationConfig: OCIVaultSyncConnectionCredentialsSchema.pick({
    tenancyOcid: true,
    userOcid: true,
    fingerprint: true,
    region: true,
    compartmentOcid: true,
    vaultOcid: true
  })
});

export const CreateOCIVaultSyncSchema = z.object({
  destinationConfig: OCIVaultSyncConnectionCredentialsSchema
}).and(GenericCreateSecretSyncFieldsSchema(SecretSync.OCIVault, { canImportSecrets: false }));

export const UpdateOCIVaultSyncSchema = z.object({
  destinationConfig: OCIVaultSyncConnectionCredentialsSchema.optional()
}).and(GenericUpdateSecretSyncFieldsSchema(SecretSync.OCIVault, { canImportSecrets: false }));

export const OCIVaultSyncListItemSchema = z.object({
  name: z.literal("Oracle Cloud Vault"),
  destination: z.literal(SecretSync.OCIVault)
});