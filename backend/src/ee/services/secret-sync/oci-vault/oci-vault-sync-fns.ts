import { TProjectPermission } from "@app/lib/types";

export const createOCIVaultSync = async (params: any) => {
  // Stub implementation
  return {
    id: "oci-vault-sync-stub",
    projectId: params.projectId,
    destination: "oci-vault",
    status: "active",
    createdAt: new Date(),
    updatedAt: new Date()
  };
};

export const updateOCIVaultSync = async (params: any) => {
  // Stub implementation
  return createOCIVaultSync(params);
};

export const deleteOCIVaultSync = async (params: any) => {
  // Stub implementation
  return;
};

export const syncSecretsToOCIVault = async (params: any) => {
  // Stub implementation - pretend sync succeeded
  return {
    success: true,
    syncedSecrets: 0
  };
};

export const validateOCIVaultConnection = async (params: any) => {
  // Stub implementation - always return valid
  return { isValid: true };
};
export const OCI_VAULT_SYNC_LIST_OPTION = {
  name: "OCI Vault" as const,
  destination: "oci-vault" as const
};

export const OCIVaultSyncFns = {
  syncSecrets: async (_secretSync: unknown, _schemaSecretMap: unknown): Promise<void> => {
    // Stub - no-op since EE OCI Vault sync is removed
  },
  getSecrets: async (_secretSync: unknown): Promise<Record<string, unknown>> => {
    return {};
  },
  removeSecrets: async (_secretSync: unknown, _schemaSecretMap: unknown): Promise<void> => {
    // Stub - no-op
  }
};
