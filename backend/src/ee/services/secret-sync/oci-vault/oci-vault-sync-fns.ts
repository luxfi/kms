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