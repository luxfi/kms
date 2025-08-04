import { TProjectPermission } from "@app/lib/types";

export interface TOCIVaultSyncConfig {
  tenancyOcid: string;
  userOcid: string;
  fingerprint: string;
  privateKey: string;
  region: string;
  compartmentOcid: string;
  vaultOcid: string;
}

export interface TCreateOCIVaultSyncDTO extends TProjectPermission {
  name: string;
  description?: string;
  sourceEnvironment: string;
  secretPath: string;
  tenancyOcid: string;
  userOcid: string;
  fingerprint: string;
  privateKey: string;
  region: string;
  compartmentOcid: string;
  vaultOcid: string;
  isAutoSyncEnabled?: boolean;
}

export interface TUpdateOCIVaultSyncDTO extends TProjectPermission {
  id: string;
  name?: string;
  description?: string;
  sourceEnvironment?: string;
  secretPath?: string;
  tenancyOcid?: string;
  userOcid?: string;
  fingerprint?: string;
  privateKey?: string;
  region?: string;
  compartmentOcid?: string;
  vaultOcid?: string;
  isAutoSyncEnabled?: boolean;
}

export interface TDeleteOCIVaultSyncDTO extends TProjectPermission {
  id: string;
}

export interface TSyncOCIVaultDTO extends TProjectPermission {
  id: string;
}