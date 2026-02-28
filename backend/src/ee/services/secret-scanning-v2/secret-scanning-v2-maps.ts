import { TSecretScanningV2ProviderType } from "./secret-scanning-v2-types";

export const SECRET_SCANNING_V2_PROVIDERS_MAP: Record<TSecretScanningV2ProviderType, string> = {
  "github": "GitHub",
  "gitlab": "GitLab",
  "bitbucket": "Bitbucket",
  "azure-devops": "Azure DevOps"
};

export const SECRET_SCANNING_V2_STATUS_MAP = {
  active: "Active",
  inactive: "Inactive",
  pending: "Pending",
  failed: "Failed"
} as const;
export const SECRET_SCANNING_DATA_SOURCE_NAME_MAP: Record<string, string> = {
  github: "GitHub",
  gitlab: "GitLab",
  bitbucket: "Bitbucket",
  "azure-devops": "Azure DevOps"
};

export const SECRET_SCANNING_DATA_SOURCE_CONNECTION_MAP: Record<string, string | null> = {
  github: "github",
  gitlab: "gitlab",
  bitbucket: "bitbucket",
  "azure-devops": "azure-devops"
};

export const AUTO_SYNC_DESCRIPTION_HELPER: Record<string, string> = {
  github: "Automatically scan GitHub repositories for exposed secrets",
  gitlab: "Automatically scan GitLab projects for exposed secrets",
  bitbucket: "Automatically scan Bitbucket repositories for exposed secrets",
  "azure-devops": "Automatically scan Azure DevOps repositories for exposed secrets"
};
