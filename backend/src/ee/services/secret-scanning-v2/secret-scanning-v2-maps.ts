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