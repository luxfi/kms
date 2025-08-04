import { TProjectPermission } from "@app/lib/types";

export type TSecretScanningV2ProviderType = "github" | "gitlab" | "bitbucket" | "azure-devops";

export type TSecretScanningV2Status = "active" | "inactive" | "pending" | "failed";

export interface TSecretScanningV2Config {
  id: string;
  projectId: string;
  provider: TSecretScanningV2ProviderType;
  status: TSecretScanningV2Status;
  lastScanAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface TCreateSecretScanningV2DTO extends TProjectPermission {
  provider: TSecretScanningV2ProviderType;
  config: Record<string, any>;
}

export interface TUpdateSecretScanningV2DTO extends TProjectPermission {
  id: string;
  config?: Record<string, any>;
  status?: TSecretScanningV2Status;
}

export interface TDeleteSecretScanningV2DTO extends TProjectPermission {
  id: string;
}

export interface TQueueSecretScanningDataSourceFullScan {
  id: string;
  type: "full-scan";
  dataSourceId: string;
}

export interface TQueueSecretScanningResourceDiffScan {
  id: string;
  type: "diff-scan";
  dataSourceId: string;
  resourceId: string;
}

export interface TQueueSecretScanningSendNotification {
  id: string;
  type: "send-notification";
  scanResultId: string;
  findings: any[];
}

export interface TGetSecretScanningV2DTO extends TProjectPermission {
  id: string;
}

export interface TListSecretScanningV2DTO extends TProjectPermission {
  limit?: number;
  offset?: number;
}