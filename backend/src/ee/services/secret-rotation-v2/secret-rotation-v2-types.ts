// Secret rotation v2 types - enterprise feature stub
import { TProjectPermission } from "@app/lib/types";

export type TSecretRotationV2Providers = 
  | "aws-iam-user"
  | "postgres-credentials"
  | "mysql-credentials"
  | "mssql-credentials"
  | "oracle-credentials"
  | "sendgrid"
  | "auth0-client-secret"
  | "azure-client-secret"
  | "okta-client-secret"
  | "ldap-password";

export enum SecretRotationV2Status {
  SUCCESS = "success",
  PENDING = "pending",
  FAILED = "failed"
}

export interface TSecretRotationV2Config {
  id: string;
  projectId: string;
  provider: TSecretRotationV2Providers;
  secretMappings: Record<string, string>;
  interval: number;
  lastRotatedAt?: Date;
  status: SecretRotationV2Status;
  createdAt: Date;
  updatedAt: Date;
}

export interface TCreateSecretRotationV2DTO extends TProjectPermission {
  provider: TSecretRotationV2Providers;
  secretMappings: Record<string, string>;
  interval: number;
  config: Record<string, any>;
}

export interface TUpdateSecretRotationV2DTO extends TProjectPermission {
  id: string;
  secretMappings?: Record<string, string>;
  interval?: number;
  config?: Record<string, any>;
}

export interface TDeleteSecretRotationV2DTO extends TProjectPermission {
  id: string;
}

export interface TSecretRotationV2QueuePayload {
  rotationId: string;
  rotationType: "scheduled" | "manual";
}

export interface TRotateSecretV2DTO extends TProjectPermission {
  id: string;
}