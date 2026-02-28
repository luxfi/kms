// Minimal audit log types - enterprise feature removed

export enum EventType {
  // Auth events
  LOGIN_SUCCESS = "login-success",
  LOGIN_FAILED = "login-failed",
  LOGOUT = "logout",
  SIGNUP = "signup",
  
  // Secret events
  SECRET_CREATED = "secret-created",
  SECRET_UPDATED = "secret-updated",
  SECRET_DELETED = "secret-deleted",
  SECRET_READ = "secret-read",
  
  // Project events
  PROJECT_CREATED = "project-created",
  PROJECT_UPDATED = "project-updated",
  PROJECT_DELETED = "project-deleted",
  
  // User events
  USER_CREATED = "user-created",
  USER_UPDATED = "user-updated",
  USER_DELETED = "user-deleted"
}

export enum UserAgentType {
  OTHER = "other",
  CLI = "cli",
  K8_OPERATOR = "k8-operator",
  TERRAFORM = "terraform",
  WEB = "web",
  NODE_SDK = "@infisical/sdk",
  PYTHON_SDK = "infisical-python"
}

// Actor types - used as type-only in most places
export type UserActor = { type: "user"; metadata: { userId: string; email: string; username: string } };
export type IdentityActor = { type: "identity"; metadata: { identityId: string; name: string } };
export type ServiceActor = { type: "service"; metadata: { serviceId: string; name: string } };
export type ScimClientActor = { type: "scim-client"; metadata: Record<string, unknown> };
export type UnknownUserActor = { type: "unknown"; metadata: Record<string, unknown> };
export type KmipClientActor = { type: "kmip-client"; metadata: Record<string, unknown> };
export type PlatformActor = { type: "platform"; metadata: Record<string, unknown> };
export type Actor = UserActor | IdentityActor | ServiceActor | ScimClientActor | UnknownUserActor | KmipClientActor | PlatformActor;
export type AuditLogInfo = { ipAddress?: string; userAgent?: string; userAgentType?: UserAgentType; actor: Actor };
export type SecretApprovalEvent = { type: string; metadata?: Record<string, unknown> };
export type WebhookTriggeredEvent = { type: string; metadata?: Record<string, unknown> };

export type TCreateAuditLogDTO = {
  actor: {
    type: "user" | "identity" | "service";
    metadata: any;
  };
  event: {
    type: EventType;
    metadata?: any;
  };
  ipAddress?: string;
  userAgent?: string;
  projectId?: string;
  orgId?: string;
};

export type TAuditLogServiceFactory = {
  createAuditLog: (data: TCreateAuditLogDTO) => Promise<void>;
  listAuditLogs: (filter: any) => Promise<{ data: any[]; totalCount: number }>;
  getAuditLog: (id: string) => Promise<any>;
};