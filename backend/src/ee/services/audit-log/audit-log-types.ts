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