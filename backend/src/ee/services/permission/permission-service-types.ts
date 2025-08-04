import { z } from "zod";

export const PermissionSubject = z.enum([
  "organization",
  "project",
  "secret",
  "folder",
  "identity",
  "user",
  "group",
  "service-token",
  "api-key",
  "certificate",
  "pki",
  "ssh",
  "integration",
  "webhook",
  "environment",
  "tag",
  "audit-log",
  "billing",
  "settings",
  "kms",
  "dynamic-secret",
  "secret-rotation",
  "secret-scanning",
  "secret-approval",
  "incident",
  "role",
  "permission"
]);

export type TPermissionSubject = z.infer<typeof PermissionSubject>;

export const PermissionActions = z.enum([
  "create",
  "read",
  "update",
  "delete",
  "list",
  "manage",
  "execute",
  "approve",
  "reject",
  "override",
  "export",
  "import"
]);

export type TPermissionActions = z.infer<typeof PermissionActions>;

export interface TPermission {
  subject: TPermissionSubject;
  action: TPermissionActions;
  conditions?: Record<string, any>;
}

export interface TPermissionCheck {
  actor: {
    type: string;
    id: string;
    orgId?: string;
  };
  permissions: TPermission[];
}

export type TPermissionServiceFactory = {
  evaluatePermission: (check: TPermissionCheck) => Promise<boolean>;
  canDoAction: (permission: TPermission, actor: any) => Promise<boolean>;
  getProjectPermission: (params: {
    actor: any;
    actorId: string;
    projectId: string;
    actorAuthMethod?: string | null;
    actorOrgId?: string;
    actionProjectType?: any;
  }) => Promise<{ permission: any; hasRole: boolean }>;
};