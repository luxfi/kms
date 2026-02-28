// Minimal org permission enums for KMS
// This is a stub implementation - full enterprise features removed

export enum OrgPermissionActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum OrgPermissionAdminConsoleAction {
  AccessAdminConsole = "access-admin-console"
}

export enum OrgPermissionIdentityActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  GrantPrivilege = "grant-privilege"
}

export enum OrgPermissionGroupActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum OrgPermissionSecretShareAction {
  ManageSettings = "manage-settings"
}

export enum OrgPermissionAppConnectionActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum OrgPermissionGatewayActions {
  ListGateways = "list-gateways",
  CreateGateways = "create-gateways",
  EditGateways = "edit-gateways",
  DeleteGateways = "delete-gateways",
  AttachGateways = "attach-gateways"
}

export enum OrgPermissionSubjects {
  Org = "organization",
  Member = "member",
  Role = "role",
  IncidentContact = "incident-contact",
  Sso = "sso",
  Scim = "scim",
  Ldap = "ldap",
  Groups = "groups",
  Billing = "billing",
  SecretScanning = "secret-scanning",
  Identity = "identity",
  AppConnections = "app-connections",
  Gateway = "gateway",
  SecretShare = "secret-share",
  AdminConsole = "admin-console"
}

// Stub permission sets
export const orgAdminPermissions = [
  { action: ["read", "create", "edit", "delete"], subject: OrgPermissionSubjects.Member },
  { action: ["read", "create", "edit", "delete"], subject: OrgPermissionSubjects.Groups },
  { action: ["read", "create", "edit", "delete"], subject: OrgPermissionSubjects.Identity },
  { action: ["read", "create", "edit", "delete"], subject: OrgPermissionSubjects.Role }
];

export const orgMemberPermissions = [
  { action: ["read"], subject: OrgPermissionSubjects.Member },
  { action: ["read"], subject: OrgPermissionSubjects.Groups }
];

export const orgNoAccessPermissions: typeof orgAdminPermissions = [];
