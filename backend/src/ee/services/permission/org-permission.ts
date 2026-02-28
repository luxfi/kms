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
  Identity = "identity"
}