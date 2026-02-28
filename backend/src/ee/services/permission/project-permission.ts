// Minimal permission enums for KMS
// This is a stub implementation - full enterprise features removed

export enum ProjectPermissionActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum ProjectPermissionCommitsActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  PerformRollback = "perform-rollback"
}

export enum ProjectPermissionSecretActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  DescribeSecret = "describe-secret",
  ReadValue = "read-value"
}

export enum ProjectPermissionCmekActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  Encrypt = "encrypt",
  Decrypt = "decrypt"
}

export enum ProjectPermissionGroupActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  GrantPrivilege = "grant-privilege"
}

export enum ProjectPermissionIdentityActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  GrantPrivilege = "grant-privilege"
}

export enum ProjectPermissionMemberActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  GrantPrivilege = "grant-privilege"
}

export enum ProjectPermissionSub {
  Role = "role",
  Member = "member",
  Groups = "groups",
  Settings = "settings",
  Integrations = "integrations",
  Webhooks = "webhooks",
  ServiceTokens = "service-tokens",
  Environments = "environments",
  Tags = "tags",
  AuditLogs = "audit-logs",
  IpAllowList = "ip-allowlist",
  Project = "workspace",
  Secrets = "secrets",
  SecretFolders = "secret-folders",
  SecretImports = "secret-imports",
  DynamicSecrets = "dynamic-secrets",
  SecretRollback = "secret-rollback",
  SecretApproval = "secret-approval",
  SecretRotation = "secret-rotation",
  Commits = "commits",
  Identity = "identity",
  CertificateAuthorities = "certificate-authorities",
  Certificates = "certificates",
  CertificateTemplates = "certificate-templates",
  SshCertificateAuthorities = "ssh-certificate-authorities",
  SshCertificates = "ssh-certificates",
  SshCertificateTemplates = "ssh-certificate-templates",
  SshHosts = "ssh-hosts",
  PkiSubscribers = "pki-subscribers",
  SshHostGroups = "ssh-host-groups",
  PkiAlerts = "pki-alerts",
  PkiCollections = "pki-collections",
  Kmip = "kmip",
  Cmek = "cmek",
  Kms = "kms",
  SecretScanningDataSources = "secret-scanning-data-sources",
  SecretScanningFindings = "secret-scanning-findings",
  SecretScanningConfigs = "secret-scanning-configs",
  SecretSyncs = "secret-syncs"
}