import { TFeatureSet } from "@app/ee/services/license/license-types";

// Mock license functions for tests
export const isAddUsersDenied = jest.fn(() => false);
export const isMachineIdentityLimitReached = jest.fn(() => false);
export const isSecretApprovalEnabled = jest.fn(() => true);
export const isSecretScanningEnabled = jest.fn(() => true);
export const isInstancePoolSizeLimitReached = jest.fn(() => false);
export const isAuthMethodLimitReached = jest.fn(() => false);
export const hasExceededPrivilegeLimit = jest.fn(() => false);
export const isOidcEnabled = jest.fn(() => true);
export const isProjectSlugReserved = jest.fn(() => false);
export const isOrganizationMultiplierLimitExceeded = jest.fn(() => false);
export const canCreateOrganization = jest.fn(() => true);
export const hasCaCertVerification = jest.fn(() => true);
export const hasAdvancedProjectRBAC = jest.fn(() => true);
export const isInvalidInstance = jest.fn(() => false);
export const hasExceededProjectLimit = jest.fn(() => false);
export const getDefaultOnPremFeatures = jest.fn(() => ({
  secretScanning: true,
  secretApproval: true,
  oidc: true,
  dynamicSecrets: true,
  identityManagement: true,
  accessControls: true,
  customRateLimits: true,
  customAlerts: true,
  auditLogStreams: true,
  pitRecovery: true,
  ipAllowlisting: true,
  rbac: true,
  groups: true,
  projectTemplates: true,
  kms: true,
  workflowIntegrations: true,
  ldap: true,
  scim: true,
  secretRotation: true,
  pki: true,
  multiOrg: true,
  gatewayProxy: true,
  externalSecretSync: true,
  appConnections: true,
  ssh: true,
  compliance: true,
  secretSharing: true
}));

export const verifyInstanceLimits = jest.fn(() => ({ valid: true }));