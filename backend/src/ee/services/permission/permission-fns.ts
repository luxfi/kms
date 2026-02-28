// Minimal permission functions for KMS
// This is a stub implementation - full enterprise features removed

export const getUserOrgPermissions = (userId: string, orgId: string) => {
  // Stub - return all permissions for now
  return {
    permissions: ["*"],
    roles: ["admin"]
  };
};

export const getUserProjectPermissions = (userId: string, projectId: string) => {
  // Stub - return all permissions for now
  return {
    permissions: ["*"],
    roles: ["admin"]
  };
};

export const ForbiddenError = class extends Error {
  constructor(message = "Forbidden") {
    super(message);
    this.name = "ForbiddenError";
  }
};

export const isAuthMethodSaml = (_authMethod: unknown): boolean => {
  return false;
};

export const throwIfMissingSecretReadValueOrDescribePermission = (
  _permission: unknown,
  _action: unknown,
  _context?: { environment?: string; secretPath?: string }
): void => {
  // Stub - no-op since EE permission checks are removed (full access)
};

// Stub - always returns true (full access) since EE permission checks are removed
export const hasSecretReadValueOrDescribePermission = (
  _permission: unknown,
  _action: unknown,
  _context?: { environment?: string; secretPath?: string }
): boolean => {
  return true;
};