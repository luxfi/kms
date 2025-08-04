import { TSuperAdminDALFactory } from "@app/services/super-admin/super-admin-dal";

export type TLicenseServiceFactory = ReturnType<typeof licenseServiceFactory>;

export const licenseServiceFactory = ({
  superAdminDAL
}: {
  superAdminDAL: TSuperAdminDALFactory;
}) => {
  const onPremFeatures = {
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
    secretSharing: true,
    fips: true,
    instanceUserManagement: true,
    hsm: true
  };
  
  const licenseFeatures = onPremFeatures;
  const refreshPlan = async () => {
    // Mock implementation
    return {
      features: {
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
      }
    };
  };

  const getOrgPlan = async (orgId: string) => {
    return {
      features: {
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
      }
    };
  };

  const getInstanceFeatures = async () => {
    return {
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
    };
  };

  const getPlan = async () => {
    return {
      features: await getInstanceFeatures()
    };
  };

  return {
    refreshPlan,
    getOrgPlan,
    getInstanceFeatures,
    getPlan,
    onPremFeatures,
    licenseFeatures
  };
};