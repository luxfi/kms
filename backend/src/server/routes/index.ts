import { Knex } from "knex";
import { z } from "zod";
import { FastifyZodProvider } from "@app/server/plugins/fastify-zod";
import { getConfig, TEnvConfig } from "@app/lib/config/env";
import { TSmtpService } from "@app/services/smtp/smtp-service";
import { TQueueServiceFactory } from "@app/queue";
import { TKeyStoreFactory } from "@app/keystore/keystore";
import { TSuperAdminDALFactory } from "@app/services/super-admin/super-admin-dal";

// Import only core services needed
import { userDALFactory } from "@app/services/user/user-dal";
import { userServiceFactory } from "@app/services/user/user-service";
import { userAliasDALFactory } from "@app/services/user-alias/user-alias-dal";
import { orgDALFactory } from "@app/services/org/org-dal";
import { orgServiceFactory } from "@app/services/org/org-service";
import { orgRoleDALFactory } from "@app/services/org/org-role-dal";
import { orgBotDALFactory } from "@app/services/org/org-bot-dal";
import { incidentContactDALFactory } from "@app/services/org/incident-contacts-dal";
import { orgMembershipDALFactory } from "@app/services/org-membership/org-membership-dal";
import { projectDALFactory } from "@app/services/project/project-dal";
import { projectServiceFactory } from "@app/services/project/project-service";
import { projectBotDALFactory } from "@app/services/project-bot/project-bot-dal";
import { projectKeyDALFactory } from "@app/services/project-key/project-key-dal";
import { projectMembershipDALFactory } from "@app/services/project-membership/project-membership-dal";
import { projectEnvDALFactory } from "@app/services/project-env/project-env-dal";
import { authLoginServiceFactory } from "@app/services/auth/auth-login-service";
import { authSignupServiceFactory } from "@app/services/auth/auth-signup-service";
import { authPasswordServiceFactory } from "@app/services/auth/auth-password-service";
import { authDALFactory } from "@app/services/auth/auth-dal";
import { tokenDALFactory } from "@app/services/auth-token/auth-token-dal";
import { tokenServiceFactory } from "@app/services/auth-token/auth-token-service";
import { casdoorAuthServiceFactory } from "@app/services/auth/casdoor-auth-service";
import { secretDALFactory } from "@app/services/secret/secret-dal";
import { secretServiceFactory } from "@app/services/secret/secret-service";
import { secretFolderDALFactory } from "@app/services/secret-folder/secret-folder-dal";
import { totpServiceFactory } from "@app/services/totp/totp-service";
import { totpConfigDALFactory } from "@app/services/totp/totp-config-dal";
import { projectRoleDALFactory } from "@app/services/project-role/project-role-dal";
import { kmsServiceFactory } from "@app/services/kms/kms-service";
import { kmskeyDALFactory } from "@app/services/kms/kms-key-dal";
import { kmsRootConfigDALFactory } from "@app/services/kms/kms-root-config-dal";
import { internalKmsDALFactory } from "@app/services/kms/internal-kms-dal";

// Basic V1 routes
import { registerV1Routes } from "@app/server/routes/v1";
import { registerV2Routes } from "@app/server/routes/v2";
import { registerV3Routes } from "@app/server/routes/v3";

// Create minimal stub services for missing EE features
const createStubAuditLogService = () => ({
  createAuditLog: async () => {},
  listAuditLogs: async () => ({ data: [], totalCount: 0 }),
  getAuditLog: async () => null
});

const createStubPermissionService = () => ({
  getOrgPermission: async () => ({ permissions: ["*"], roles: ["admin"] }),
  getProjectPermission: async () => ({ permissions: ["*"], roles: ["admin"] }),
  getUserOrgPermissions: async () => ({ permissions: ["*"], roles: ["admin"] }),
  getUserProjectPermissions: async () => ({ permissions: ["*"], roles: ["admin"] })
});

export const registerRoutes = async (
  server: FastifyZodProvider,
  {
    auditLogDb,
    superAdminDAL,
    db,
    hsmModule,
    smtp: smtpService,
    queue: queueService,
    keyStore,
    envConfig
  }: {
    auditLogDb?: Knex;
    superAdminDAL: TSuperAdminDALFactory;
    db: Knex;
    hsmModule?: any; // Optional HSM module
    smtp: TSmtpService;
    queue: TQueueServiceFactory;
    keyStore: TKeyStoreFactory;
    envConfig: TEnvConfig;
  }
) => {
  const appCfg = getConfig();
  
  // Core DALs
  const userDAL = userDALFactory(db);
  const userAliasDAL = userAliasDALFactory(db);
  const authDAL = authDALFactory(db);
  const tokenDAL = tokenDALFactory(db);
  const orgDAL = orgDALFactory(db);
  const orgRoleDAL = orgRoleDALFactory(db);
  const orgBotDAL = orgBotDALFactory(db);
  const incidentContactDAL = incidentContactDALFactory(db);
  const orgMembershipDAL = orgMembershipDALFactory(db);
  const projectDAL = projectDALFactory(db);
  const projectBotDAL = projectBotDALFactory(db);
  const projectKeyDAL = projectKeyDALFactory(db);
  const projectMembershipDAL = projectMembershipDALFactory(db);
  const projectEnvDAL = projectEnvDALFactory(db);
  const projectRoleDAL = projectRoleDALFactory(db);
  const secretDAL = secretDALFactory(db);
  const secretFolderDAL = secretFolderDALFactory(db);
  const totpConfigDAL = totpConfigDALFactory(db);
  const kmsKeyDAL = kmskeyDALFactory(db);
  const kmsRootConfigDAL = kmsRootConfigDALFactory(db);
  const internalKmsDAL = internalKmsDALFactory(db);

  // Stub services for missing EE features
  const auditLogService = createStubAuditLogService();
  const permissionService = createStubPermissionService();
  
  // Core services
  const tokenService = tokenServiceFactory({
    tokenDAL,
    cfg: appCfg
  });

  const totpService = totpServiceFactory({
    totpConfigDAL
  });

  const kmsService = kmsServiceFactory({
    kmsDAL: internalKmsDAL,
    kmsKeyDAL,
    kmsRootConfigDAL,
    projectDAL,
    keyStore
  });
  
  const userService = userServiceFactory({
    userDAL,
    userAliasDAL,
    orgDAL,
    db
  });
  
  const loginService = authLoginServiceFactory({
    userDAL,
    smtpService,
    tokenService,
    orgDAL,
    totpService,
    orgMembershipDAL,
    auditLogService
  });

  const signupService = authSignupServiceFactory({
    userDAL,
    userAliasDAL,
    authDAL,
    orgDAL,
    orgBotDAL,
    orgRoleDAL,
    orgMembershipDAL,
    projectDAL,
    projectBotDAL,
    projectKeyDAL,
    projectMembershipDAL,
    projectEnvDAL,
    projectRoleDAL,
    incidentContactDAL,
    tokenService,
    smtpService,
    keyStore
  });

  const passwordService = authPasswordServiceFactory({
    tokenService,
    smtpService,
    userDAL,
    authDAL,
    totpConfigDAL
  });
  
  const casdoorAuthService = casdoorAuthServiceFactory({
    userDAL,
    orgDAL,
    orgMembershipDAL,
    tokenService,
    authDAL
  });
  
  const orgService = orgServiceFactory({
    orgDAL,
    orgBotDAL,
    orgRoleDAL,
    incidentContactDAL,
    userDAL,
    orgMembershipDAL,
    smtpService,
    tokenService,
    permissionService,
    db
  });
  
  const projectService = projectServiceFactory({
    projectDAL,
    projectBotDAL,
    projectKeyDAL,
    projectRoleDAL,
    folderDAL: secretFolderDAL,
    projectEnvDAL,
    projectMembershipDAL,
    orgDAL,
    orgRoleDAL,
    userDAL,
    permissionService,
    smtpService,
    kmsService,
    auditLogService,
    db
  });
  
  const secretService = secretServiceFactory({
    secretDAL,
    secretFolderDAL,
    projectDAL,
    projectBotDAL,
    projectEnvDAL,
    permissionService,
    auditLogService,
    db
  });

  // Basic health check
  server.route({
    method: "GET",
    url: "/api/status",
    schema: {
      response: {
        200: z.object({
          status: z.string(),
          date: z.string()
        })
      }
    },
    handler: async () => {
      return {
        status: "OK",
        date: new Date().toISOString()
      };
    }
  });

  // Decorate server with services
  server.decorate("services", {
    user: userService,
    login: loginService,
    signup: signupService,
    password: passwordService,
    casdoorAuth: casdoorAuthService,
    authToken: tokenService,
    org: orgService,
    project: projectService,
    secret: secretService,
    totp: totpService,
    kms: kmsService,
    permission: permissionService,
    auditLog: auditLogService
  });

  // Register routes
  await server.register(registerV1Routes, { prefix: "/api/v1" });
  await server.register(registerV2Routes, { prefix: "/api/v2" });
  await server.register(registerV3Routes, { prefix: "/api/v3" });
};