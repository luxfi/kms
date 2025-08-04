// Default roles for KMS
import { ProjectMembershipRole } from "@app/db/schemas";
import { ProjectPermissionActions, ProjectPermissionSub } from "./project-permission";

export const projectAdminPermissions = [
  {
    action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete],
    subject: ProjectPermissionSub.Secrets
  },
  {
    action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete],
    subject: ProjectPermissionSub.SecretFolders
  },
  {
    action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete],
    subject: ProjectPermissionSub.ServiceTokens
  },
  {
    action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete],
    subject: ProjectPermissionSub.Member
  },
  {
    action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete],
    subject: ProjectPermissionSub.Settings
  }
];

export const projectMemberPermissions = [
  {
    action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete],
    subject: ProjectPermissionSub.Secrets
  },
  {
    action: [ProjectPermissionActions.Read],
    subject: ProjectPermissionSub.SecretFolders
  }
];

export const projectViewerPermissions = [
  {
    action: [ProjectPermissionActions.Read],
    subject: ProjectPermissionSub.Secrets
  },
  {
    action: [ProjectPermissionActions.Read],
    subject: ProjectPermissionSub.SecretFolders
  }
];

export const getDefaultProjectRolePermissions = (role: ProjectMembershipRole) => {
  switch (role) {
    case ProjectMembershipRole.Admin:
      return projectAdminPermissions;
    case ProjectMembershipRole.Member:
      return projectMemberPermissions;
    case ProjectMembershipRole.Viewer:
      return projectViewerPermissions;
    default:
      return [];
  }
};