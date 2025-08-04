import { z } from "zod";
import { ActorType } from "@app/lib/types";

export enum SSHHostStatus {
  ACTIVE = "active",
  INACTIVE = "inactive",
  UNREACHABLE = "unreachable"
}

export enum LoginMappingSource {
  LOCAL = "local",
  LDAP = "ldap",
  OIDC = "oidc"
}

export const SSHHostPermissionActions = z.enum([
  "create",
  "read",
  "update",
  "delete",
  "scan"
]);

export type TSSHHostPermissionActions = z.infer<typeof SSHHostPermissionActions>;

export const SSHHostPermissionSub = z.object({
  projectId: z.string().uuid()
});

export type TSSHHostPermissionSub = z.infer<typeof SSHHostPermissionSub>;

export type TCreateSSHHostDTO = {
  actor: {
    type: ActorType;
    id: string;
    orgId: string;
  };
  projectId: string;
  hostname: string;
  ipAddress?: string;
  port?: number;
  username?: string;
  publicKey?: string;
  tags?: string[];
};

export type TUpdateSSHHostDTO = {
  actor: {
    type: ActorType;
    id: string;
    orgId: string;
  };
  projectId: string;
  hostId: string;
  hostname?: string;
  ipAddress?: string;
  port?: number;
  username?: string;
  publicKey?: string;
  tags?: string[];
  status?: SSHHostStatus;
};

export type TDeleteSSHHostDTO = {
  actor: {
    type: ActorType;
    id: string;
    orgId: string;
  };
  projectId: string;
  hostId: string;
};

export type TListSSHHostsDTO = {
  actor: {
    type: ActorType;
    id: string;
    orgId: string;
  };
  projectId: string;
  status?: SSHHostStatus;
  tags?: string[];
  limit?: number;
  offset?: number;
};