import { TProjectPermission } from "@app/lib/types";

export interface TGroup {
  id: string;
  orgId: string;
  name: string;
  slug: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface TGroupMembership {
  id: string;
  groupId: string;
  userId: string;
  role: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface TCreateGroupDTO {
  orgId: string;
  name: string;
  slug?: string;
  description?: string;
}

export interface TUpdateGroupDTO {
  id: string;
  name?: string;
  slug?: string;
  description?: string;
}

export interface TDeleteGroupDTO {
  id: string;
}

export interface TAddUserToGroupDTO {
  groupId: string;
  userId: string;
  role?: string;
}

export interface TRemoveUserFromGroupDTO {
  groupId: string;
  userId: string;
}

export interface TGroupProjectPermission extends TProjectPermission {
  groupId: string;
}

export interface TListGroupsDTO {
  orgId: string;
  limit?: number;
  offset?: number;
}

export interface TGetGroupBySlugDTO {
  orgId: string;
  slug: string;
}