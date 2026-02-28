// Minimal group functions - enterprise feature removed

export const addUsersToGroupByUserIds = async (params: {
  userIds: string[];
  groupId: string;
  userDAL: any;
}) => {
  // Stub implementation
  return [];
};

export const removeUsersFromGroupByUserIds = async (params: {
  userIds: string[];
  groupId: string;
}) => {
  // Stub implementation
  return [];
};

export const getDefaultOrgGroupSlug = (name: string) => {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "-");
};
export const convertPendingGroupAdditionsToGroupMemberships = async (_params: {
  userIds?: string[];
  groupId?: string;
  tx?: unknown;
}): Promise<void> => {
  // Stub - no-op since EE group management is removed
};
