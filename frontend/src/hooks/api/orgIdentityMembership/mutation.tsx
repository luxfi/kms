import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiRequest } from "@app/config/request";

import { identitiesKeys } from "../identities";
import {
  TCreateOrgIdentityMembershipDTO,
  TDeleteOrgIdentityMembershipDTO,
  TOrgIdentityMembership
} from "./types";

export const useCreateOrgIdentityMembership = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ identityId, roles }: TCreateOrgIdentityMembershipDTO) => {
      const { data } = await apiRequest.post<{ identityMembership: TOrgIdentityMembership }>(
        `/v1/org-identity-memberships/${identityId}`,
        { roles }
      );
      return data.identityMembership;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: identitiesKeys.searchIdentities({ search: {} }) });
    }
  });
};

export const useDeleteOrgIdentityMembership = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ identityId }: TDeleteOrgIdentityMembershipDTO) => {
      const { data } = await apiRequest.delete<{ identityMembership: TOrgIdentityMembership }>(
        `/v1/org-identity-memberships/${identityId}`
      );
      return data.identityMembership;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: identitiesKeys.searchIdentities({ search: {} }) });
    }
  });
};
