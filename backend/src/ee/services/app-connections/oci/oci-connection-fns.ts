import { TAppConnection } from "@app/services/app-connection/app-connection-types";

export const createOCIConnection = async (params: any) => {
  // Stub implementation
  return {
    id: "oci-connection-stub",
    projectId: params.projectId,
    type: "oci" as const,
    name: params.name,
    description: params.description,
    metadata: {},
    createdAt: new Date(),
    updatedAt: new Date()
  } as TAppConnection;
};

export const updateOCIConnection = async (params: any) => {
  // Stub implementation
  return createOCIConnection(params);
};

export const deleteOCIConnection = async (params: any) => {
  // Stub implementation
  return;
};

export const validateOCIConnection = async (params: any) => {
  // Stub implementation - always return valid
  return { isValid: true };
};
export const getOCIConnectionListItem = () => ({
  name: "OCI" as const,
  app: "oci" as const,
  methods: ["user-api-key"]
});

export const validateOCIConnectionCredentials = async (_params: unknown): Promise<void> => {
  // Stub - no-op since EE OCI connection validation is removed
};
