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