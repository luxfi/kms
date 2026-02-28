import { TAppConnection } from "@app/services/app-connection/app-connection-types";

export const createOracleDBConnection = async (params: any) => {
  // Stub implementation
  return {
    id: "oracledb-connection-stub",
    projectId: params.projectId,
    type: "oracledb" as const,
    name: params.name,
    description: params.description,
    metadata: {},
    createdAt: new Date(),
    updatedAt: new Date()
  } as TAppConnection;
};

export const updateOracleDBConnection = async (params: any) => {
  // Stub implementation
  return createOracleDBConnection(params);
};

export const deleteOracleDBConnection = async (params: any) => {
  // Stub implementation
  return;
};

export const validateOracleDBConnection = async (params: any) => {
  // Stub implementation - always return valid
  return { isValid: true };
};
export const getOracleDBConnectionListItem = () => ({
  name: "OracleDB" as const,
  app: "oracledb" as const,
  methods: ["basic-auth"]
});
