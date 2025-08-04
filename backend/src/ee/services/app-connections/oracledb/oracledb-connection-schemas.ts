import { z } from "zod";
import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import {
  BaseAppConnectionSchema,
  GenericCreateAppConnectionFieldsSchema,
  GenericUpdateAppConnectionFieldsSchema
} from "@app/services/app-connection/app-connection-schemas";

export enum OracleDBConnectionMethod {
  BasicAuth = "basic-auth"
}

export const OracleDBConnectionBasicAuthCredentialsSchema = z.object({
  host: z.string().trim().min(1, "Host required"),
  port: z.number().int().positive("Port must be positive"),
  database: z.string().trim().min(1, "Database required"),
  username: z.string().trim().min(1, "Username required"),
  password: z.string().trim().min(1, "Password required"),
  serviceName: z.string().optional(),
  sid: z.string().optional()
});

const BaseOracleDBConnectionSchema = BaseAppConnectionSchema.extend({ app: z.literal(AppConnection.OracleDB) });

export const OracleDBConnectionSchema = z.intersection(
  BaseOracleDBConnectionSchema,
  z.discriminatedUnion("method", [
    z.object({
      method: z.literal(OracleDBConnectionMethod.BasicAuth),
      credentials: OracleDBConnectionBasicAuthCredentialsSchema
    })
  ])
);

// Convert discriminatedUnion to regular union for compatibility
export const SanitizedOracleDBConnectionSchema = z.union([
  BaseOracleDBConnectionSchema.extend({
    method: z.literal(OracleDBConnectionMethod.BasicAuth),
    credentials: OracleDBConnectionBasicAuthCredentialsSchema.pick({
      host: true,
      port: true,
      database: true,
      username: true,
      serviceName: true,
      sid: true
    })
  })
]);

export const ValidateOracleDBConnectionCredentialsSchema = z.discriminatedUnion("method", [
  z.object({
    method: z.literal(OracleDBConnectionMethod.BasicAuth),
    credentials: OracleDBConnectionBasicAuthCredentialsSchema
  })
]);

export const CreateOracleDBConnectionSchema = ValidateOracleDBConnectionCredentialsSchema.and(
  GenericCreateAppConnectionFieldsSchema(AppConnection.OracleDB)
);

export const UpdateOracleDBConnectionSchema = z
  .object({
    credentials: OracleDBConnectionBasicAuthCredentialsSchema.optional()
  })
  .and(GenericUpdateAppConnectionFieldsSchema(AppConnection.OracleDB));

export const OracleDBConnectionListItemSchema = z.object({
  name: z.literal("Oracle Database"),
  app: z.literal(AppConnection.OracleDB),
  methods: z.nativeEnum(OracleDBConnectionMethod).array()
});