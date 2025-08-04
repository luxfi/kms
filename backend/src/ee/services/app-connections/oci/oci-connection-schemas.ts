import { z } from "zod";
import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import {
  BaseAppConnectionSchema,
  GenericCreateAppConnectionFieldsSchema,
  GenericUpdateAppConnectionFieldsSchema
} from "@app/services/app-connection/app-connection-schemas";

export enum OCIConnectionMethod {
  UserAPIKey = "user-api-key"
}

export const OCIConnectionUserAPIKeyCredentialsSchema = z.object({
  tenancyOcid: z.string().trim().min(1, "Tenancy OCID required"),
  userOcid: z.string().trim().min(1, "User OCID required"),
  fingerprint: z.string().trim().min(1, "Fingerprint required"),
  privateKey: z.string().trim().min(1, "Private Key required"),
  region: z.string().trim().min(1, "Region required"),
  compartmentOcid: z.string().trim().min(1, "Compartment OCID required")
});

const BaseOCIConnectionSchema = BaseAppConnectionSchema.extend({ app: z.literal(AppConnection.OCI) });

export const OCIConnectionSchema = z.intersection(
  BaseOCIConnectionSchema,
  z.discriminatedUnion("method", [
    z.object({
      method: z.literal(OCIConnectionMethod.UserAPIKey),
      credentials: OCIConnectionUserAPIKeyCredentialsSchema
    })
  ])
);

// Convert discriminatedUnion to regular union for compatibility
export const SanitizedOCIConnectionSchema = z.union([
  BaseOCIConnectionSchema.extend({
    method: z.literal(OCIConnectionMethod.UserAPIKey),
    credentials: OCIConnectionUserAPIKeyCredentialsSchema.pick({
      tenancyOcid: true,
      userOcid: true,
      fingerprint: true,
      region: true,
      compartmentOcid: true
    })
  })
]);

export const ValidateOCIConnectionCredentialsSchema = z.discriminatedUnion("method", [
  z.object({
    method: z.literal(OCIConnectionMethod.UserAPIKey),
    credentials: OCIConnectionUserAPIKeyCredentialsSchema
  })
]);

export const CreateOCIConnectionSchema = ValidateOCIConnectionCredentialsSchema.and(
  GenericCreateAppConnectionFieldsSchema(AppConnection.OCI)
);

export const UpdateOCIConnectionSchema = z
  .object({
    credentials: OCIConnectionUserAPIKeyCredentialsSchema.optional()
  })
  .and(GenericUpdateAppConnectionFieldsSchema(AppConnection.OCI));

export const OCIConnectionListItemSchema = z.object({
  name: z.literal("Oracle Cloud Infrastructure"),
  app: z.literal(AppConnection.OCI),
  methods: z.nativeEnum(OCIConnectionMethod).array()
});