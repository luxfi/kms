import { z } from "zod";

// Stub implementation for secret rotation v2 union schema
export const SecretRotationV2UnionSchema = z.union([
  z.object({
    type: z.literal("aws-iam-user"),
    config: z.object({
      accessKeyId: z.string(),
      secretAccessKey: z.string()
    })
  }),
  z.object({
    type: z.literal("azure-client-secret"),
    config: z.object({
      tenantId: z.string(),
      clientId: z.string(),
      clientSecret: z.string()
    })
  }),
  z.object({
    type: z.literal("postgres-credentials"),
    config: z.object({
      host: z.string(),
      port: z.number(),
      database: z.string(),
      username: z.string(),
      password: z.string()
    })
  }),
  z.object({
    type: z.literal("mysql-credentials"),
    config: z.object({
      host: z.string(),
      port: z.number(),
      database: z.string(),
      username: z.string(),
      password: z.string()
    })
  }),
  z.object({
    type: z.literal("mssql-credentials"),
    config: z.object({
      host: z.string(),
      port: z.number(),
      database: z.string(),
      username: z.string(),
      password: z.string()
    })
  }),
  z.object({
    type: z.literal("oracledb-credentials"),
    config: z.object({
      host: z.string(),
      port: z.number(),
      database: z.string(),
      username: z.string(),
      password: z.string()
    })
  }),
  z.object({
    type: z.literal("auth0-client-secret"),
    config: z.object({
      domain: z.string(),
      clientId: z.string(),
      clientSecret: z.string()
    })
  }),
  z.object({
    type: z.literal("ldap-password"),
    config: z.object({
      url: z.string(),
      bindDN: z.string(),
      bindPassword: z.string()
    })
  }),
  z.object({
    type: z.literal("okta-client-secret"),
    config: z.object({
      domain: z.string(),
      clientId: z.string(),
      clientSecret: z.string()
    })
  }),
  z.object({
    type: z.literal("sendgrid-api-key"),
    config: z.object({
      apiKey: z.string()
    })
  })
]);

export const SecretRotationV2ProvidersSchema = z.enum([
  "aws-iam-user",
  "azure-client-secret",
  "mssql-credentials",
  "mysql-credentials",
  "oracledb-credentials",
  "postgres-credentials",
  "auth0-client-secret",
  "ldap-password",
  "okta-client-secret",
  "sendgrid-api-key"
]);
// Alias for compatibility
export const SecretRotationV2Schema = SecretRotationV2UnionSchema;
