import { TSecretRotationV2Providers } from "./secret-rotation-v2-types";

export const SECRET_ROTATION_V2_PROVIDERS_MAP: Record<TSecretRotationV2Providers, string> = {
  "aws-iam-user": "AWS IAM User",
  "azure-client-secret": "Azure Client Secret",
  "mssql-credentials": "MSSQL Credentials",
  "mysql-credentials": "MySQL Credentials",
  "oracledb-credentials": "OracleDB Credentials",
  "postgres-credentials": "PostgreSQL Credentials",
  "auth0-client-secret": "Auth0 Client Secret",
  "ldap-password": "LDAP Password",
  "okta-client-secret": "Okta Client Secret",
  "sendgrid-api-key": "SendGrid API Key"
};