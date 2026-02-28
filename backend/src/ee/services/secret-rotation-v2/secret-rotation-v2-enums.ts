// Secret rotation v2 enums - enterprise feature stub

export enum SecretRotation {
  PostgresCredentials = "postgres-credentials",
  MysqlCredentials = "mysql-credentials",
  MssqlCredentials = "mssql-credentials",
  OracleDBCredentials = "oracledb-credentials",
  AwsIamUser = "aws-iam-user",
  AzureClientSecret = "azure-client-secret",
  Auth0ClientSecret = "auth0-client-secret",
  LdapPassword = "ldap-password",
  OktaClientSecret = "okta-client-secret",
  SendgridApiKey = "sendgrid-api-key"
}
