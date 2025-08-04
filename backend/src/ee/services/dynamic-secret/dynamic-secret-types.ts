export enum DatabaseProviderClients {
  Postgres = "postgres",
  MySQL = "mysql",
  MsSQL = "mssql",
  OracleDB = "oracledb",
  MongoDB = "mongodb",
  Redis = "redis",
  Elasticsearch = "elasticsearch",
  Cassandra = "cassandra"
}

export enum DynamicSecretProviders {
  AWS_IAM = "aws-iam",
  AWS_STS = "aws-sts",
  POSTGRES = "postgres",
  MYSQL = "mysql",
  MSSQL = "mssql",
  ORACLEDB = "oracledb",
  MONGODB = "mongodb",
  REDIS = "redis",
  ELASTICSEARCH = "elasticsearch",
  CASSANDRA = "cassandra",
  AZURE_ENTRA_ID = "azure-entra-id",
  GCP_IAM = "gcp-iam",
  KUBERNETES = "kubernetes",
  GITHUB = "github",
  LDAP = "ldap",
  TOTP = "totp"
}

export interface TDynamicSecretConfig {
  id: string;
  name: string;
  type: DynamicSecretProviders;
  projectId: string;
  secretPath: string;
  defaultTTL: string;
  maxTTL?: string;
  config: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface TDynamicSecretLease {
  id: string;
  dynamicSecretId: string;
  expiresAt: Date;
  metadata: Record<string, any>;
  status: "active" | "revoked" | "expired";
  createdAt: Date;
  updatedAt: Date;
}