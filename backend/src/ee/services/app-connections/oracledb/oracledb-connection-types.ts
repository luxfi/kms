import { TProjectPermission } from "@app/lib/types";

export interface TOracleDBConnectionConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  serviceName?: string;
  sid?: string;
}

export interface TCreateOracleDBConnectionDTO extends TProjectPermission {
  name: string;
  description?: string;
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  serviceName?: string;
  sid?: string;
}

export interface TUpdateOracleDBConnectionDTO extends TProjectPermission {
  id: string;
  name?: string;
  description?: string;
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  password?: string;
  serviceName?: string;
  sid?: string;
}

export interface TDeleteOracleDBConnectionDTO extends TProjectPermission {
  id: string;
}

export interface TValidateOracleDBConnectionDTO extends TProjectPermission {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  serviceName?: string;
  sid?: string;
}