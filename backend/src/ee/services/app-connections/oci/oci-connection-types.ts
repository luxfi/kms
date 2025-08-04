import { TProjectPermission } from "@app/lib/types";

export interface TOCIConnectionConfig {
  tenancyOcid: string;
  userOcid: string;
  fingerprint: string;
  privateKey: string;
  region: string;
  compartmentOcid: string;
}

export interface TCreateOCIConnectionDTO extends TProjectPermission {
  name: string;
  description?: string;
  tenancyOcid: string;
  userOcid: string;
  fingerprint: string;
  privateKey: string;
  region: string;
  compartmentOcid: string;
}

export interface TUpdateOCIConnectionDTO extends TProjectPermission {
  id: string;
  name?: string;
  description?: string;
  tenancyOcid?: string;
  userOcid?: string;
  fingerprint?: string;
  privateKey?: string;
  region?: string;
  compartmentOcid?: string;
}

export interface TDeleteOCIConnectionDTO extends TProjectPermission {
  id: string;
}

export interface TValidateOCIConnectionDTO extends TProjectPermission {
  tenancyOcid: string;
  userOcid: string;
  fingerprint: string;
  privateKey: string;
  region: string;
  compartmentOcid: string;
}