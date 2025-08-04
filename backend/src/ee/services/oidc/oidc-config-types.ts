// OIDC config types - enterprise feature removed

export enum OIDCJWTSignatureAlgorithm {
  RS256 = "RS256",
  RS384 = "RS384",
  RS512 = "RS512",
  ES256 = "ES256",
  ES384 = "ES384",
  ES512 = "ES512",
  PS256 = "PS256",
  PS384 = "PS384",
  PS512 = "PS512"
}

export type TOidcConfig = {
  id: string;
  orgId: string;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint: string;
  jwksUri: string;
  clientId: string;
  clientSecret: string;
  allowedEmailDomains?: string[];
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
};

export type TOidcConfigInsert = Omit<TOidcConfig, "id" | "createdAt" | "updatedAt">;
export type TOidcConfigUpdate = Partial<TOidcConfigInsert>;