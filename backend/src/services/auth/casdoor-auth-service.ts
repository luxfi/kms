import axios from "axios";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { getConfig } from "@app/lib/config/env";
import { BadRequestError, UnauthorizedError } from "@app/lib/errors";
import { TUserDALFactory } from "../user/user-dal";
import { TOrgDALFactory } from "../org/org-dal";
import { TOrgMembershipDALFactory } from "../org-membership/org-membership-dal";
import { OrgMembershipRole, OrgMembershipStatus } from "@app/db/schemas";
import { TAuthTokenServiceFactory } from "../auth-token/auth-token-service";
import { AuthTokenType } from "./auth-type";
import { TAuthDALFactory } from "./auth-dal";

const CasdoorConfigSchema = z.object({
  CASDOOR_ENDPOINT: z.string().default("http://localhost:8000"),
  CASDOOR_CLIENT_ID: z.string().default("lux-kms-client"),
  CASDOOR_CLIENT_SECRET: z.string().default("lux-kms-secret-change-in-production"),
  CASDOOR_ORGANIZATION: z.string().default("built-in"),
  CASDOOR_APPLICATION: z.string().default("lux-kms")
});

type TCasdoorAuthServiceFactoryDep = {
  userDAL: TUserDALFactory;
  orgDAL: TOrgDALFactory;
  orgMembershipDAL: TOrgMembershipDALFactory;
  tokenService: TAuthTokenServiceFactory;
  authDAL: TAuthDALFactory;
};

export type TCasdoorAuthServiceFactory = ReturnType<typeof casdoorAuthServiceFactory>;

export const casdoorAuthServiceFactory = ({
  userDAL,
  orgDAL,
  orgMembershipDAL,
  tokenService,
  authDAL
}: TCasdoorAuthServiceFactoryDep) => {
  const config = CasdoorConfigSchema.parse(getConfig());
  
  const getOAuthLoginUrl = (redirectUri: string) => {
    const params = new URLSearchParams({
      client_id: config.CASDOOR_CLIENT_ID,
      response_type: "code",
      redirect_uri: redirectUri,
      scope: "read",
      state: "kms"
    });
    
    return `${config.CASDOOR_ENDPOINT}/login/oauth/authorize?${params.toString()}`;
  };
  
  const exchangeCodeForToken = async (code: string, redirectUri: string) => {
    try {
      const response = await axios.post(`${config.CASDOOR_ENDPOINT}/api/login/oauth/access_token`, {
        grant_type: "authorization_code",
        client_id: config.CASDOOR_CLIENT_ID,
        client_secret: config.CASDOOR_CLIENT_SECRET,
        code,
        redirect_uri: redirectUri
      });
      
      return response.data;
    } catch (error) {
      throw new BadRequestError({ message: "Failed to exchange code for token" });
    }
  };
  
  const getCasdoorUser = async (accessToken: string) => {
    try {
      const response = await axios.get(`${config.CASDOOR_ENDPOINT}/api/userinfo`, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      });
      
      return response.data;
    } catch (error) {
      throw new UnauthorizedError({ message: "Failed to get user info from Casdoor" });
    }
  };
  
  const loginWithCasdoor = async ({
    code,
    redirectUri,
    ip,
    userAgent
  }: {
    code: string;
    redirectUri: string;
    ip: string;
    userAgent: string;
  }) => {
    // Exchange code for token
    const tokenData = await exchangeCodeForToken(code, redirectUri);
    
    // Get user info from Casdoor
    const casdoorUser = await getCasdoorUser(tokenData.access_token);
    
    // Check if user exists in our database
    let user = await userDAL.findOne({ email: casdoorUser.email });
    
    if (!user) {
      // Create new user
      const username = casdoorUser.name || casdoorUser.email.split("@")[0];
      
      // Create default organization for new user
      const org = await orgDAL.create({
        name: `${username}-org`,
        slug: `${username}-org`.toLowerCase()
      });
      
      // Create user
      user = await userDAL.create({
        email: casdoorUser.email,
        username,
        firstName: casdoorUser.displayName?.split(" ")[0] || username,
        lastName: casdoorUser.displayName?.split(" ").slice(1).join(" ") || "",
        isEmailVerified: true, // Trust Casdoor's verification
        authMethods: []
      });
      
      // Create org membership
      await orgMembershipDAL.create({
        userId: user.id,
        orgId: org.id,
        role: OrgMembershipRole.Admin,
        status: OrgMembershipStatus.Accepted
      });
    }
    
    // Generate access and refresh tokens
    const accessToken = await tokenService.createTokenPair({
      type: AuthTokenType.ACCESS,
      userId: user.id,
      ip,
      userAgent
    });
    
    const refreshToken = await tokenService.createTokenPair({
      type: AuthTokenType.REFRESH,
      userId: user.id,
      ip,
      userAgent
    });
    
    return {
      user,
      accessToken,
      refreshToken,
      casdoorToken: tokenData.access_token
    };
  };
  
  const logoutFromCasdoor = async (userId: string) => {
    // Revoke all tokens for the user
    await tokenService.revokeAllTokens(userId);
    
    // Optionally logout from Casdoor
    // This would require additional implementation based on Casdoor's logout API
    
    return true;
  };
  
  return {
    getOAuthLoginUrl,
    loginWithCasdoor,
    logoutFromCasdoor,
    getCasdoorUser
  };
};