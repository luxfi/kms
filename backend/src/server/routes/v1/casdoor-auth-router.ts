import { z } from "zod";
import { FastifyZodProvider } from "@app/server/types";
import { getConfig } from "@app/lib/config/env";
import { casdoorAuthServiceFactory } from "@app/services/auth/casdoor-auth-service";
import { verifyAuth } from "@app/server/plugins/auth/verify-auth";
import { AuthMode } from "@app/services/auth/auth-type";

export const registerCasdoorAuthRouter = async (server: FastifyZodProvider) => {
  // OAuth login redirect
  server.route({
    method: "GET",
    url: "/login",
    schema: {
      querystring: z.object({
        redirect_uri: z.string().optional().default("/dashboard")
      }),
      response: {
        302: z.any()
      }
    },
    handler: async (req, res) => {
      const { redirect_uri } = req.query;
      const appCfg = getConfig();
      const callbackUrl = `${appCfg.SITE_URL}/api/v1/auth/casdoor/callback`;
      const loginUrl = req.services.casdoorAuth.getOAuthLoginUrl(callbackUrl);
      
      // Store redirect URI in session/cookie for use after callback
      res.setCookie("redirect_uri", redirect_uri, {
        httpOnly: true,
        secure: appCfg.HTTPS_ENABLED,
        sameSite: "lax",
        maxAge: 600 // 10 minutes
      });
      
      return res.redirect(302, loginUrl);
    }
  });
  
  // OAuth callback
  server.route({
    method: "GET",
    url: "/callback",
    schema: {
      querystring: z.object({
        code: z.string(),
        state: z.string().optional()
      }),
      response: {
        302: z.any()
      }
    },
    handler: async (req, res) => {
      const { code } = req.query;
      const appCfg = getConfig();
      const callbackUrl = `${appCfg.SITE_URL}/api/v1/auth/casdoor/callback`;
      
      const { user, accessToken, refreshToken } = await req.services.casdoorAuth.loginWithCasdoor({
        code,
        redirectUri: callbackUrl,
        ip: req.ip,
        userAgent: req.headers["user-agent"] || ""
      });
      
      // Set cookies for tokens
      res.setCookie("jid", refreshToken, {
        httpOnly: true,
        secure: appCfg.HTTPS_ENABLED,
        sameSite: "strict",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });
      
      res.setCookie("aid", accessToken, {
        httpOnly: true,
        secure: appCfg.HTTPS_ENABLED,
        sameSite: "strict",
        path: "/",
        maxAge: 15 * 60 * 1000 // 15 minutes
      });
      
      // Get redirect URI from cookie
      const redirectUri = req.cookies.redirect_uri || "/dashboard";
      res.clearCookie("redirect_uri");
      
      return res.redirect(302, redirectUri);
    }
  });
  
  // Logout
  server.route({
    method: "POST",
    url: "/logout",
    schema: {
      response: {
        200: z.object({
          message: z.string()
        })
      }
    },
    preHandler: verifyAuth([AuthMode.JWT]),
    handler: async (req, res) => {
      const { id: userId } = req.permission.user;
      
      await req.services.casdoorAuth.logoutFromCasdoor(userId);
      
      res.clearCookie("jid");
      res.clearCookie("aid");
      
      return {
        message: "Logged out successfully"
      };
    }
  });
  
  // Get current user info
  server.route({
    method: "GET",
    url: "/me",
    schema: {
      response: {
        200: z.object({
          user: z.any()
        })
      }
    },
    preHandler: verifyAuth([AuthMode.JWT]),
    handler: async (req) => {
      const { user } = req.permission;
      
      return {
        user
      };
    }
  });
};