import { z } from "zod";
import { FastifyZodProvider } from "@app/server/plugins/fastify-zod";

export const registerOracleDBConnectionRouter = async (server: FastifyZodProvider) => {
  // Stub implementation for OracleDB connection router
  server.route({
    method: "GET",
    url: "/",
    schema: {
      response: {
        200: z.object({
          message: z.string()
        })
      }
    },
    handler: async () => {
      return {
        message: "OracleDB connection router not implemented"
      };
    }
  });
};