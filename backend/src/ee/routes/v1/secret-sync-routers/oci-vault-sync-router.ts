import { z } from "zod";
import { FastifyZodProvider } from "@app/server/plugins/fastify-zod";

export const registerOCIVaultSyncRouter = async (server: FastifyZodProvider) => {
  // Stub implementation for OCI Vault sync router
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
        message: "OCI Vault sync router not implemented"
      };
    }
  });
};