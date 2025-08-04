import { z } from "zod";
import { FastifyZodProvider } from "@app/server/plugins/fastify-zod";

export const registerOCIConnectionRouter = async (server: FastifyZodProvider) => {
  // Stub implementation for OCI connection router
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
        message: "OCI connection router not implemented"
      };
    }
  });
};