// OpenTelemetry removed - using simple logging for metrics
import fp from "fastify-plugin";

import { logger } from "@app/lib/logger";

export const apiMetrics = fp(async (fastify) => {
  fastify.addHook("onResponse", async (request, reply) => {
    const { method } = request;
    const route = request.routerPath;
    const { statusCode } = reply;

    // Log latency for observability (can be scraped by log aggregators)
    logger.debug({
      msg: "api_latency",
      route,
      method,
      statusCode,
      latencyMs: reply.elapsedTime
    });
  });
});
