// Telemetry instrumentation removed - this is now a no-op stub
// OpenTelemetry and dd-trace dependencies have been removed for simplicity

import dotenv from "dotenv";

dotenv.config();

// No-op: telemetry is disabled in this build
const setupTelemetry = () => {
  // Telemetry disabled
};

void setupTelemetry();
