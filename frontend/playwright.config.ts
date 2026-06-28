import { defineConfig, devices } from "@playwright/test";

// E2E against the embedded SPA served by the Go KMS binary (one origin: UI at
// /, API at /v1). Point KMS_URL at a running instance, or let webServer launch
// the prebuilt binary ($KMS_BIN) with an in-memory-ish temp data dir.
const baseURL = process.env.KMS_URL || "http://127.0.0.1:18080";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false, // shared KMS instance + first-run signup ordering
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // When KMS_BIN is set, Playwright boots the KMS itself (UI+API) before tests.
  webServer: process.env.KMS_BIN
    ? {
        command: process.env.KMS_BIN,
        url: `${baseURL}/v1/status`,
        timeout: 30_000,
        reuseExistingServer: !process.env.CI,
        env: {
          KMS_LISTEN: "127.0.0.1:18080",
          ZAP_PORT: "0",
          KMS_DATA_DIR: process.env.KMS_DATA_DIR || "/tmp/kms-e2e-data",
          KMS_MASTER_KEY_B64: process.env.KMS_MASTER_KEY_B64 || "ZTJlLWUyZS1lMmUtZTJlLWUyZS1lMmUtZTJlLWUyZQ==",
          KMS_WEB_AUTH_SECRET: "e2e-web-auth-secret-32-bytes-minimum!!",
        },
      }
    : undefined,
});
