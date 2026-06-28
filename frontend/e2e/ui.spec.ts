import { test, expect } from "@playwright/test";

// Browser e2e: the embedded SPA renders and drives the real auth flow against
// the Go backend. Selectors target the Infisical-derived login (multi-step:
// email → password) + first-run admin signup. Robust locators (role/placeholder)
// so minor DOM churn doesn't break them; refined against the live instance.

const ADMIN = { email: "ui-admin@lux.network", password: "Ui-Secret-pw1!" };

test("SPA renders (Suspense gate resolves, not a blank/JSON page)", async ({ page }) => {
  const resp = await page.goto("/");
  // The Go server serves the SPA HTML at / (not API JSON).
  expect(resp?.headers()["content-type"] || "").toContain("text/html");
  await expect(page).toHaveTitle(/KMS/i, { timeout: 15_000 });
  // app mounted (root div has content)
  await expect(page.locator("#root")).not.toBeEmpty({ timeout: 15_000 });
});

test("auth surface is reachable (login or first-run signup)", async ({ page }) => {
  await page.goto("/");
  // Either the login email step or the admin signup form must appear.
  const email = page.getByPlaceholder(/email/i).first();
  await expect(email).toBeVisible({ timeout: 15_000 });
});

// Full UI flow — exercised when running against a fresh instance. Skipped by
// default (depends on first-run/seed state); enable with E2E_UI_FLOW=1 once the
// instance is freshly provisioned.
test.describe("@flow full UI login → dashboard", () => {
  test.skip(!process.env.E2E_UI_FLOW, "set E2E_UI_FLOW=1 against a fresh instance");

  test("admin can sign in and reach the org dashboard", async ({ page }) => {
    await page.goto("/");
    // email step
    await page.getByPlaceholder(/email/i).first().fill(ADMIN.email);
    await page.getByRole("button", { name: /continue|login|next/i }).first().click();
    // password step
    await page.getByPlaceholder(/password/i).first().fill(ADMIN.password);
    await page.getByRole("button", { name: /login|continue|sign in/i }).first().click();
    // landed somewhere authenticated (org overview / projects)
    await expect(page).toHaveURL(/\/(org|organization|projects|overview)/i, { timeout: 20_000 });
  });
});
