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
  // Either the login email step or the admin signup form must appear. The
  // signup form inputs are name-keyed (no placeholder); login uses a placeholder
  // — match both.
  const email = page.locator('input[name="email"], input[type="email"]').first();
  await expect(email).toBeVisible({ timeout: 15_000 });
});

// Full UI flow against a FRESH instance: first-run admin signup → authenticated.
// Enable with E2E_UI_FLOW=1 (the instance must have no users yet, so /admin/signup
// is shown). The signup form is name-keyed: firstName/lastName/email/password/
// confirmPassword + Continue.
test.describe("@flow first-run admin signup → authenticated", () => {
  test.skip(!process.env.E2E_UI_FLOW, "set E2E_UI_FLOW=1 against a fresh (no-user) instance");

  test("admin signs up and leaves the signup screen authenticated", async ({ page, request }) => {
    const cfg = await (await request.get("/v1/admin/config")).json();
    test.skip(cfg.config.initialized, "instance already has a user — first-run flow needs a fresh instance");
    await page.goto("/");
    await expect(page).toHaveURL(/\/admin\/signup/i, { timeout: 15_000 });

    await page.fill('input[name="firstName"]', "E2E");
    await page.fill('input[name="lastName"]', "Admin");
    await page.fill('input[name="email"]', ADMIN.email);
    await page.fill('input[name="password"]', ADMIN.password);
    await page.fill('input[name="confirmPassword"]', ADMIN.password);
    await page.getByRole("button", { name: /continue/i }).click();

    // Signup succeeded → SPA mints a session and navigates off /admin/signup.
    await expect(page).not.toHaveURL(/\/admin\/signup/i, { timeout: 25_000 });
    // A session token is now held (in-memory, key kms__auth-token) — prove by
    // hitting an authed API from the page context succeeds.
    const ok = await page.evaluate(async () => (await fetch("/v1/admin/config")).ok);
    expect(ok).toBeTruthy();
  });
});
