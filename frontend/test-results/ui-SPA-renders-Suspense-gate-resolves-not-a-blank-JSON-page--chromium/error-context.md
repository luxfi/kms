# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: ui.spec.ts >> SPA renders (Suspense gate resolves, not a blank/JSON page)
- Location: e2e/ui.spec.ts:10:1

# Error details

```
Error: expect(received).toContain(expected) // indexOf

Expected substring: "text/html"
Received string:    "application/json"
```

# Page snapshot

```yaml
- generic [ref=e2]: "{\"service\":\"kms\",\"status\":\"ok\"}"
```

# Test source

```ts
  1  | import { test, expect } from "@playwright/test";
  2  | 
  3  | // Browser e2e: the embedded SPA renders and drives the real auth flow against
  4  | // the Go backend. Selectors target the Infisical-derived login (multi-step:
  5  | // email → password) + first-run admin signup. Robust locators (role/placeholder)
  6  | // so minor DOM churn doesn't break them; refined against the live instance.
  7  | 
  8  | const ADMIN = { email: "ui-admin@lux.network", password: "Ui-Secret-pw1!" };
  9  | 
  10 | test("SPA renders (Suspense gate resolves, not a blank/JSON page)", async ({ page }) => {
  11 |   const resp = await page.goto("/");
  12 |   // The Go server serves the SPA HTML at / (not API JSON).
> 13 |   expect(resp?.headers()["content-type"] || "").toContain("text/html");
     |                                                 ^ Error: expect(received).toContain(expected) // indexOf
  14 |   await expect(page).toHaveTitle(/KMS/i, { timeout: 15_000 });
  15 |   // app mounted (root div has content)
  16 |   await expect(page.locator("#root")).not.toBeEmpty({ timeout: 15_000 });
  17 | });
  18 | 
  19 | test("auth surface is reachable (login or first-run signup)", async ({ page }) => {
  20 |   await page.goto("/");
  21 |   // Either the login email step or the admin signup form must appear. The
  22 |   // signup form inputs are name-keyed (no placeholder); login uses a placeholder
  23 |   // — match both.
  24 |   const email = page.locator('input[name="email"], input[type="email"]').first();
  25 |   await expect(email).toBeVisible({ timeout: 15_000 });
  26 | });
  27 | 
  28 | // Full UI flow against a FRESH instance: first-run admin signup → authenticated.
  29 | // Enable with E2E_UI_FLOW=1 (the instance must have no users yet, so /admin/signup
  30 | // is shown). The signup form is name-keyed: firstName/lastName/email/password/
  31 | // confirmPassword + Continue.
  32 | test.describe("@flow first-run admin signup → authenticated", () => {
  33 |   test.skip(!process.env.E2E_UI_FLOW, "set E2E_UI_FLOW=1 against a fresh (no-user) instance");
  34 | 
  35 |   test("admin signs up and leaves the signup screen authenticated", async ({ page, request }) => {
  36 |     const cfg = await (await request.get("/v1/admin/config")).json();
  37 |     test.skip(cfg.config.initialized, "instance already has a user — first-run flow needs a fresh instance");
  38 |     await page.goto("/");
  39 |     await expect(page).toHaveURL(/\/admin\/signup/i, { timeout: 15_000 });
  40 | 
  41 |     await page.fill('input[name="firstName"]', "E2E");
  42 |     await page.fill('input[name="lastName"]', "Admin");
  43 |     await page.fill('input[name="email"]', ADMIN.email);
  44 |     await page.fill('input[name="password"]', ADMIN.password);
  45 |     await page.fill('input[name="confirmPassword"]', ADMIN.password);
  46 |     await page.getByRole("button", { name: /continue/i }).click();
  47 | 
  48 |     // Signup succeeded → SPA mints a session and navigates off /admin/signup.
  49 |     await expect(page).not.toHaveURL(/\/admin\/signup/i, { timeout: 25_000 });
  50 |     // A session token is now held (in-memory, key kms__auth-token) — prove by
  51 |     // hitting an authed API from the page context succeeds.
  52 |     const ok = await page.evaluate(async () => (await fetch("/v1/admin/config")).ok);
  53 |     expect(ok).toBeTruthy();
  54 |   });
  55 | });
  56 | 
```