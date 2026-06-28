import { test, expect, APIRequestContext } from "@playwright/test";

// API-level e2e against the running KMS (same origin as the SPA). Mirrors the
// SPA's own request flow: bootstrap → first-admin signup → login → select-org →
// whoami → project → environment → folder → secret round-trip. Deterministic,
// no browser flakiness — the contract the UI depends on.

const ADMIN = { email: "e2e-admin@lux.network", password: "E2e-Secret-pw!", organizationName: "E2E" };

async function bootSession(api: APIRequestContext): Promise<{ token: string }> {
  // first-run signup is only valid once; tolerate "already initialized" on reruns
  const cfg = await (await api.get("/v1/admin/config")).json();
  if (!cfg.config.initialized) {
    const s = await api.post("/v1/admin/signup", { data: ADMIN });
    expect(s.ok()).toBeTruthy();
  }
  const login = await api.post("/v1/auth/login", { data: { email: ADMIN.email, password: ADMIN.password } });
  expect(login.ok()).toBeTruthy();
  const { accessToken } = await login.json();
  const sel = await api.post("/v1/auth/select-organization", {
    headers: { authorization: `Bearer ${accessToken}` },
    data: {},
  });
  expect(sel.ok()).toBeTruthy();
  return { token: (await sel.json()).token };
}

test("bootstrap endpoints render the SPA gate", async ({ request }) => {
  const status = await request.get("/v1/status");
  expect(status.ok()).toBeTruthy();
  expect((await status.json()).message).toBe("ok");

  const config = await request.get("/v1/admin/config");
  expect(config.ok()).toBeTruthy();
  expect((await config.json()).config).toHaveProperty("initialized");
});

test("auth: signup → login → select-org → whoami", async ({ request }) => {
  const { token } = await bootSession(request);
  const me = await request.get("/v1/user", { headers: { authorization: `Bearer ${token}` } });
  expect(me.ok()).toBeTruthy();
  expect((await me.json()).user.email).toBe(ADMIN.email);

  // unauthenticated is rejected
  expect((await request.get("/v1/user")).status()).toBe(401);

  // bad password rejected
  const bad = await request.post("/v1/auth/login", { data: { email: ADMIN.email, password: "wrong" } });
  expect(bad.status()).toBe(401);
});

test("secrets round-trip: project → secret → list → read → delete", async ({ request }) => {
  const { token } = await bootSession(request);
  const auth = { authorization: `Bearer ${token}` };

  const proj = await request.post("/v1/projects", { headers: auth, data: { projectName: "E2E App" } });
  expect(proj.ok()).toBeTruthy();
  const project = (await proj.json()).project;
  expect(project.environments.length).toBeGreaterThanOrEqual(3); // default dev/staging/prod

  // create
  const created = await request.post("/v4/secrets/API_KEY", {
    headers: auth,
    data: { projectId: project.id, environment: "dev", secretPath: "/", secretValue: "sk-e2e-123" },
  });
  expect(created.ok()).toBeTruthy();

  // list returns the value
  const list = await request.get(
    `/v1/secrets?projectId=${project.id}&environment=dev&secretPath=${encodeURIComponent("/")}`,
    { headers: auth }
  );
  expect(list.ok()).toBeTruthy();
  const secrets = (await list.json()).secrets;
  const apiKey = secrets.find((s: any) => s.secretKey === "API_KEY");
  expect(apiKey?.secretValue).toBe("sk-e2e-123");

  // env isolation
  const prod = await request.get(
    `/v1/secrets?projectId=${project.id}&environment=prod&secretPath=${encodeURIComponent("/")}`,
    { headers: auth }
  );
  expect((await prod.json()).secrets.length).toBe(0);

  // delete
  await request.delete("/v4/secrets/API_KEY", {
    headers: auth,
    data: { projectId: project.id, environment: "dev", secretPath: "/" },
  });
  const after = await request.get(
    `/v1/secrets?projectId=${project.id}&environment=dev&secretPath=${encodeURIComponent("/")}`,
    { headers: auth }
  );
  expect((await after.json()).secrets.find((s: any) => s.secretKey === "API_KEY")).toBeUndefined();
});
