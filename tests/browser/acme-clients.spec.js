const { test, expect } = require("@playwright/test");

const adminToken = "browser-test-admin-token-not-for-deployment";
async function signIn(page) {
  await page.getByLabel("Admin token", { exact: true }).fill(adminToken);
  await page.getByRole("button", { name: "Open administration" }).click();
  await expect(page.locator("#workspace")).toBeVisible();
}
async function fixture(page, empty = false) {
  const now = Math.floor(Date.now() / 1000);
  const acme = {
    settings: { mode: "http01", base_url: "https://acme.example.com", allowed_networks: [], validation_networks: [], allowed_domains: [], staging: false, terms_agreed: true },
    accounts: empty ? [] : [
      { id: "main", contact: ["mailto:tls-admin@example.com"], status: "valid", thumbprint: "example-key-fingerprint", created_at: now - 100 * 86400 },
      { id: "f7b5169d-024a-4978-8c81-3608bcbdcb20", contact: [], status: "valid", thumbprint: "second-key-fingerprint", created_at: now - 86400 },
      { id: "retired", contact: ["mailto:retired@example.com"], status: "deactivated", thumbprint: "retired-key-fingerprint", created_at: now - 86400 },
    ],
    orders: empty ? [] : [
      { id: "valid", account_id: "main", domains: ["home.example.com"], staging: false, state: "valid", phase: "Issued", error: null, created_at: now, certificate_expires_at: now + 90 * 86400, revoked: false },
      { id: "expired", account_id: "main", domains: ["legacy.example.com"], staging: false, state: "valid", phase: "Issued", error: null, created_at: now - 92 * 86400, certificate_expires_at: now - 2 * 86400, revoked: false },
      { id: "failed", account_id: "main", domains: ["api.example.com"], staging: false, state: "invalid", phase: "HTTP-01 verification", error: "HTTP-01 validation failed: challenge URL returned 404", created_at: now, certificate_expires_at: null, revoked: false },
      { id: "revoked", account_id: "main", domains: ["revoked.example.com"], staging: true, state: "valid", phase: "Issued", error: null, created_at: now, certificate_expires_at: now + 90 * 86400, revoked: true },
      { id: "unknown", account_id: "main", domains: ["unknown.example.com"], staging: false, state: "valid", phase: "Issued", error: null, created_at: now, certificate_expires_at: null, revoked: false },
      { id: "pending", account_id: "main", domains: ["pending.example.com"], staging: false, state: "pending", phase: "Awaiting HTTP-01 verification", error: null, created_at: now, certificate_expires_at: null, revoked: false },
      { id: "other", account_id: "f7b5169d-024a-4978-8c81-3608bcbdcb20", domains: ["other.example.com"], staging: true, state: "valid", phase: "Issued", error: null, created_at: now, certificate_expires_at: now + 86400, revoked: false },
    ],
  };
  await page.route("**/api/admin/overview", route => route.fulfill({ json: { providers: [], clients: [], drivers: [], challenges: [], audit: [], active: 0, failed: 0 } }));
  await page.route("**/api/admin/acme/settings", route => route.fulfill({ json: acme }));
  return acme;
}

for (const width of [1280, 390, 320]) {
  test(`registered clients show accurate certificate validity and scoped requests at ${width}px`, async ({ page }) => {
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.setViewportSize({ width, height: 900 });
    const acme = await fixture(page);
    expect((await page.goto("/acme-endpoint/clients")).status()).toBe(200);
    await signIn(page);
    await expect(page.locator("#page-title")).toHaveText("ACME endpoint");
    await expect(page.getByRole("tab", { name: "Clients", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(page.locator("#acme-endpoint-status")).toHaveText("Enabled");
    await expect(page.locator("#add-button")).toBeHidden();
    await expect(page.getByText("Configure endpoint", { exact: true })).toHaveCount(0);
    const client = page.locator(".acme-client").filter({ has: page.locator(".acme-client-identity", { hasText: "tls-admin@example.com" }) });
    await expect(client.locator(".acme-client-status")).toHaveText("Registered");
    await expect(client).toContainText("6 recent requests");
    const toggle = client.locator("#acme-client-toggle-main");
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    const requests = page.locator("#acme-client-requests-main");
    const requestFor = domain => requests.locator(".acme-client-request").filter({ has: page.getByRole("link", { name: domain, exact: true }) });
    await expect(requestFor("home.example.com").locator(".status")).toHaveText("Valid");
    await expect(requestFor("home.example.com")).toContainText("90 days remaining");
    await expect(requestFor("home.example.com").locator("time")).toHaveAttribute("datetime", new Date(acme.orders[0].certificate_expires_at * 1000).toISOString());
    await expect(requestFor("legacy.example.com").locator(".status")).toHaveText("Expired");
    await expect(requestFor("legacy.example.com")).toContainText("2 days ago");
    await expect(requestFor("api.example.com")).toContainText("No certificate issued");
    await expect(requestFor("api.example.com")).toContainText("challenge URL returned 404");
    await expect(requestFor("revoked.example.com").locator(".status")).toHaveText("Revoked");
    await expect(requestFor("unknown.example.com")).toContainText("Expiry unavailable");
    await expect(requestFor("pending.example.com")).toContainText("Certificate not issued yet");
    await expect(requests).not.toContainText("other.example.com");
    await expect(client.locator(".acme-client-status")).toHaveText("Registered");
    await client.getByText("Registration details", { exact: true }).click();
    await expect(client).toContainText("example-key-fingerprint");
    await toggle.focus();
    await page.evaluate(() => loadAcmeSettings());
    await expect(client.getByRole("button", { name: "Hide requests" })).toBeFocused();
    await expect(client.locator("details")).toHaveAttribute("open", "");
    await expect(requests).toBeVisible();
    await expect(page.locator("#acme-client-list")).toContainText("Client f7b5169d");
    await expect(page.locator(".acme-client-status").filter({ hasText: "Deactivated" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: `test-results/acme-clients-${width}.png`, fullPage: true });
    await requestFor("legacy.example.com").getByRole("link").click();
    await expect(page).toHaveURL(/\/activity\/orders\/expired$/);
    await expect(page.locator("#detail-panel")).toContainText("Expired");
    await page.goBack();
    await expect(page).toHaveURL(/\/acme-endpoint\/clients$/);
    await expect(requests).toBeVisible();
    expect(errors).toEqual([]);
  });
}

test("endpoint tabs preserve drafts, saved status, browser history, and reload routes", async ({ page }) => {
  const acme = await fixture(page);
  await page.goto("/acme-endpoint");
  await signIn(page);
  await expect(page.getByRole("tab", { name: "Connection", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await page.getByLabel("Access mode").selectOption("disabled");
  await page.getByLabel("Server URL seen by clients").fill("https://unsaved.example.com");
  await expect(page.locator("#acme-endpoint-status")).toHaveText("Enabled");
  await page.getByRole("tab", { name: "Settings", exact: true }).press("ArrowRight");
  await expect(page).toHaveURL(/\/acme-endpoint\/clients$/);
  await expect(page.getByRole("tab", { name: "Clients", exact: true })).toBeFocused();
  await page.goBack();
  await expect(page).toHaveURL(/\/acme-endpoint\/settings$/);
  await expect(page.getByLabel("Access mode")).toHaveValue("disabled");
  await expect(page.getByLabel("Server URL seen by clients")).toHaveValue("https://unsaved.example.com");
  await page.evaluate(() => refresh());
  await expect(page.getByLabel("Server URL seen by clients")).toHaveValue("https://unsaved.example.com");
  await page.reload();
  await signIn(page);
  await expect(page.getByRole("tab", { name: "Settings", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByLabel("Server URL seen by clients")).toHaveValue(acme.settings.base_url);
  await page.getByRole("tab", { name: "Settings", exact: true }).press("End");
  await expect(page).toHaveURL(/\/acme-endpoint\/clients$/);
  await page.reload();
  await signIn(page);
  await expect(page.getByRole("tab", { name: "Clients", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("button", { name: "Save changes" })).toBeHidden();
});

test("an empty clients tab directs registration through the connection tab", async ({ page }) => {
  await fixture(page, true);
  await page.goto("/acme-endpoint/clients");
  await signIn(page);
  await expect(page.locator("#acme-client-list")).toContainText("No registered clients yet");
  await expect(page.locator("#acme-client-list")).toContainText("Connection tab");
  await expect(page.locator("#acme-client-list button")).toHaveCount(0);
});
