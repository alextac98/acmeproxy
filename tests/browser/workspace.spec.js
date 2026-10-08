const { test, expect } = require("@playwright/test");
const { goTo } = require("./navigation");

const adminToken = "browser-test-admin-token-not-for-deployment";
async function signIn(page) {
  await page.getByLabel("Admin token", { exact: true }).fill(adminToken);
  await page.getByRole("button", { name: "Open administration" }).click();
  await expect(page.locator("#workspace")).toBeVisible();
}
async function fixture(page, fresh = false) {
  const now = Math.floor(Date.now() / 1000);
  const overview = {
    providers: fresh ? [] : [{ id: "dns", name: "Production DNS", driver: "dns_cf", zone: "example.com" }],
    clients: fresh ? [] : [
      { id: "home", name: "Home service", scopes: ["home.example.com"], revoked: false },
      { id: "api", name: "API service", scopes: ["api.example.com"], revoked: false },
    ],
    drivers: [{ id: "dns_cf", name: "Cloudflare", docs: "https://github.com/acmesh-official/acme.sh/wiki/dnsapi", fields: [{ key: "CF_Token", label: "API token" }] }],
    challenges: [], audit: [], active: 0, failed: 0,
  };
  const certificates = fresh ? [] : [
    { id: "renewal", domains: ["home.example.com", "*.home.example.com"], state: "failed", phase: "DNS authorization failed", staging: false, auto_renew: true, downloadable: true, last_error: "DNS provider unavailable", expires_at: now + 86400 * 11, next_attempt: now + 3600 },
    { id: "expired", domains: ["expired.example.com"], state: "issued", phase: "Issued", staging: true, auto_renew: false, downloadable: true, expires_at: now - 3600, renew_at: now - 86400 },
  ];
  const acme = {
    settings: { mode: "disabled", base_url: "", allowed_networks: [], validation_networks: [], allowed_domains: [], staging: true, terms_agreed: false },
    accounts: [],
    orders: fresh ? [] : [{ id: "order", account_id: "account", domains: ["api.example.com"], staging: true, state: "invalid", phase: "HTTP-01 verification", error: "HTTP-01 verification failed", created_at: now }],
  };
  await page.route("**/api/admin/overview", route => route.fulfill({ json: overview }));
  await page.route("**/api/admin/certificates", route => route.fulfill({ json: certificates }));
  await page.route("**/api/admin/acme/settings", route => route.fulfill({ json: acme }));
  await page.route("**/api/admin/activity?*", route => route.fulfill({ json: { retention: 1000, stored: 0, events: [], next_before: null } }));
  return { overview, certificates, acme };
}

for (const width of [1280, 390, 320]) {
  test(`fresh setup and all three certificate methods are clear at ${width}px`, async ({ page }) => {
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.setViewportSize({ width, height: 900 });
    await fixture(page, true);
    await page.goto("/");
    await signIn(page);
    await expect(page).toHaveURL(/\/overview$/);
    await expect(page.locator("#setup-guide")).toBeVisible();
    await page.locator("#add-button").click();
    await expect(page.locator(".method-card")).toHaveCount(3);
    await expect(page.locator("#methods-panel")).toContainText("private keys");
    await expect(page.locator("#methods-panel")).toContainText("wildcard certificates are not supported");
    for (const [tab, title, validation] of [
      ["certificates", "Managed certificates", "DNS-01"],
      ["acme", "ACME endpoint", "HTTP-01"],
      ["clients", "DNS gateway", "DNS-01"],
    ]) {
      await goTo(page, tab);
      await expect(page.locator("#page-title")).toHaveText(title);
      await expect(page.locator(".page-heading p")).toHaveCount(1);
      await expect(page.locator("#page-description")).toContainText(validation);
      expect(await page.locator("#page-description").evaluate(element => getComputedStyle(element).backgroundColor)).toBe("rgba(0, 0, 0, 0)");
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
    await goTo(page, "certificates");
    await page.locator("#add-button").click();
    await expect(page.locator("#certificate-coverage")).toContainText("Connect a DNS provider");
    await expect(page.locator('#certificate-form button[type="submit"]')).toBeDisabled();
    await goTo(page, "settings");
    await expect(page.getByLabel("Keep last N events")).toBeVisible();
    await expect(page.getByLabel("Access mode")).not.toBeVisible();
    await page.screenshot({ path: `test-results/workspace-settings-${width}.png`, fullPage: true });
    expect(errors).toEqual([]);
  });
}

test("overview links renewal failures to details while keeping current validity separate", async ({ page }) => {
  const { certificates } = await fixture(page);
  await page.route("**/api/admin/certificates/renewal/retry", async route => {
    expect(route.request().method()).toBe("POST");
    certificates[0].state = "queued";
    certificates[0].phase = "Queued";
    certificates[0].last_error = null;
    await route.fulfill({ json: {} });
  });
  await page.goto("/");
  await signIn(page);
  await expect(page.locator("#overview-attention")).toContainText("current certificate is still valid");
  await page.locator("#overview-attention .attention").first().getByRole("link", { name: "Review issue" }).click();
  await expect(page).toHaveURL(/\/certificates\/renewal$/);
  await expect(page.locator("#detail-panel")).toContainText("Renewal failed");
  await expect(page.locator("#detail-panel")).toContainText("Available · valid until");
  await expect(page.getByRole("button", { name: "Download files", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Retry renewal / issuance" }).click();
  await expect(page.locator("#detail-panel")).toContainText("Queued");
  await expect(page.locator("#detail-panel")).not.toContainText("DNS provider unavailable");
  await page.locator("#detail-panel").getByRole("link", { name: "Production DNS" }).first().click();
  await expect(page).toHaveURL(/\/providers\/dns$/);
  await expect(page.locator("#detail-panel")).toContainText("Configured");
  await page.goBack();
  await expect(page).toHaveURL(/\/certificates\/renewal$/);
  await page.locator("#page-back").click();
  await expect(page.locator("#certificate-list")).toContainText("Expired");
  await expect(page.locator("#certificate-list").getByRole("button")).toHaveCount(0);
  await page.screenshot({ path: "test-results/workspace-certificates.png", fullPage: true });
});

test("gateway clients open their own scoped connection instructions", async ({ page }) => {
  await fixture(page);
  await page.goto("/clients");
  await signIn(page);
  await expect(page).toHaveURL(/\/dns-gateway$/);
  for (const [name, id, domain] of [["Home service", "home", "home.example.com"], ["API service", "api", "api.example.com"]]) {
    await page.locator("#client-list").getByRole("link", { name, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/dns-gateway/${id}$`));
    await expect(page.locator("#detail-panel")).toContainText(domain);
    await expect(page.locator("#gateway-client-command")).toHaveValue(new RegExp(`ACMEPROXY_USERNAME='${id}'`));
    await expect(page.locator("#gateway-client-command")).toHaveValue(/YOUR_SAVED_TOKEN/);
    await page.evaluate(() => refresh());
    await expect(page.locator("#page-title")).toHaveText(name);
    await page.locator("#page-back").click();
  }
});

test("bookmarked editors and order details reload, and old validation links remain valid", async ({ page }) => {
  await fixture(page);
  for (const [path, title] of [
    ["/providers/new", "Connect DNS provider"],
    ["/providers/dns/edit", "Edit DNS provider"],
    ["/certificates/new", "Request certificate"],
    ["/dns-gateway/new", "Create gateway client"],
    ["/acme-endpoint/configuration", "Configure ACME endpoint"],
    ["/activity/orders/order", "api.example.com"],
  ]) {
    expect((await page.goto(path)).status()).toBe(200);
    await signIn(page);
    await expect(page.locator("#page-title")).toHaveText(title);
    await expect(page).toHaveURL(new RegExp(path + "$"));
  }
  await expect(page.locator("#detail-panel")).toContainText("HTTP-01 verification failed");
  await page.reload();
  await signIn(page);
  await expect(page.locator("#detail-panel")).toContainText("Order IDorder");
  expect((await page.goto("/validations")).status()).toBe(200);
  await signIn(page);
  await expect(page).toHaveURL(/\/activity\/validations$/);
  await expect(page.locator('#main-navigation [data-tab="activity"]')).toHaveAttribute("aria-current", "page");
  await expect(page.locator('#activity-tabs [data-tab="challenges"]')).toHaveAttribute("aria-current", "page");
});

test("provider drafts survive refresh and a missing edit route cannot create a new provider", async ({ page }) => {
  await fixture(page);
  await page.goto("/providers/dns/edit");
  await signIn(page);
  await page.getByLabel("Connection name").fill("Unsaved DNS name");
  await page.getByLabel("CF_Token", { exact: true }).fill("unsaved-test-credential");
  await page.evaluate(() => refresh());
  await expect(page.getByLabel("Connection name")).toHaveValue("Unsaved DNS name");
  await expect(page.getByLabel("CF_Token", { exact: true })).toHaveValue("unsaved-test-credential");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByLabel("CF_Token", { exact: true })).toHaveValue("");
  await page.goto("/providers/missing/edit");
  await signIn(page);
  await expect(page.locator("#page-title")).toHaveText("Provider unavailable");
  await expect(page.getByRole("button", { name: "Save provider" })).not.toBeVisible();
});
