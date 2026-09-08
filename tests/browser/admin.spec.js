const { test, expect } = require("@playwright/test");

test("admin can configure DNS, create and revoke a client, and use the mobile layout", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page.getByLabel("Admin token", { exact: true }).fill("incorrect");
  await page.getByRole("button", { name: "Open administration" }).click();
  await expect(page.getByRole("alert").first()).toContainText("invalid");
  await page
    .getByLabel("Admin token", { exact: true })
    .fill("browser-test-admin-token-not-for-deployment");
  await page.getByRole("button", { name: "Open administration" }).click();
  await expect(
    page.getByRole("heading", { name: "DNS providers", exact: true }),
  ).toBeVisible();
  await page.locator("#add-button").click();
  await page.getByLabel("Connection name").fill("Lab DNS");
  await page.getByLabel("DNS provider", { exact: true }).selectOption("dns_cf");
  await page.getByLabel("Zone", { exact: true }).fill("example.com");
  await page.getByLabel("CF_Token", { exact: true }).fill("fake-browser-token");
  await page.getByRole("button", { name: "Save provider" }).click();
  await expect(page.locator("#provider-list")).toContainText("Lab DNS");
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByLabel("CF_Token", { exact: true })).toHaveValue("");
  await page.getByLabel("Connection name").fill("Lab DNS updated");
  await page.getByRole("button", { name: "Save provider" }).click();
  await expect(page.locator("#provider-list")).toContainText("Lab DNS updated");
  await page.screenshot({
    path: "test-results/providers-desktop.png",
    fullPage: true,
  });
  await page.locator('[data-tab="clients"]').click();
  await page.locator("#add-button").click();
  await page.getByLabel("Client name", { exact: true }).fill("Home Assistant");
  await page.getByLabel("Allowed domains").fill("home.example.com");
  await page.getByRole("button", { name: "Create client" }).click();
  await expect(
    page.getByRole("heading", { name: "Client is ready" }),
  ).toBeVisible();
  await expect(page.getByLabel("Client token / password")).toHaveValue(
    /^[A-Za-z0-9_-]{43}$/,
  );
  await page.getByRole("button", { name: "Done", exact: true }).click();
  await expect(page.locator("#new-client-token")).toHaveValue("");
  await page.getByRole("button", { name: "Revoke", exact: true }).click();
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.locator("#client-list")).not.toContainText("Home Assistant");
  await expect(page.locator("#revoked-client-list")).not.toBeVisible();
  await page.locator("#revoked-clients summary").click();
  await expect(page.locator("#revoked-client-list")).toContainText("Home Assistant");
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.locator("#confirm-description")).toContainText("validation history permanently");
  await page.locator("#confirm-dialog").getByRole("button", { name: "Cancel" }).click();
  await expect(page.locator("#revoked-client-list")).toContainText("Home Assistant");
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.locator("#revoked-clients")).not.toBeVisible();
  await expect(page.locator("#notice")).toHaveText("Client permanently deleted.");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('[data-tab="providers"]').click();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/providers-mobile.png",
    fullPage: true,
  });
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "One place for DNS access." }),
  ).toBeVisible();
  expect(errors).toEqual([]);
});

for (const width of [1280, 390]) {
  test(`validation errors stay inside forms at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.goto("/");
    await page.getByRole("button", { name: "Open administration" }).click();
    await expect(page.locator("#admin-token-validation-error")).toBeVisible();
    await page.getByLabel("Admin token", { exact: true })
      .fill("browser-test-admin-token-not-for-deployment");
    await expect(page.locator("#admin-token-validation-error")).toHaveCount(0);
    await page.getByRole("button", { name: "Open administration" }).click();
    await page.locator("#add-button").click();
    await page.getByRole("button", { name: "Save provider" }).click();
    await expect(page.locator("#provider-name-validation-error")).toBeVisible();
    await expect(page.locator("#provider-zone-validation-error")).toBeVisible();
    await expect(page.locator("#provider-name")).toBeFocused();
    await page.locator("#provider-dialog").getByRole("button", { name: "Cancel" }).click();
    await page.locator("#add-button").click();
    await expect(page.locator("#provider-dialog .field-error")).toHaveCount(0);
    await page.locator("#provider-dialog").getByRole("button", { name: "Cancel" }).click();

    await page.locator('[data-tab="clients"]').click();
    await page.locator("#add-button").click();
    await page.getByLabel("Client name", { exact: true }).fill("Validation check");
    let submissions = 0;
    await page.route("**/api/admin/clients", async (route) => {
      submissions++;
      await route.fulfill({ status: 400, json: { error: "Invalid domain scope" } });
    });
    await page.getByRole("button", { name: "Create client" }).click();
    const domains = page.getByLabel("Allowed domains");
    const error = page.locator("#client-scopes-validation-error");
    await expect(error).toBeVisible();
    await expect(domains).toBeFocused();
    await expect(domains).toHaveAttribute("aria-invalid", "true");
    await expect(domains).toHaveAttribute("aria-describedby", "client-scopes-validation-error");
    await expect(error).toHaveText(/.+/);
    // Moving focus and allowing popup dismissal must not hide the inline error.
    await page.getByLabel("Client name", { exact: true }).focus();
    await page.waitForTimeout(1500);
    await expect(error).toBeVisible();
    expect(submissions).toBe(0);
    const box = await error.boundingBox();
    expect(await page.evaluate(({ x, y }) => {
      return document.elementFromPoint(x, y)?.classList.contains("field-error");
    }, { x: box.x + box.width / 2, y: box.y + box.height / 2 })).toBe(true);
    await domains.fill("home.example.com");
    await expect(error).toHaveCount(0);
    await expect(domains).not.toHaveAttribute("aria-invalid");
    await page.getByRole("button", { name: "Create client" }).click();
    await expect(page.locator("#client-error")).toHaveText("Invalid domain scope");
    await expect(page.locator("#client-dialog")).toBeVisible();
    expect(submissions).toBe(1);
  });
}

for (const width of [1280, 390]) {
  test(`DNS validations group history by domain at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    const domain = "homeassistant.home.example.com";
    const challenge = (id, host, state, updated_at, operation = "present") => ({
      id, fqdn: `_acme-challenge.${host}`, state, updated_at, operation,
      provider_name: "Production DNS", provider_driver: "dns_cf", expires_at: 1900000000,
      client_name: "Home Assistant", last_error: state === "failed" ? "DNS provider unavailable" : null,
    });
    const overview = {
      providers: [], clients: [], drivers: [{ id: "dns_cf", name: "Cloudflare", fields: [] }], audit: [], active: 3, failed: 1,
      challenges: [
        challenge("old", domain, "cleaned", 100),
        challenge("other", "example.co.uk", "active", 200),
        challenge("failed", domain, "failed", 500, "cleanup"),
        challenge("pending", domain, "present_pending", 400),
        challenge("cleanup", "apps.example.co.uk", "cleanup_pending", 300),
      ],
    };
    await page.route("**/api/admin/overview", (route) => route.fulfill({ json: overview }));
    const operations = [];
    await page.route("**/api/admin/challenges/*/*", (route) => {
      operations.push(new URL(route.request().url()).pathname);
      return route.fulfill({ json: {} });
    });
    await page.goto("/");
    await page.getByLabel("Admin token", { exact: true }).fill("test-token");
    await page.getByRole("button", { name: "Open administration" }).click();
    await page.getByRole("link", { name: "DNS validations", exact: true }).click();
    await expect(page.getByRole("heading", { name: "DNS validations", exact: true })).toBeVisible();
    const groups = page.locator(".certificate-domain");
    await expect(groups).toHaveCount(3);
    await expect(groups.first().getByRole("heading")).toHaveText(domain);
    const group = page.getByRole("region", { name: domain, exact: true });
    await expect(group).toContainText("3 validations");
    await expect(group.locator(".certificate-record")).not.toBeVisible();
    await expect(group.locator("summary time")).toBeVisible();
    await expect(group.locator("summary time")).toContainText("Last Event:");
    await group.locator("summary").focus();
    await page.keyboard.press("Enter");
    await expect(group.locator(".certificate-record")).toBeVisible();
    await page.getByRole("button", { name: "Refresh", exact: false }).click();
    await expect(page.locator("#refresh-status")).toHaveText("Up to date.");
    await expect(group.locator(".certificate-record")).toBeVisible();
    await expect(group).toContainText(`DNS record (TXT): _acme-challenge.${domain}`);
    await expect(group.locator(".row")).toHaveCount(3);
    await expect(group.locator(".row").first()).toContainText("Client name:Home Assistant");
    await expect(group.locator(".row").first()).toContainText("DNS provider:Production DNS · Cloudflare");
    await expect(group.locator(".row").first()).toContainText("TXT removal failed");
    await expect(group.locator(".row").first()).toContainText("DNS provider unavailable");
    await expect(group.locator(".row").last()).toContainText("TXT value removed");
    await expect(group.locator(".row").last().getByRole("button")).toHaveCount(0);
    await expect(group).toContainText("Publishing TXT value");
    await expect(page.getByRole("region", { name: "example.co.uk", exact: true })).toContainText("TXT value published");
    await expect(page.getByRole("region", { name: "apps.example.co.uk", exact: true })).toContainText("Removing TXT value");
    await group.getByRole("button", { name: "Retry", exact: true }).click();
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    await expect(page.locator("#confirm-dialog")).not.toBeVisible();
    expect(operations).toEqual(["/api/admin/challenges/failed/retry"]);
    await group.locator(".row").nth(1).getByRole("button", { name: "Clean up", exact: true }).click();
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    await expect(page.locator("#confirm-dialog")).not.toBeVisible();
    expect(operations[1]).toBe("/api/admin/challenges/pending/cleanup");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const single = page.getByRole("region", { name: "example.co.uk", exact: true });
    await expect(single.locator(".certificate-details")).not.toBeVisible();
    await expect(single.locator("summary time")).toBeVisible();
    await single.locator("summary").click();
    await expect(single.locator(".certificate-details")).toBeVisible();
    await expect(single.locator("time")).toHaveCount(1);
    await page.screenshot({ path: `test-results/certificates-${width}.png`, fullPage: true });
    await single.locator("summary").click();
    await expect(single.locator(".certificate-details")).not.toBeVisible();
    overview.challenges = [];
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(page.locator("#challenge-list")).toHaveText("No DNS validations yet");
  });
}

test("manual refresh reports progress, unchanged success, and failure", async ({ page }) => {
  const overview = { providers: [], clients: [], drivers: [], audit: [], challenges: [], active: 0, failed: 0 };
  let fail = false;
  let pending;
  await page.route("**/api/admin/overview", async (route) => {
    if (pending) await pending;
    await route.fulfill(fail
      ? { status: 503, json: { error: "Server unavailable" } }
      : { json: overview });
  });
  await page.goto("/");
  await page.getByLabel("Admin token", { exact: true }).fill("test-token");
  await page.getByRole("button", { name: "Open administration" }).click();
  await page.getByRole("link", { name: "DNS validations", exact: true }).click();
  const button = page.locator("#refresh");
  const status = page.locator("#refresh-status");
  for (const shouldFail of [false, true, false]) {
    fail = shouldFail;
    let finish;
    pending = new Promise((resolve) => { finish = resolve; });
    await button.click();
    await expect(button).toBeDisabled();
    await expect(button).toHaveText("Refreshing…");
    await expect(status).toBeEmpty();
    finish();
    await expect(button).toBeEnabled();
    await expect(button).toHaveText("Refresh ↻");
    await expect(status).toBeVisible();
    await expect(status).toHaveText(shouldFail ? "Refresh failed: Server unavailable" : "Up to date.");
  }
});

test("tab URLs support direct links, reloads, and browser history", async ({ page }) => {
  const routes = [
    ["/providers", "DNS providers"],
    ["/clients", "Clients"],
    ["/validations", "DNS validations"],
    ["/activity", "Activity"],
  ];
  const login = async () => {
    await page.getByLabel("Admin token", { exact: true }).fill("browser-test-admin-token-not-for-deployment");
    await page.getByRole("button", { name: "Open administration" }).click();
  };
  for (const [path, title] of routes) {
    const response = await page.goto(path);
    expect(response.status()).toBe(200);
    await expect(page.locator("#login")).toBeVisible();
    await login();
    await expect(page.locator("#page-title")).toHaveText(title);
    await expect(page).toHaveURL(new RegExp(`${path}$`));
    await expect(page.getByRole("navigation").getByRole("link", { name: title, exact: true }))
      .toHaveAttribute("aria-current", "page");
  }
  await page.reload();
  await login();
  await expect(page.locator("#page-title")).toHaveText("Activity");
  await expect(page).toHaveURL(/\/activity$/);
  for (const [path, title] of routes.slice(0, 3)) {
    await page.getByRole("navigation").getByRole("link", { name: title, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`${path}$`));
    await expect(page.locator("#page-title")).toHaveText(title);
  }
  // Clicking the active tab must not add a duplicate history entry.
  await page.getByRole("navigation").getByRole("link", { name: "DNS validations", exact: true }).click();
  await page.goBack();
  await expect(page).toHaveURL(/\/clients$/);
  await expect(page.locator("#page-title")).toHaveText("Clients");
  await page.locator("#add-button").click();
  await expect(page.locator("#client-dialog")).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL(/\/providers$/);
  await expect(page.locator("#page-title")).toHaveText("DNS providers");
  await expect(page.locator("#client-dialog")).not.toBeVisible();
  await page.goForward();
  await expect(page).toHaveURL(/\/clients$/);
  await expect(page.locator("#page-title")).toHaveText("Clients");
  await page.locator("aside .brand").click();
  await expect(page).toHaveURL(/\/providers$/);
  await page.goto("/");
  await expect(page).toHaveURL(/\/providers$/);
  expect((await page.request.get("/not-a-page")).status()).toBe(404);
});

for (const width of [1280, 390]) {
  test(`revoked clients stay collapsed and deletion errors remain visible at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.clock.install();
    const overview = {
      providers: [], drivers: [], audit: [], challenges: [], active: 0, failed: 0,
      clients: [
        { id: "active", name: "Current service", scopes: ["home.example.com"], revoked: false },
        { id: "revoked", name: "Old service", scopes: ["old.example.com"], revoked: true },
      ],
    };
    await page.route("**/api/admin/overview", (route) => route.fulfill({ json: overview }));
    await page.route("**/api/admin/clients/revoked/permanent", (route) => route.fulfill({
      status: 409, json: { error: "Clean up outstanding DNS validations first" },
    }));
    await page.goto("/clients");
    await page.getByLabel("Admin token", { exact: true }).fill("test-token");
    await page.getByRole("button", { name: "Open administration" }).click();
    await expect(page.locator("#client-list")).toContainText("Current service");
    await expect(page.getByText("Old service", { exact: true })).not.toBeVisible();
    await page.clock.runFor(10000);
    await expect(page.getByText("Old service", { exact: true })).not.toBeVisible();
    await page.locator("#revoked-clients summary").click();
    await expect(page.getByText("Old service", { exact: true })).toBeVisible();
    await page.clock.runFor(10000);
    await expect(page.getByText("Old service", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    await expect(page.locator("#confirm-error")).toHaveText("Clean up outstanding DNS validations first");
    await expect(page.locator("#confirm-dialog")).toBeVisible();
    await page.locator("#confirm-dialog").getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByText("Old service", { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: `test-results/clients-${width}.png`, fullPage: true });
  });
}

test("success notices expire, reset their timer, and clear on navigation", async ({ page }) => {
  await page.clock.install();
  await page.route("**/api/admin/overview", (route) => route.fulfill({
    json: { providers: [], clients: [], drivers: [], audit: [], challenges: [], active: 0, failed: 0 },
  }));
  await page.goto("/");
  await page.getByLabel("Admin token", { exact: true }).fill("test-token");
  await page.getByRole("button", { name: "Open administration" }).click();
  const notice = page.locator("#notice");
  await page.evaluate(() => notify("Provider saved."));
  await expect(notice).toBeVisible();
  await page.clock.runFor(4000);
  await expect(notice).toBeVisible();
  await page.evaluate(() => notify("Client permanently deleted."));
  await page.clock.runFor(1000);
  await expect(notice).toBeVisible();
  await expect(notice).toHaveText("Client permanently deleted.");
  await page.clock.runFor(4000);
  await expect(notice).not.toBeVisible();
  await page.evaluate(() => notify("Provider removed."));
  await page.getByRole("link", { name: "Clients", exact: true }).click();
  await expect(notice).not.toBeVisible();
  await page.goBack();
  await expect(notice).not.toBeVisible();
  await page.evaluate(() => notify("Provider saved."));
  await page.clock.runFor(1000);
  await page.evaluate(() => notify("Connection failed.", true));
  await page.clock.runFor(6000);
  await expect(notice).toBeVisible();
  await expect(notice).toHaveText("Connection failed.");
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(notice).toBeEmpty();
  await page.getByLabel("Admin token", { exact: true }).fill("test-token");
  await page.getByRole("button", { name: "Open administration" }).click();
  await expect(notice).not.toBeVisible();
});

for (const width of [1280, 390]) {
  test(`activity log supports retention, search, and stable older pages at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.clock.install();
    let retention = 120;
    let events = Array.from({ length: 120 }, (_, index) => ({
      id: 120 - index, at: 1788800000 - index, actor: "worker", action: "dns.published",
      target: `host-${120 - index}.example.com`, outcome: "success",
    }));
    let reads = 0;
    let fail = false;
    await page.route("**/api/admin/overview", (route) => route.fulfill({
      json: { providers: [], clients: [], drivers: [], challenges: [], audit: [], active: 0, failed: 0 },
    }));
    await page.route("**/api/admin/activity?*", (route) => {
      reads++;
      if (fail) return route.fulfill({ status: 503, json: { error: "Log unavailable" } });
      const query = new URL(route.request().url()).searchParams;
      const filtered = events.filter((event) =>
        (!query.has("before") || event.id < Number(query.get("before"))) &&
        Object.values(event).join(" ").includes(query.get("search") || ""));
      return route.fulfill({ json: {
        retention, stored: events.length, events: filtered.slice(0, 50),
        next_before: filtered.length > 50 ? filtered[49].id : null,
      } });
    });
    const saved = [];
    await page.route("**/api/admin/activity/retention", (route) => {
      retention = route.request().postDataJSON().retention;
      saved.push(retention);
      events = events.slice(0, retention);
      return route.fulfill({ json: { retention } });
    });
    await page.goto("/activity");
    await page.getByLabel("Admin token", { exact: true }).fill("test-token");
    await page.getByRole("button", { name: "Open administration" }).click();
    await expect(page.locator("#audit-list tr")).toHaveCount(50);
    await expect(page.locator("#audit-list tr").first()).toContainText("host-120.example.com");
    await expect(page.getByLabel("Keep last N events")).toHaveValue("120");
    await page.getByRole("button", { name: "Older", exact: false }).click();
    await expect(page.locator("#audit-list tr").first()).toContainText("host-70.example.com");
    const readsBefore = reads;
    await page.clock.runFor(10000);
    expect(reads).toBe(readsBefore);
    await expect(page.locator("#audit-list tr").first()).toContainText("host-70.example.com");
    await page.getByRole("button", { name: "Newer", exact: false }).click();
    await expect(page.locator("#audit-list tr").first()).toContainText("host-120.example.com");
    await page.getByLabel("Search events").fill("host-119.");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.locator("#audit-list tr")).toHaveCount(1);
    await expect(page.locator("#audit-list tr")).toContainText("host-119.example.com");
    await page.getByLabel("Search events").fill("no-such-event");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.locator("#activity-empty")).toHaveText("No matching events");
    await page.getByLabel("Search events").fill("");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.locator("#audit-list tr")).toHaveCount(50);
    // Background refresh must not discard an unsaved limit.
    await page.getByLabel("Keep last N events").fill("60");
    await page.getByRole("heading", { name: "Activity log" }).click();
    await page.clock.runFor(10000);
    await expect(page.getByLabel("Keep last N events")).toHaveValue("60");
    await page.getByRole("button", { name: "Save limit" }).click();
    await expect(page.locator("#confirm-description")).toContainText("permanently deleted");
    await page.locator("#confirm-dialog").getByRole("button", { name: "Cancel" }).click();
    expect(saved).toEqual([]);
    await page.getByRole("button", { name: "Save limit" }).click();
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    await expect(page.locator("#confirm-dialog")).not.toBeVisible();
    expect(saved).toEqual([60]);
    await expect(page.locator("#activity-count")).toContainText("60 events stored");
    await page.getByRole("button", { name: "Older", exact: false }).click();
    await expect(page.locator("#audit-list tr")).toHaveCount(10);
    await page.getByRole("button", { name: "Latest", exact: true }).click();
    await expect(page.locator("#audit-list tr")).toHaveCount(50);
    await page.getByRole("button", { name: "Refresh", exact: false }).click();
    await expect(page.locator("#activity-status")).toHaveText("Up to date.");
    fail = true;
    await page.getByRole("button", { name: "Refresh", exact: false }).click();
    await expect(page.locator("#activity-status")).toHaveText("Log unavailable");
    await expect(page.locator("#audit-list tr")).toHaveCount(50);
    fail = false;
    await page.getByRole("button", { name: "Refresh", exact: false }).click();
    await expect(page.locator("#activity-status")).toHaveText("Up to date.");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: `test-results/activity-${width}.png`, fullPage: true });
  });
}

for (const width of [1280, 390]) {
  test(`about page and problem reporting work at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const revision = 'a'.repeat(40);
    await page.route('**/healthz', route => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ status: 'ok', version: '2.3.4', revision, release: false, dirty: true, display_version: 'v2.3.4-aaaaaaa-dirty', version_url: `https://github.com/alextac98/acmeproxy/commit/${revision}` }),
    }));
    const response = await page.goto('/about');
    expect(response.status()).toBe(200);
    await page.getByLabel('Admin token', { exact: true }).fill('browser-test-admin-token-not-for-deployment');
    await page.getByRole('button', { name: 'Open administration' }).click();
    await expect(page.locator('#page-title')).toHaveText('About');
    await expect(page.locator('#about-panel')).toBeVisible();
    await expect(page.locator('#gateway-summary')).toBeHidden();
    await expect(page.locator('#add-button')).toBeHidden();
    await expect(page.locator('#about-version')).toHaveText('v2.3.4-aaaaaaa-dirty');
    await expect(page.locator('#app-version')).toHaveText('v2.3.4-aaaaaaa-dirty');
    await expect(page.locator('#app-version')).toHaveAttribute('href', `https://github.com/alextac98/acmeproxy/commit/${revision}`);
    await expect(page.locator('#app-version')).toHaveAttribute('target', '_blank');
    expect(await page.locator('#app-version').evaluate(el => getComputedStyle(el).textAlign)).toBe('center');
    await expect(page.locator('#app-version')).not.toHaveAttribute('data-tab');
    await expect(page.locator('#about-build a')).toHaveAttribute('href', `https://github.com/alextac98/acmeproxy/commit/${revision}`);
    await expect(page.locator('.utility-actions').getByRole('link', { name: 'About', exact: true }))
      .toHaveAttribute('aria-current', 'page');
    const report = page.getByRole('link', { name: 'Report a problem', exact: true });
    await expect(report).toBeVisible();
    await report.focus();
    await expect(report).toBeFocused();
    for (const link of await page.locator('.report-problem').all()) {
      await expect(link).toHaveAttribute('href', 'https://github.com/alextac98/acmeproxy/issues/new/choose');
    }
    await expect(report).toHaveAttribute('target', '_blank');
    await page.getByText('Attributions', { exact: true }).click();
    await expect(page.locator('.about-attributions')).toHaveAttribute('open', '');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: `test-results/about-${width}.png`, fullPage: true });
    await page.getByRole('navigation').getByRole('link', { name: 'DNS providers', exact: true }).click();
    await expect(page.locator('#gateway-summary')).toBeVisible();
    await page.locator('.utility-actions').getByRole('link', { name: 'About', exact: true }).click();
    await expect(page).toHaveURL(/\/about$/);
    await page.goBack();
    await expect(page).toHaveURL(/\/providers$/);
    await expect(page.locator('#about-panel')).toBeHidden();
  });
}

test('about identifies a local build without inventing a commit link', async ({ page }) => {
  await page.route('**/healthz', route => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ status: 'ok', version: '0.1.0', revision: 'unknown', display_version: 'v0.1.0-dev', version_url: null, release: false, dirty: false }),
  }));
  await page.goto('/about');
  await expect(page.locator('#about-build')).toHaveText('Local build');
  await expect(page.locator('#about-build a')).toHaveCount(0);
  await expect(page.locator('#app-version')).toHaveText('v0.1.0-dev');
  await expect(page.locator('#app-version')).not.toHaveAttribute('href');
});

for (const released of [false, true]) {
  test(`version links to ${released ? 'release' : 'clean dev commit'}`, async ({ page }) => {
    const revision = 'b'.repeat(40);
    const versionUrl = released ? 'https://github.com/alextac98/acmeproxy/releases/tag/v0.1.0'
      : `https://github.com/alextac98/acmeproxy/commit/${revision}`;
    const display = released ? 'v0.1.0' : 'v0.1.0-bbbbbbb';
    await page.route('**/healthz', route => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ status: 'ok', version: '0.1.0', revision, release: released, dirty: false, display_version: display, version_url: versionUrl }),
    }));
    await page.goto('/about');
    await expect(page.locator('#app-version')).toHaveText(display);
    await expect(page.locator('#app-version')).toHaveAttribute('href', versionUrl);
    await expect(page.locator('#app-version')).toHaveAttribute('target', '_blank');
    await expect(page.locator('#app-version')).not.toHaveAttribute('data-tab');
  });
}
