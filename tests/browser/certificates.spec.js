const { test, expect } = require("@playwright/test");

test("request, monitor, download, and pause a managed certificate", async ({ page }) => {
  // UI fixture: never create real ACME orders from browser tests.
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  let certificates = [];
  let request;
  const id = "certificate-ui-fixture";
  await page.route("**/api/admin/certificates**", async route => {
    expect(route.request().headers().authorization).toBe("Bearer browser-test-admin-token-not-for-deployment");
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.pathname.endsWith(".pem")) {
      return route.fulfill({ status: 200, contentType: "application/x-pem-file", body: "TEST CERTIFICATE FIXTURE" });
    }
    if (method === "POST") {
      request = route.request().postDataJSON();
      certificates = [{ id, domains: request.domains, staging: request.staging, state: "queued", phase: "Queued", auto_renew: true, downloadable: false }];
      return route.fulfill({ status: 202, json: { id } });
    }
    if (method === "PUT") certificates[0].auto_renew = route.request().postDataJSON().auto_renew;
    if (method === "DELETE") certificates = [];
    return route.fulfill({ json: method === "GET" ? certificates : {} });
  });
  await page.goto("/certificates");
  await page.getByLabel("Admin token", { exact: true }).fill("browser-test-admin-token-not-for-deployment");
  await page.getByRole("button", { name: "Open administration" }).click();
  await expect(page.getByRole("heading", { name: "Certificates", exact: true })).toBeVisible();
  await page.locator("#add-button").click();
  await page.getByLabel("Domains", { exact: true }).fill("example.com\n*.example.com");
  await page.getByLabel("Certificate type").selectOption("staging");
  await page.locator("#certificate-terms").check();
  await page.getByRole("button", { name: "Request certificate", exact: true }).click();
  await expect(page.locator("#certificate-list")).toContainText("Queued");
  expect(request).toEqual({ domains: ["example.com", "*.example.com"], staging: true, terms_agreed: true });
  const now = Math.floor(Date.now() / 1000);
  certificates[0] = { ...certificates[0], state: "issued", phase: "Issued", downloadable: true, expires_at: now + 86400 * 6, renew_at: now + 86400 * 4 };
  await page.evaluate(() => refreshCertificates());
  await expect(page.locator("#certificate-list")).toContainText("not browser trusted");
  await expect(page.locator("#certificate-list")).toContainText("Renewal scheduled");
  const downloading = page.waitForEvent("download");
  await page.getByRole("button", { name: "PEM bundle", exact: true }).click();
  expect((await downloading).suggestedFilename()).toBe("bundle.pem");
  await page.getByRole("button", { name: "Pause renewal", exact: true }).click();
  await expect(page.getByRole("button", { name: "Enable renewal", exact: true })).toBeVisible();
  await expect(page.locator("#certificate-list")).toContainText("Automatic renewal off");
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: "test-results/certificates-mobile.png", fullPage: true });
  await page.getByRole("button", { name: "Remove", exact: true }).click();
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.locator("#certificate-list")).toContainText("No managed certificates yet");
  expect(errors).toEqual([]);
});
