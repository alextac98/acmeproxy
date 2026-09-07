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
  await expect(page.locator("#client-list")).toContainText("Revoked");
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
