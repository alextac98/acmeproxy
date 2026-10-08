async function goTo(page, tab) {
  await page.locator("#workspace").waitFor({ state: "visible" });
  const menu = page.locator("#menu-toggle");
  if (await menu.isVisible() && await menu.getAttribute("aria-expanded") !== "true") await menu.click();
  await page.locator(`#main-navigation [data-tab="${["challenges", "orders"].includes(tab) ? "activity" : tab}"]`).click();
  if (["challenges", "orders"].includes(tab)) await page.locator(`#activity-tabs [data-tab="${tab}"]`).click();
}
module.exports = { goTo };
