const { defineConfig } = require("@playwright/test");
module.exports = defineConfig({
  testDir: "./tests/browser",
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:18080",
    headless: true,
    channel: "chromium",
  },
  webServer: {
    command: "node scripts/ui-test-server.js",
    url: "http://127.0.0.1:18080/healthz",
    timeout: 30000,
  },
});
