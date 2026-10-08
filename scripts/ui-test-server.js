// Browser-only fixture uses a temporary config directory and fake credentials. No DNS calls.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "acmeproxy-browser-"));
execFileSync("target/debug/acmeproxy", ["init", "--config-dir", root]);
fs.writeFileSync(
  path.join(root, "admin.token"),
  "browser-test-admin-token-not-for-deployment",
);
const home = path.resolve(".local/acme.sh");
const listen = process.env.ACMEPROXY_UI_TEST_LISTEN || "127.0.0.1:18080";
fs.writeFileSync(
  path.join(root, "config.toml"),
  `[server]\nlisten = ${JSON.stringify(listen)}\ndnsapi_home = ${JSON.stringify(home)}\n`,
);
const child = spawn("target/debug/acmeproxy", ["serve", "--config-dir", root], {
  stdio: "inherit",
});
function stop() {
  child.kill("SIGTERM");
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
child.on("exit", (code) => {
  fs.rmSync(root, { recursive: true, force: true });
  process.exit(code || 0);
});
