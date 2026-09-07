"use strict";
const $ = (id) => document.getElementById(id);
let token = "",
  data = null,
  currentTab = "providers",
  refreshTimer,
  confirmAction;
const tabs = {
  providers: [
    "DNS providers",
    "Keep DNS credentials in one place. Route challenges by domain.",
    "+ Add provider",
  ],
  clients: [
    "Clients",
    "Give services access to only the domains they need.",
    "+ Add client",
  ],
  challenges: [
    "Challenges",
    "Follow DNS operations from request through cleanup.",
    null,
  ],
  activity: [
    "Activity",
    "Review configuration changes and DNS operations.",
    null,
  ],
};
function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}
function action(label, handler, className = "subtle") {
  const el = node("button", className, label);
  el.type = "button";
  el.addEventListener("click", handler);
  return el;
}
function notify(message, error = false) {
  $("notice").textContent = message;
  $("notice").className = error ? "error" : "";
  $("notice").hidden = false;
}
async function api(path, method = "GET", body) {
  const response = await fetch("/api/admin" + path, {
    method,
    headers: {
      Authorization: "Bearer " + token,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error("The server returned an unexpected response.");
  }
  if (!response.ok) {
    if (response.status === 401) logout();
    throw new Error(result.error || "Request failed.");
  }
  return result;
}
async function refresh() {
  data = await api("/overview");
  $("provider-count").textContent = data.providers.length;
  $("client-count").textContent = data.clients.filter((c) => !c.revoked).length;
  $("challenge-count").textContent = data.active;
  $("challenge-note").textContent = data.failed
    ? `${data.failed} failed · needs attention`
    : "Waiting or published";
  renderProviders();
  renderClients();
  renderChallenges();
  renderAudit();
}
function logout() {
  token = "";
  clearInterval(refreshTimer);
  data = null;
  $("workspace").hidden = true;
  $("login").hidden = false;
  $("admin-token").value = "";
  document.querySelectorAll("dialog").forEach((d) => d.close());
  ["new-client-id", "new-client-token", "client-example"].forEach(
    (id) => ($(id).value = ""),
  );
}
$("logout").onclick = logout;
$("login-form").onsubmit = async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  $("login-error").textContent = "";
  token = $("admin-token").value.trim();
  try {
    await refresh();
    $("admin-token").value = "";
    $("login").hidden = true;
    $("workspace").hidden = false;
    switchTab("providers");
    refreshTimer = setInterval(
      () => refresh().catch((e) => notify(e.message, true)),
      10000,
    );
  } catch (e) {
    token = "";
    $("login-error").textContent = e.message;
  } finally {
    button.disabled = false;
  }
};
function switchTab(tab) {
  currentTab = tab;
  $("breadcrumb").textContent = tabs[tab][0];
  $("page-title").textContent = tabs[tab][0];
  $("page-description").textContent = tabs[tab][1];
  $("add-button").hidden = !tabs[tab][2];
  $("add-button").textContent = tabs[tab][2];
  Object.keys(tabs).forEach((key) => ($(key + "-panel").hidden = key !== tab));
  document
    .querySelectorAll("[data-tab]")
    .forEach((b) => b.classList.toggle("selected", b.dataset.tab === tab));
}
document
  .querySelectorAll("[data-tab]")
  .forEach((b) => (b.onclick = () => switchTab(b.dataset.tab)));
document.querySelector("aside .brand").onclick = (event) => {
  event.preventDefault();
  switchTab("providers");
};
$("add-button").onclick = () =>
  currentTab === "providers" ? openProvider() : openClient();
$("refresh").onclick = () => refresh().catch((e) => notify(e.message, true));
document
  .querySelectorAll(".close")
  .forEach((b) =>
    b.addEventListener("click", () => b.closest("dialog").close()),
  );
$("token-dialog").addEventListener("close", () =>
  ["new-client-id", "new-client-token", "client-example"].forEach(
    (id) => ($(id).value = ""),
  ),
);
function empty(target, title, description, label, handler) {
  const el = node("div", "empty");
  el.append(node("strong", "", title), node("p", "", description));
  if (label) el.append(action(label, handler, "secondary"));
  target.append(el);
}
function identity(title, subtitle, icon) {
  const outer = node("div", "row-identity");
  if (icon) outer.append(node("span", "provider-icon", icon));
  const text = node("div");
  text.append(
    node("div", "row-title", title),
    node("div", "row-subtitle", subtitle),
  );
  outer.append(text);
  return outer;
}
function renderProviders() {
  const list = $("provider-list");
  list.replaceChildren();
  if (!data.providers.length)
    return empty(
      list,
      "Connect your first DNS provider",
      "Your services will use scoped client credentials to request DNS challenges.",
      "+ Add provider",
      () => openProvider(),
    );
  data.providers.forEach((p) => {
    const driver = data.drivers.find((d) => d.id === p.driver);
    const row = node("div", "row");
    row.append(
      identity(
        p.name,
        `${driver?.name || p.driver} · ${p.zone}`,
        p.driver === "dns_cf"
          ? "CF"
          : p.driver.replace("dns_", "").slice(0, 2).toUpperCase(),
      ),
    );
    const buttons = node("div", "row-actions");
    buttons.append(
      action("Edit", () => openProvider(p)),
      action("Remove", () =>
        confirm(
          "Remove provider?",
          `Remove ${p.name} from configuration. Outstanding challenges must be cleaned up first.`,
          async () => {
            await api("/providers/" + p.id, "DELETE");
            await refresh();
            notify("Provider removed.");
          },
        ),
      ),
    );
    row.append(buttons);
    list.append(row);
  });
}
function renderClients() {
  const list = $("client-list");
  list.replaceChildren();
  if (!data.clients.length)
    return empty(
      list,
      "No clients yet",
      "Create a client for a service and choose the domains it may validate.",
      "+ Add client",
      openClient,
    );
  data.clients.forEach((c) => {
    const row = node("div", "row"),
      info = identity(c.name, c.id);
    info.firstChild.append(node("div", "scope-list", c.scopes.join(" · ")));
    row.append(info);
    const buttons = node("div", "row-actions");
    buttons.append(
      node(
        "span",
        "status " + (c.revoked ? "" : "active"),
        c.revoked ? "Revoked" : "Active",
      ),
    );
    if (!c.revoked)
      buttons.append(
        action("Revoke", () =>
          confirm(
            "Revoke client?",
            `${c.name} will lose access immediately. Its outstanding challenges will be queued for cleanup.`,
            async () => {
              await api("/clients/" + c.id, "DELETE");
              await refresh();
              notify("Client revoked. Cleanup has been queued.");
            },
          ),
        ),
      );
    row.append(buttons);
    list.append(row);
  });
}
const statusText = {
  active: "Published",
  present_pending: "Publishing",
  cleanup_pending: "Cleaning up",
  cleaned: "Cleaned",
  failed: "Failed",
};
function renderChallenges() {
  const list = $("challenge-list");
  list.replaceChildren();
  if (!data.challenges.length)
    return empty(
      list,
      "No challenges yet",
      "Challenges appear here when an authorized ACME client requests validation.",
    );
  data.challenges.forEach((c) => {
    const row = node("div", "row");
    const info = identity(
      c.fqdn,
      `${c.client_name} · ${new Date(c.updated_at * 1000).toLocaleString()}`,
    );
    if (c.last_error) info.firstChild.append(node("p", "error", c.last_error));
    row.append(info);
    const buttons = node("div", "row-actions");
    buttons.append(node("span", "status " + c.state, statusText[c.state]));
    if (c.state === "failed")
      buttons.append(
        action("Retry", () =>
          confirm(
            "Retry with current credentials?",
            "Retry this operation using the provider credentials currently saved in configuration.",
            async () => {
              await api("/challenges/" + c.id + "/retry", "POST");
              await refresh();
            },
          ),
        ),
      );
    if (!["cleaned", "cleanup_pending"].includes(c.state))
      buttons.append(
        action("Clean up", () =>
          confirm(
            "Clean up challenge?",
            "Remove this challenge value from DNS. Validation will fail if the ACME client still needs it.",
            async () => {
              await api("/challenges/" + c.id + "/cleanup", "POST");
              await refresh();
              notify("Cleanup queued.");
            },
          ),
        ),
      );
    row.append(buttons);
    list.append(row);
  });
}
function renderAudit() {
  const list = $("audit-list");
  list.replaceChildren();
  if (!data.audit.length)
    return empty(
      list,
      "No activity yet",
      "Configuration changes and DNS operation results will appear here.",
    );
  data.audit.forEach((a) => {
    const row = node("div", "row");
    row.append(
      identity(
        a.action.replaceAll(".", " · "),
        `${a.actor} · ${a.target} · ${a.outcome}`,
      ),
      node("time", "audit-time", new Date(a.at * 1000).toLocaleString()),
    );
    list.append(row);
  });
}
function openProvider(provider) {
  $("provider-form").reset();
  $("provider-error").textContent = "";
  $("provider-id").value = provider?.id || "";
  $("provider-dialog-title").textContent = provider
    ? "Edit DNS provider"
    : "Add DNS provider";
  $("provider-name").value = provider?.name || "";
  $("provider-zone").value = provider?.zone || "";
  const select = $("provider-driver");
  select.replaceChildren();
  const ordered = [...data.drivers].sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  ordered.forEach((d) => {
    const option = node("option", "", d.name);
    option.value = d.id;
    select.append(option);
  });
  select.value =
    provider?.driver ||
    (data.drivers.some((d) => d.id === "dns_cf")
      ? "dns_cf"
      : ordered[0]?.id || "");
  credentialFields();
  $("provider-dialog").showModal();
}
function credentialFields() {
  const fields = $("credential-fields");
  fields.replaceChildren();
  const driver = data.drivers.find((d) => d.id === $("provider-driver").value);
  if (!driver) {
    fields.append(
      node(
        "p",
        "error",
        "No installed DNS adapters. Install the pinned adapter bundle and restart.",
      ),
    );
    return;
  }
  $("provider-docs").href = driver.docs;
  driver.fields.forEach((field, i) => {
    const id = "credential-" + i;
    const label = node("label", "", field.key);
    label.htmlFor = id;
    const input = node("input");
    input.id = id;
    input.name = field.key;
    input.type = "password";
    input.autocomplete = "new-password";
    input.placeholder = field.label;
    input.maxLength = 4096;
    fields.append(label, input);
  });
}
$("provider-driver").onchange = credentialFields;
$("provider-form").onsubmit = async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  $("provider-error").textContent = "";
  const credentials = {};
  $("credential-fields")
    .querySelectorAll("input")
    .forEach((i) => {
      if (i.value) credentials[i.name] = i.value;
    });
  const id = $("provider-id").value;
  try {
    await api("/providers" + (id ? "/" + id : ""), id ? "PUT" : "POST", {
      name: $("provider-name").value.trim(),
      driver: $("provider-driver").value,
      zone: $("provider-zone").value.trim(),
      credentials,
    });
    $("provider-dialog").close();
    $("provider-form").reset();
    await refresh();
    notify("Provider saved to config.toml. Credentials are encrypted.");
  } catch (e) {
    $("provider-error").textContent = e.message;
  } finally {
    button.disabled = false;
  }
};
function openClient() {
  $("client-form").reset();
  $("client-error").textContent = "";
  $("client-dialog").showModal();
}
$("client-form").onsubmit = async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  $("client-error").textContent = "";
  try {
    const result = await api("/clients", "POST", {
      name: $("client-name").value.trim(),
      scopes: $("client-scopes")
        .value.split(/\n/)
        .map((s) => s.trim())
        .filter(Boolean),
    });
    $("client-dialog").close();
    $("new-client-id").value = result.id;
    $("new-client-token").value = result.token;
    $("client-example").value =
      `export ACMEPROXY_ENDPOINT='${location.origin}'\nexport ACMEPROXY_USERNAME='${result.id}'\nexport ACMEPROXY_PASSWORD='${result.token}'`;
    $("token-dialog").showModal();
    await refresh();
  } catch (e) {
    $("client-error").textContent = e.message;
  } finally {
    button.disabled = false;
  }
};
$("copy-token").onclick = async () => {
  try {
    await navigator.clipboard.writeText($("new-client-token").value);
    $("copy-token").textContent = "Copied";
    setTimeout(() => ($("copy-token").textContent = "Copy token"), 2000);
  } catch {
    $("new-client-token").select();
  }
};
function confirm(title, description, handler) {
  $("confirm-title").textContent = title;
  $("confirm-description").textContent = description;
  $("confirm-error").textContent = "";
  confirmAction = handler;
  $("confirm-dialog").showModal();
}
$("confirm-form").onsubmit = async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  try {
    await confirmAction();
    $("confirm-dialog").close();
  } catch (e) {
    $("confirm-error").textContent = e.message;
  } finally {
    button.disabled = false;
  }
};
