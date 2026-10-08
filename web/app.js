"use strict";
const $ = (id) => document.getElementById(id);
let token = "",
  data = null,
  currentTab = "overview",
  currentView = "list",
  currentId = null,
  currentPath = "",
  editorRoute = null,
  refreshTimer,
  noticeTimer,
  confirmAction;
let activityData = null,
  activityBefore = null,
  activityPrevious = [],
  activitySearch = "",
  activityLoading = false,
  activitySaving = false,
  activityRequest = 0,
  activityRetentionDirty = false;
let certificatesData = null, acmeSettingsDirty = false, acmeSettingsData = null, acmeSettingsSaving = false;
let currentAcmeView = "connection";
const acmeClientRequestsOpen = new Set(), acmeClientRegistrationOpen = new Set();
const acmePaths = { connection: "/acme-endpoint", settings: "/acme-endpoint/settings", clients: "/acme-endpoint/clients" };
let sessionVersion = 0;
let overviewRequest = 0, certificatesRequest = 0, acmeRequest = 0, certificateSaving = false;
const methodDescriptions = {
  certificates: "Request and download certificates here. ACME Proxy obtains and renews them using DNS-01, stores the private keys, and supports wildcard certificates.",
  acme: "Connect your ACME client via HTTP-01. ACME Proxy obtains the certificates; your client stores the private keys and handles renewal. No gateway token is needed, and wildcard certificates are not supported.",
  clients: "Use a scoped client token to let ACME Proxy manage DNS-01 records, including wildcards. Your client obtains and renews certificates directly with its certificate authority and stores the private keys.",
};
const tabs = {
  overview: ["Overview", "+ Get a certificate", "/overview", "Your certificates, connections, and recent activity."],
  methods: ["Get a certificate", null, "/certificate-methods", "Choose where your certificate and private key will be managed."],
  providers: ["DNS providers", "+ Connect provider", "/providers", "Shared DNS access for all three certificate methods."],
  certificates: ["Managed certificates", "+ Request certificate", "/certificates", methodDescriptions.certificates],
  clients: ["DNS gateway", "+ Create gateway client", "/dns-gateway", methodDescriptions.clients],
  acme: ["ACME endpoint", null, "/acme-endpoint", methodDescriptions.acme],
  challenges: ["DNS validations", null, "/activity/validations", "Inspect DNS publishing and cleanup, grouped by domain."],
  orders: ["ACME orders", null, "/activity/orders", "Inspect orders received through the HTTP-01 ACME endpoint."],
  activity: ["Activity", null, "/activity", "Search administrative and worker events."],
  about: ["About", null, "/about"],
  settings: ["Settings", null, "/settings", "Instance preferences and service configuration."],
};
function routeLink(label, path, className = "") {
  const link = node("a", className, label);
  link.href = path;
  link.dataset.route = "";
  return link;
}
function resourcePath(tab, id, suffix = "") {
  return tabs[tab][2] + "/" + encodeURIComponent(id) + suffix;
}
function renderMethods() {
  const list = $("method-list");
  for (const [tab, label, path] of [
    ["certificates", "Request certificate →", "/certificates/new"],
    ["acme", "Connect ACME client →", "/acme-endpoint"],
    ["clients", "Create gateway client →", "/dns-gateway/new"],
  ]) {
    const card = node("section", "panel method-card");
    card.append(node("h2", "", tabs[tab][0]), node("p", "", methodDescriptions[tab]), routeLink(label, path, tab === "certificates" ? "primary" : "secondary"));
    list.append(card);
  }
}
function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}
function clearFieldError(field) {
  const errorId = field.id + "-validation-error";
  $(errorId)?.remove();
  field.removeAttribute("aria-invalid");
  const descriptions = (field.getAttribute("aria-describedby") || "")
    .split(/\s+/)
    .filter((id) => id && id !== errorId);
  if (descriptions.length)
    field.setAttribute("aria-describedby", descriptions.join(" "));
  else field.removeAttribute("aria-describedby");
}
function showFieldError(field) {
  const errorId = field.id + "-validation-error";
  if (!$(errorId)) {
    const error = node("p", "error field-error");
    error.id = errorId;
    error.setAttribute("role", "alert");
    field.insertAdjacentElement("afterend", error);
    field.setAttribute(
      "aria-describedby",
      [field.getAttribute("aria-describedby"), errorId].filter(Boolean).join(" "),
    );
  }
  $(errorId).textContent = field.validationMessage;
  field.setAttribute("aria-invalid", "true");
}
document.querySelectorAll("form").forEach((form) => {
  // Keep native constraint checks, but render errors inside the dialog instead
  // of relying on the browser's transient validation popup.
  form.addEventListener("invalid", (event) => {
    event.preventDefault();
    showFieldError(event.target);
    if (event.target === form.querySelector(":invalid")) event.target.focus();
  }, true);
  const updateError = (event) => {
    const field = event.target;
    if (!field.hasAttribute("aria-invalid")) return;
    if (field.validity.valid) clearFieldError(field);
    else showFieldError(field);
  };
  form.addEventListener("input", updateError);
  form.addEventListener("change", updateError);
  form.addEventListener("reset", () => {
    form.querySelectorAll('[aria-invalid="true"]').forEach(clearFieldError);
  });
});
function action(label, handler, className = "subtle") {
  const el = node("button", className, label);
  el.type = "button";
  el.addEventListener("click", handler);
  return el;
}
function clearNotice() {
  clearTimeout(noticeTimer);
  $("notice").hidden = true;
  $("notice").textContent = "";
  $("notice").className = "";
}
function notify(message, error = false) {
  clearNotice();
  $("notice").textContent = message;
  $("notice").className = error ? "error" : "";
  $("notice").hidden = false;
  if (!error) noticeTimer = setTimeout(clearNotice, 5000);
}
async function api(path, method = "GET", body) {
  const session = token;
  const version = sessionVersion;
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
  if (version !== sessionVersion) throw new Error("Your session has ended. Sign in to continue.");
  if (!response.ok) {
    if (response.status === 401 && token === session) logout();
    throw new Error(result.error || "Request failed.");
  }
  return result;
}
async function refresh({ metadataOnly = false } = {}) {
  const session = sessionVersion;
  const request = ++overviewRequest;
  const result = await api("/overview");
  if (!token || session !== sessionVersion || request !== overviewRequest) return;
  data = result;
  renderProviders();
  renderClients();
  renderChallenges();
  renderOverview();
  renderCurrentDetail();
  updateCoverage();
  if (metadataOnly) return;
  const loads = [];
  if (["overview", "certificates"].includes(currentTab)) loads.push(refreshCertificates());
  if (["overview", "acme", "orders"].includes(currentTab)) loads.push(loadAcmeSettings());
  if ((currentTab === "activity" && activityBefore === null || currentTab === "settings") && !activityLoading)
    loads.push(loadActivity().catch(showActivityError));
  await Promise.all(loads);
}
function logout() {
  token = "";
  sessionVersion++;
  certificatesData = null;
  editorRoute = null;
  certificateSaving = false;
  clearNotice();
  clearInterval(refreshTimer);
  data = null;
  activityRequest++;
  acmeSettingsDirty = false;
  acmeSettingsData = null;
  acmeSettingsSaving = false;
  acmeClientRequestsOpen.clear();
  acmeClientRegistrationOpen.clear();
  $("acme-client-list").replaceChildren();
  $("acme-settings-save").disabled = true;
  $("acme-endpoint-status").textContent = "Loading…";
  $("acme-endpoint-status").className = "status";
  activityLoading = false;
  activityData = null;
  activityBefore = null;
  activityPrevious = [];
  activitySearch = "";
  activityRetentionDirty = false;
  $("activity-search-form").reset();
  $("activity-retention-form").reset();
  $("activity-status").textContent = "";
  $("activity-retention-error").textContent = "";
  ["provider-form", "certificate-form", "client-form", "acme-settings-form"].forEach(id => $(id).reset());
  $("detail-panel").replaceChildren();
  $("revoked-clients").open = false;
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
  sessionVersion++;
  token = $("admin-token").value.trim();
  try {
    await refresh({ metadataOnly: true });
    $("admin-token").value = "";
    $("login").hidden = true;
    $("workspace").hidden = false;
    navigate(location.pathname + location.search, "replace");
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
function resolveRoute(path) {
  const url = new URL(path, location.origin);
  let pathname = url.pathname.replace(/\/$/, "") || "/overview";
  pathname = ({ "/clients": "/dns-gateway", "/validations": "/activity/validations" })[pathname] || pathname;
  const tab = Object.keys(tabs).find(key => tabs[key][2] === pathname);
  if (tab) return { tab, view: "list", id: null, path: pathname + url.search };
  const acmeView = pathname === "/acme-endpoint/configuration" ? "settings" : Object.keys(acmePaths).find(view => acmePaths[view] === pathname);
  if (acmeView) return { tab: "acme", view: "list", acmeView, id: null, path: acmePaths[acmeView] + url.search };
  for (const key of ["providers", "certificates", "clients", "orders"]) {
    const prefix = tabs[key][2] + "/";
    if (!pathname.startsWith(prefix)) continue;
    const parts = pathname.slice(prefix.length).split("/");
    if (parts.length > 2 || parts.length === 2 && (key !== "providers" || parts[1] !== "edit")) break;
    let id;
    try { id = decodeURIComponent(parts[0]); } catch { break; }
    if (!id) break;
    return { tab: key, view: id === "new" && key !== "orders" ? "new" : parts.length === 2 ? "edit" : "detail", id: id === "new" ? null : id, path: pathname + url.search };
  }
  return { tab: "overview", view: "list", id: null, path: "/overview" };
}
function tabFromLocation() {
  return resolveRoute(location.pathname + location.search).tab;
}
function switchTab(tab, navigation = "push") {
  navigate(tabs[tab][2], navigation);
}
function setPageTitle(title) {
  $("page-title").textContent = title;
  document.title = title + " · ACME Proxy";
  const crumb = $("breadcrumb");
  crumb.replaceChildren(node("span", "", "Administration / "));
  if (currentView === "list") crumb.append(node("span", "", tabs[currentTab][0]));
  else crumb.append(routeLink(tabs[currentTab][0], tabs[currentTab][2]), node("span", "", " / " + title));
}
function navigate(path, navigation = "push") {
  const route = resolveRoute(path);
  const changed = currentPath !== route.path;
  if (changed && !$("notice").classList.contains("error")) clearNotice();
  if (navigation !== "none" && location.pathname + location.search !== route.path) {
    history[navigation === "replace" ? "replaceState" : "pushState"](null, "", route.path);
  }
  currentTab = route.tab;
  currentView = route.view;
  currentId = route.id;
  currentPath = route.path;
  currentAcmeView = route.acmeView || "connection";
  let title = tabs[currentTab][0];
  if (currentView === "new") title = ({ providers: "Connect DNS provider", certificates: "Request certificate", clients: "Create gateway client" })[currentTab];
  if (currentView === "edit") title = "Edit DNS provider";
  setPageTitle(title);
  $("page-description").textContent = tabs[currentTab][3] || "";
  $("page-description").hidden = !tabs[currentTab][3];
  $("acme-endpoint-status").hidden = currentTab !== "acme";
  renderAcmeTabs();
  $("add-button").hidden = currentView !== "list" || !tabs[currentTab][1];
  $("add-button").textContent = tabs[currentTab][1] || "";
  const backPath = currentView === "edit" && currentTab === "providers" ? resourcePath("providers", currentId) : tabs[currentTab][2];
  $("page-back").hidden = currentView === "list";
  $("page-back").href = backPath;
  $("page-back").dataset.route = "";
  $("page-back").textContent = "← " + (currentView === "edit" && currentTab === "providers" ? "Provider details" : tabs[currentTab][0]);
  let panel = currentTab + "-panel";
  if (currentView === "detail") panel = "detail-panel";
  if (["new", "edit"].includes(currentView)) panel = ({ providers: "provider", certificates: "certificate", clients: "client", acme: "acme" })[currentTab] + "-editor-panel";
  document.querySelectorAll(".content > section").forEach(section => { section.hidden = section.id !== panel; });
  $("activity-tabs").hidden = !["activity", "challenges", "orders"].includes(currentTab);
  document.querySelectorAll("[data-tab]").forEach(link => {
    const selected = link.dataset.tab === currentTab || link.closest("#main-navigation") && link.dataset.tab === "activity" && ["challenges", "orders"].includes(currentTab);
    link.classList.toggle("selected", selected);
    if (selected) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  document.querySelector("aside").classList.remove("menu-open");
  $("menu-toggle").setAttribute("aria-expanded", "false");
  if (data) {
    if (["new", "edit"].includes(currentView) && currentTab !== "acme" && editorRoute !== currentPath) {
      editorRoute = currentPath;
      if (currentTab === "providers") prepareProvider(data.providers.find(provider => provider.id === currentId));
      else {
        $(currentTab === "clients" ? "client-form" : "certificate-form").reset();
        $(currentTab === "clients" ? "client-error" : "certificate-error").textContent = "";
      }
    }
    renderCurrentDetail();
    renderChallenges();
    updateCoverage();
    if (["overview", "certificates"].includes(currentTab)) refreshCertificates().catch(error => notify(error.message, true));
    if (["overview", "acme", "orders"].includes(currentTab)) loadAcmeSettings().catch(error => notify(error.message, true));
    if (currentTab === "activity") {
      const search = new URL(currentPath, location.origin).searchParams.get("search") || "";
      $("activity-search").value = search;
      if (changed || !activityData) loadActivity(null, search, []).catch(showActivityError);
    }
    if (currentTab === "settings") loadActivity().catch(showActivityError);
  }
  if (changed && !$("workspace").hidden) {
    window.scrollTo(0, 0);
    $("page-title").focus({ preventScroll: true });
  }
}
document.addEventListener("click", event => {
  const cancel = event.target.closest("[data-cancel-editor]");
  if (cancel) { cancel.closest("form").reset(); editorRoute = null; navigate(tabs[currentTab][2]); return; }
  const link = event.target.closest("a[data-tab], a[data-route], aside .brand");
  if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  navigate(link.getAttribute("href"));
});
$("menu-toggle").onclick = () => {
  const open = document.querySelector("aside").classList.toggle("menu-open");
  $("menu-toggle").setAttribute("aria-expanded", String(open));
};
window.addEventListener("popstate", () => {
  document.querySelectorAll("dialog[open]").forEach(dialog => dialog.close());
  navigate(location.pathname + location.search, "none");
});
function renderAcmeTabs() {
  document.querySelectorAll("[data-acme-view]").forEach(tab => {
    const selected = tab.dataset.acmeView === currentAcmeView;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    $(tab.getAttribute("aria-controls")).hidden = !selected;
  });
}
const acmeViewTabs = Array.from(document.querySelectorAll("[data-acme-view]"));
acmeViewTabs.forEach((tab, index) => {
  tab.onclick = () => { navigate(acmePaths[tab.dataset.acmeView]); tab.focus({ preventScroll: true }); };
  tab.onkeydown = event => {
    const next = event.key === "ArrowRight" ? (index + 1) % acmeViewTabs.length
      : event.key === "ArrowLeft" ? (index + acmeViewTabs.length - 1) % acmeViewTabs.length
      : event.key === "Home" ? 0 : event.key === "End" ? acmeViewTabs.length - 1 : null;
    if (next === null) return;
    event.preventDefault();
    acmeViewTabs[next].click();
  };
});
renderMethods();
navigate(location.pathname + location.search, "replace");
$("add-button").onclick = () => {
  if (currentTab === "overview") navigate(tabs.methods[2]);
  else if (currentTab === "providers") openProvider();
  else if (currentTab === "certificates") openCertificate();
  else openClient();
};
$("refresh").onclick = async () => {
  const button = $("refresh");
  const status = $("refresh-status");
  button.disabled = true;
  button.textContent = "Refreshing…";
  status.textContent = "";
  status.className = "";
  try {
    await refresh();
    status.textContent = "Up to date.";
  } catch (e) {
    status.className = "error";
    status.textContent = "Refresh failed: " + e.message;
  } finally {
    button.disabled = false;
    button.textContent = "Refresh ↻";
  }
};
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
function empty(target, title, label, handler) {
  const el = node("div", "empty");
  el.append(node("strong", "", title));
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
  if (!data.providers.length) return empty(list, "Connect your first DNS provider", "+ Connect provider", () => openProvider());
  data.providers.forEach(provider => {
    const driver = data.drivers.find(item => item.id === provider.driver);
    const row = node("div", "row");
    const info = identity(provider.name, `${driver?.name || provider.driver} · ${provider.zone}`, provider.driver.replace("dns_", "").slice(0, 2).toUpperCase());
    info.querySelector(".row-title").replaceChildren(routeLink(provider.name, resourcePath("providers", provider.id)));
    const actions = node("div", "row-actions");
    actions.append(node("span", "status", "Configured"), routeLink("View details", resourcePath("providers", provider.id), "subtle"));
    row.append(info, actions);
    list.append(row);
  });
}
function removeProvider(provider) {
  confirm("Remove provider?", `Remove ${provider.name} from configuration. Outstanding challenges must be cleaned up first.`, async () => {
    await api("/providers/" + provider.id, "DELETE");
    navigate("/providers");
    await refresh();
    notify("Provider removed.");
  });
}
function renderClients() {
  const list = $("client-list"), revokedList = $("revoked-client-list");
  list.replaceChildren();
  revokedList.replaceChildren();
  const revokedCount = data.clients.filter(client => client.revoked).length;
  $("revoked-client-count").textContent = revokedCount;
  $("revoked-clients").hidden = !revokedCount;
  if (!revokedCount) $("revoked-clients").open = false;
  if (!data.clients.some(client => !client.revoked)) empty(list, "No active gateway clients", "+ Create gateway client", openClient);
  data.clients.forEach(client => {
    const row = node("div", "row"), info = identity(client.name, client.scopes.join(" · "));
    info.querySelector(".row-title").replaceChildren(routeLink(client.name, resourcePath("clients", client.id)));
    const actions = node("div", "row-actions");
    actions.append(node("span", "status " + (client.revoked ? "" : "active"), client.revoked ? "Revoked" : "Active"), routeLink("View details", resourcePath("clients", client.id), "subtle"));
    row.append(info, actions);
    (client.revoked ? revokedList : list).append(row);
  });
}
function revokeClient(client) {
  confirm("Revoke client?", `${client.name} will lose access immediately. Its outstanding challenges will be queued for cleanup.`, async () => {
    await api("/clients/" + client.id, "DELETE");
    await refresh();
    notify("Client revoked. Cleanup has been queued.");
  });
}
function deleteClient(client) {
  confirm("Permanently delete client?", `Delete ${client.name} and its DNS validation history permanently. This cannot be undone. Any outstanding DNS records must be cleaned up first.`, async () => {
    await api("/clients/" + client.id + "/permanent", "DELETE");
    navigate("/dns-gateway");
    await refresh();
    notify("Client permanently deleted.");
  });
}
const statusText = {
  active: "TXT value published",
  present_pending: "Publishing TXT value",
  cleanup_pending: "Removing TXT value",
  cleaned: "TXT value removed",
  failed: "Failed",
};
function validationTime(challenge) {
  const date = new Date(challenge.updated_at * 1000);
  const time = node("time", "validation-time", `Last Event: ${date.toLocaleString()}`);
  time.dateTime = date.toISOString();
  return time;
}
function renderChallenges() {
  const list = $("challenge-list");
  const expanded = new Set(
    [...list.querySelectorAll("details[open]")].map((detail) => detail.dataset.domain),
  );
  list.replaceChildren();
  const filter = new URL(currentPath, location.origin).searchParams.get("domain");
  const challengesToShow = filter ? data.challenges.filter(challenge => challenge.fqdn.replace(/^_acme-challenge\./i, "") === filter) : data.challenges;
  $("challenge-filter").hidden = !filter;
  $("challenge-filter").replaceChildren();
  if (filter) $("challenge-filter").append(node("span", "", "Domain: " + filter), routeLink("Show all validations", "/activity/validations"));
  if (!challengesToShow.length) return empty(list, filter ? "No retained DNS validations for this domain" : "No DNS validations yet");
  const domains = new Map();
  [...challengesToShow]
    .sort((a, b) => b.updated_at - a.updated_at)
    .forEach((challenge) => {
      const domain = challenge.fqdn.replace(/^_acme-challenge\./i, "");
      if (!domains.has(domain)) domains.set(domain, []);
      domains.get(domain).push(challenge);
    });
  domains.forEach((challenges, domain) => {
    const single = challenges.length === 1;
    const group = node("section", "certificate-domain");
    group.setAttribute("aria-label", domain);
    const disclosure = node("details", "validation-disclosure");
    disclosure.dataset.domain = domain;
    disclosure.open = expanded.has(domain);
    const summary = node("summary", "validation-summary");
    summary.append(node("h3", "", domain));
    const meta = node("div", "validation-summary-meta");
    if (!single) meta.append(node("span", "badge", `${challenges.length} validations`));
    const failures = challenges.filter((c) => c.state === "failed").length;
    if (failures) meta.append(node("span", "status failed", `${failures} failed`));
    meta.append(validationTime(challenges[0]));
    summary.append(meta);
    disclosure.append(summary);
    const record = node("p", "certificate-record", "DNS record (TXT): ");
    record.append(node("code", "", challenges[0].fqdn));
    disclosure.append(record);
    group.append(disclosure);
    challenges.forEach((c) => {
      const row = node("div", "row");
      const info = node("div", "certificate-info");
      const driver = data.drivers.find((d) => d.id === c.provider_driver);
      const provider = [c.provider_name, driver?.name || c.provider_driver]
        .filter(Boolean).join(" · ") || "Unknown";
      const details = node("dl", "certificate-details");
      for (const [label, value] of [
        ["Client name", c.client_name],
        ["DNS provider", provider],
      ]) {
        const detail = node("div");
        detail.append(node("dt", "", label + ":"), node("dd", "", value));
        details.append(detail);
      }
      info.append(details);
      if (c.last_error) info.append(node("p", "error", c.last_error));
      row.append(info);
      const buttons = node("div", "row-actions");
      if (!single) buttons.append(validationTime(c));
      const status = node("span", "status " + c.state,
        c.state === "failed"
          ? (c.operation === "cleanup" ? "TXT removal failed" : "TXT publishing failed")
          : statusText[c.state]);
      if (c.state === "active") status.title = "The DNS adapter succeeded; records may still be propagating.";
      if (c.state === "cleaned") status.title = "The temporary validation TXT value was removed. Other DNS records are unchanged.";
      buttons.append(status);
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
      disclosure.append(row);
    });
    list.append(group);
  });
}
function showActivityError(error) {
  $("activity-status").className = "error";
  $("activity-status").textContent = error.message;
  if (currentTab === "settings") $("activity-retention-error").textContent = error.message;
}
function activityControls() {
  $("activity-retention-form").querySelector("button").disabled = activityLoading || activitySaving || !activityData;
  $("activity-refresh").disabled = activityLoading;
  $("activity-older").disabled = activityLoading || !activityData?.next_before;
  $("activity-newer").disabled = activityLoading || !activityPrevious.length;
  $("activity-latest").disabled = activityLoading || activityBefore === null;
}
async function loadActivity(before = activityBefore, search = activitySearch, previous = activityPrevious) {
  const request = ++activityRequest;
  const session = sessionVersion;
  activityLoading = true;
  activityControls();
  try {
    const query = new URLSearchParams({ search });
    if (before !== null) query.set("before", before);
    const result = await api("/activity?" + query);
    if (request !== activityRequest || session !== sessionVersion || !token) return;
    const moved = before !== activityBefore || search !== activitySearch;
    activityData = result;
    if (!activityRetentionDirty) $("activity-retention-error").textContent = "";
    if ($("activity-status").classList.contains("error")) {
      $("activity-status").className = "";
      $("activity-status").textContent = "";
    }
    activityBefore = before;
    activitySearch = search;
    activityPrevious = previous;
    if (!activityRetentionDirty) $("activity-retention").value = result.retention;
    renderAudit();
    if (moved) $("activity-table").scrollTop = 0;
  } finally {
    if (request === activityRequest) {
      activityLoading = false;
      activityControls();
    }
  }
}
function renderAudit() {
  const list = $("audit-list");
  list.replaceChildren();
  const events = activityData.events;
  $("activity-table").hidden = !events.length;
  $("activity-empty").hidden = !!events.length;
  $("activity-empty").textContent = activitySearch
    ? "No matching events"
    : activityBefore !== null ? "These older events are no longer retained. Select Latest." : "No events yet";
  $("activity-count").textContent = `${activityData.stored.toLocaleString()} events stored · Page ${activityPrevious.length + 1}`;
  events.forEach((event) => {
    const row = node("tr");
    const date = new Date(event.at * 1000);
    const timeCell = node("td");
    const time = node("time", "", date.toLocaleString());
    time.dateTime = date.toISOString();
    timeCell.append(time);
    row.append(timeCell);
    for (const key of ["action", "actor", "target", "outcome"])
      row.append(node("td", "", event[key]));
    list.append(row);
  });
}
$("activity-refresh").onclick = async () => {
  const button = $("activity-refresh");
  button.textContent = "Refreshing…";
  $("activity-status").className = "";
  $("activity-status").textContent = "";
  try {
    await loadActivity();
    $("activity-status").textContent = "Up to date.";
  } catch (error) {
    showActivityError(error);
  } finally {
    button.textContent = "Refresh ↻";
  }
};
$("activity-older").onclick = () => loadActivity(
  activityData.next_before, activitySearch, [...activityPrevious, activityBefore],
).catch(showActivityError);
$("activity-newer").onclick = () => loadActivity(
  activityPrevious.at(-1), activitySearch, activityPrevious.slice(0, -1),
).catch(showActivityError);
$("activity-latest").onclick = () => loadActivity(null, activitySearch, []).catch(showActivityError);
$("activity-search-form").onsubmit = (event) => {
  event.preventDefault();
  const search = $("activity-search").value.trim();
  const path = "/activity" + (search ? "?search=" + encodeURIComponent(search) : "");
  if (path === currentPath) loadActivity(null, search, []).catch(showActivityError);
  else navigate(path);
};
$("activity-retention").addEventListener("input", () => { activityRetentionDirty = true; });
$("activity-retention-form").onsubmit = async (event) => {
  event.preventDefault();
  const retention = Number($("activity-retention").value);
  const save = async () => {
    activitySaving = true;
    activityControls();
    try {
      await api("/activity/retention", "PUT", { retention });
      activityRetentionDirty = false;
      await loadActivity(null, activitySearch, []);
      notify(`Activity log now keeps the last ${retention.toLocaleString()} events.`);
    } finally {
      activitySaving = false;
      activityControls();
    }
  };
  if (activityData && retention < activityData.retention) {
    confirm("Reduce event retention?",
      `Keep only the newest ${retention.toLocaleString()} events. Older events will be permanently deleted.`, save);
  } else {
    try { await save(); } catch (error) { showActivityError(error); }
  }
};
function openProvider(provider) {
  navigate(provider ? resourcePath("providers", provider.id, "/edit") : "/providers/new");
}
function prepareProvider(provider) {
  $("provider-form").reset();
  $("provider-error").textContent = "";
  $("provider-id").value = provider?.id || "";

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
    const result = await api("/providers" + (id ? "/" + id : ""), id ? "PUT" : "POST", {
      name: $("provider-name").value.trim(),
      driver: $("provider-driver").value,
      zone: $("provider-zone").value.trim(),
      credentials,
    });
    $("provider-form").reset();
    editorRoute = null;
    await refresh();
    navigate(resourcePath("providers", result.id));
    notify("Provider saved.");
  } catch (e) {
    $("provider-error").textContent = e.message;
  } finally {
    button.disabled = false;
  }
};
function openClient() {
  navigate("/dns-gateway/new");
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
    $("new-client-id").value = result.id;
    $("new-client-token").value = result.token;
    $("client-example").value =
      `export ACMEPROXY_ENDPOINT='${location.origin}'\nexport ACMEPROXY_USERNAME='${result.id}'\nexport ACMEPROXY_PASSWORD='${result.token}'`;
    $("client-form").reset();
    $("token-dialog").showModal();
    await refresh().catch(error => notify(error.message, true));
    navigate(resourcePath("clients", result.id));
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

fetch("/healthz")
  .then((response) => response.ok ? response.json() : null)
  .then((health) => {
    if (!health) return;
    const version = health.display_version || `v${health.version}`;
    $("app-version").textContent = version;
    $("about-version").textContent = version;
    if (health.version_url) {
      $("app-version").href = health.version_url;
      $("app-version").title = health.release ? "View release on GitHub" : "View commit on GitHub";
    } else {
      $("app-version").removeAttribute("href");
      $("app-version").title = "Build commit unavailable";
    }
    const revision = /^[a-f0-9]{40}$/.test(health.revision || "") ? health.revision : null;
    if (revision) {
      const commit = node("a", "", revision.slice(0, 7));
      commit.href = `https://github.com/alextac98/acmeproxy/commit/${revision}`;
      commit.target = "_blank";
      commit.rel = "noreferrer";
      $("about-build").replaceChildren(commit);
    } else {
      $("about-build").textContent = "Local build";
    }

  })
  .catch(() => {});

function openCertificate() {
  navigate("/certificates/new");
}
$("certificate-form").onsubmit = async (event) => {
  event.preventDefault();
  const button = event.submitter;
  certificateSaving = true;
  button.disabled = true;
  $("certificate-error").textContent = "";
  try {
    const result = await api("/certificates", "POST", {
      domains: $("certificate-domains").value.split(/\n/).map(s => s.trim()).filter(Boolean),
      staging: $("certificate-environment").value === "staging",
      terms_agreed: $("certificate-terms").checked,
    });
    $("certificate-form").reset();
    await refreshCertificates();
    navigate(resourcePath("certificates", result.id));
    notify("Certificate requested. DNS validation and issuance will run automatically.");
  } catch (error) {
    $("certificate-error").textContent = error.message;
  } finally {
    certificateSaving = false;
    button.disabled = false;
  }
};
async function downloadCertificate(id, file) {
  const session = sessionVersion;
  try {
    const response = await fetch(`/api/admin/certificates/${id}/${file}`, { headers: { Authorization: "Bearer " + token } });
    if (!response.ok) {
      if (response.status === 401) logout();
      throw new Error((await response.json()).error || "Download failed.");
    }
    const blob = await response.blob();
    if (!token || session !== sessionVersion) return;
    const url = URL.createObjectURL(blob);
    const link = node("a");
    link.href = url;
    link.download = file;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { notify(error.message, true); }
}
function certificateStatus(cert) {
  if (cert.expires_at && cert.expires_at <= Date.now() / 1000) return ["Expired", "failed"];
  if (cert.downloadable && cert.last_error) return ["Renewal failed", "failed"];
  if (cert.state === "failed") return ["Issuance failed", "failed"];
  if (cert.state === "issued") return ["Valid", "active"];
  return [cert.state === "issuing" ? "Issuing" : "Queued", "present_pending"];
}
function formatDate(value) {
  return value ? new Date(value * 1000).toLocaleString() : "Not scheduled";
}
function renderCertificateTable(target, certificates, summary = false) {
  target.replaceChildren();
  if (!certificates.length) return empty(target, "No managed certificates yet", "Request certificate", openCertificate);
  const table = node("table", "resource-table");
  table.setAttribute("aria-label", "Managed certificates");
  const head = node("thead"), headRow = node("tr");
  const columns = ["Domains", "Status", "Valid until", "Action"];
  columns.forEach(label => { const th = node("th", "", label); th.scope = "col"; headRow.append(th); });
  head.append(headRow);
  const body = node("tbody");
  for (const cert of summary ? certificates.slice(0, 5) : certificates) {
    const row = node("tr");
    const cells = columns.map(label => { const cell = node("td"); cell.dataset.label = label; row.append(cell); return cell; });
    cells[0].append(routeLink(cert.domains[0], resourcePath("certificates", cert.id)));
    if (cert.domains.length > 1) cells[0].append(node("small", "", cert.domains.slice(1).join(", ")));
    cells[0].append(node("small", cert.staging ? "staging-label" : "", cert.staging ? "Staging · not browser trusted" : "Production · Let's Encrypt"));
    const [status, tone] = certificateStatus(cert);
    cells[1].append(node("span", "status " + tone, status));
    if (!cert.auto_renew) cells[1].append(node("small", "", "Renewal paused"));
    cells[2].append(node("span", "", cert.expires_at ? new Date(cert.expires_at * 1000).toLocaleDateString() : "Not issued"));
    if (cert.expires_at > Date.now() / 1000) cells[2].append(node("small", "", `${Math.ceil((cert.expires_at - Date.now() / 1000) / 86400)} days remaining`));
    cells[3].append(routeLink("View details", resourcePath("certificates", cert.id), "subtle"));
    body.append(row);
  }
  table.append(head, body);
  target.append(table);
}
async function refreshCertificates() {
  const session = sessionVersion;
  const request = ++certificatesRequest;
  const result = await api("/certificates");
  if (!token || session !== sessionVersion || request !== certificatesRequest) return;
  certificatesData = result;
  renderCertificateTable($("certificate-list"), result);
  renderOverview();
  renderCurrentDetail();
}
function providerFor(domain) {
  const host = domain.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  return [...(data?.providers || [])].sort((a, b) => b.zone.length - a.zone.length).find(provider => host === provider.zone.toLowerCase() || host.endsWith("." + provider.zone.toLowerCase()));
}
function updateCoverage() {
  if (!data) return;
  const form = $("certificate-form");
  let hint = $("certificate-coverage");
  if (!hint) { hint = node("p", "hint"); hint.id = "certificate-coverage"; hint.setAttribute("role", "status"); $("certificate-domains").insertAdjacentElement("afterend", hint); }
  const domains = $("certificate-domains").value.split(/\s+/).filter(Boolean);
  const missing = domains.filter(domain => !providerFor(domain));
  hint.replaceChildren();
  if (!data.providers.length) hint.append(node("span", "", "Connect a DNS provider before requesting a certificate. "), routeLink("Connect provider →", "/providers/new"));
  else if (missing.length) hint.textContent = "Missing DNS provider coverage: " + missing.join(", ");
  else if (domains.length) hint.textContent = "DNS provider coverage is configured for these domains.";
  hint.hidden = !hint.textContent;
  form.querySelector('button[type="submit"]').disabled = certificateSaving || !data.providers.length;
}
$("certificate-domains").addEventListener("input", updateCoverage);
function detailSection(title, ...children) {
  const section = node("section", "panel settings-card");
  section.append(node("h2", "", title), ...children);
  return section;
}
function keyValues(entries) {
  const list = node("dl", "detail-values");
  entries.forEach(([label, value]) => {
    list.append(node("dt", "", label));
    const entry = node("dd");
    entry.append(value instanceof Node ? value : node("span", "", value));
    list.append(entry);
  });
  return list;
}
function renderCurrentDetail() {
  if (!data) return;
  if (currentTab === "providers" && currentView === "edit" && !data.providers.some(provider => provider.id === currentId)) {
    $("provider-editor-panel").hidden = true;
    $("detail-panel").hidden = false;
    setPageTitle("Provider unavailable");
    $("detail-panel").replaceChildren(node("p", "empty", "This provider is no longer available. Return to DNS providers to continue."));
    return;
  }
  if (currentView !== "detail") return;
  const target = $("detail-panel");
  const opened = new Set([...target.querySelectorAll("details[open]")].map(detail => detail.dataset.section));
  target.replaceChildren();
  let record;
  if (currentTab === "certificates") record = certificatesData?.find(cert => cert.id === currentId);
  if (currentTab === "providers") record = data.providers.find(provider => provider.id === currentId);
  if (currentTab === "clients") record = data.clients.find(client => client.id === currentId);
  if (currentTab === "orders") record = acmeSettingsData?.orders.find(order => order.id === currentId);
  if (!record) {
    const loading = currentTab === "certificates" && !certificatesData || currentTab === "orders" && !acmeSettingsData;
    setPageTitle(loading ? "Loading details…" : "Resource unavailable");
    target.append(node("p", "empty", loading ? "Loading…" : "This resource is no longer available. Return to the list to continue."));
    return;
  }
  setPageTitle(record.name || record.domains.join(", "));
  if (currentTab === "certificates") {
    const [status, tone] = certificateStatus(record);
    const statusPanel = detailSection("Certificate status", node("span", "status " + tone, status));
    statusPanel.append(keyValues([
      ["Certificate type", record.staging ? "Let's Encrypt staging · Test certificate (not browser trusted)" : "Let's Encrypt production · Trusted certificate"],
      ["Current certificate", record.downloadable ? record.expires_at <= Date.now() / 1000 ? "Expired" : "Available · valid until " + formatDate(record.expires_at) : "Not issued"],
      ["Issuance phase", record.phase || record.state],
      ["Automatic renewal", record.auto_renew ? "On" : "Off"],
      ...(record.auto_renew && record.state === "issued" && record.renew_at ? [["Renewal scheduled", formatDate(record.renew_at)]] : []),
      ...(record.next_attempt && record.last_error && record.auto_renew ? [["Next attempt", formatDate(record.next_attempt)]] : []),
    ]));
    if (record.last_error) {
      statusPanel.append(node("p", "error", record.last_error));
      if (record.downloadable && record.expires_at > Date.now() / 1000) statusPanel.append(node("p", "hint", "Renewal failed; the current certificate is still valid and can be downloaded."));
    }
    const actions = node("div", "detail-actions");
    if (record.downloadable) actions.append(action("Download files", () => openDownloads(record.id), "primary"));
    if (record.state === "failed") actions.append(action("Retry renewal / issuance", async () => {
      try { await api(`/certificates/${record.id}/retry`, "POST"); await refreshCertificates(); } catch (error) { notify(error.message, true); }
    }, "secondary"));
    actions.append(action(record.auto_renew ? "Pause renewal" : "Enable renewal", async () => {
      try { await api(`/certificates/${record.id}`, "PUT", { auto_renew: !record.auto_renew }); await refreshCertificates(); } catch (error) { notify(error.message, true); }
    }, "secondary"));
    statusPanel.append(actions);
    target.append(statusPanel);
    const domains = node("div", "domain-coverage");
    record.domains.forEach(domain => {
      const provider = providerFor(domain), row = node("div", "row");
      row.append(node("span", "", domain), provider ? routeLink(provider.name, resourcePath("providers", provider.id)) : node("span", "error", "Missing DNS provider coverage"));
      domains.append(row);
    });
    target.append(detailSection("DNS provider coverage", domains, node("p", "hint", "Provider configuration does not establish live DNS provider health.")));
    const activityLinks = node("div", "detail-actions");
    record.domains.forEach(domain => activityLinks.append(routeLink("DNS validations for " + domain, "/activity/validations?domain=" + encodeURIComponent(domain.replace(/^\*\./, "")))));
    target.append(detailSection("Related activity", node("p", "hint", "These views show retained DNS validations for the domain, which may include other clients or certificate attempts."), activityLinks));
    target.append(node("p", "hint", "Renewal updates the files stored here. Download or retrieve them through the admin API and install them on your services."));
    if (record.state !== "issuing") {
      const advanced = node("details", "panel advanced-settings");
      advanced.dataset.section = "advanced";
      advanced.open = opened.has("advanced");
      advanced.append(node("summary", "", "Advanced"));
      const body = node("div", "settings-card");
      body.append(node("p", "muted", "Remove this certificate and its stored private key after DNS cleanup."), action("Remove certificate", () => confirm("Remove certificate?", "Delete this stored certificate and key and stop future renewals. Existing downloaded copies remain valid; this does not revoke the certificate.", async () => {
        await api(`/certificates/${record.id}`, "DELETE");
        navigate("/certificates");
        await refreshCertificates();
        notify("Certificate removed.");
      }), "danger"));
      advanced.append(body);
      target.append(advanced);
    }
  } else if (currentTab === "providers") {
    const driver = data.drivers.find(item => item.id === record.driver);
    const actions = node("div", "detail-actions");
    actions.append(routeLink("Edit provider", resourcePath("providers", record.id, "/edit"), "primary"));
    target.append(detailSection("Provider connection", keyValues([["DNS provider", driver?.name || record.driver], ["Zone coverage", record.zone], ["Credentials", "Configured · saved values are hidden"]]), node("p", "hint", "Configured credentials have not been checked for live DNS provider health."), actions));
    target.append(detailSection("Remove connection", node("p", "muted", "Outstanding challenges must be cleaned up before removing a provider. Existing challenges retain their original credential snapshots."), action("Remove provider", () => removeProvider(record), "danger")));
  } else if (currentTab === "clients") {
    target.append(detailSection("Gateway client", keyValues([["Status", record.revoked ? "Revoked" : "Active"], ["Client ID", record.id], ["Allowed domains", record.scopes.join(", ")]])));
    if (!record.revoked) {
      const command = node("textarea");
      command.id = "gateway-client-command";
      command.readOnly = true;
      command.rows = 5;
      command.value = `export ACMEPROXY_ENDPOINT='${location.origin}'\nexport ACMEPROXY_USERNAME='${record.id}'\nexport ACMEPROXY_PASSWORD='<YOUR_SAVED_TOKEN>'`;
      const label = node("label", "", "acme.sh environment"); label.htmlFor = command.id;
      target.append(detailSection("Connection instructions", node("p", "hint", "Use the token you saved when this client was created. Tokens are shown only once and cannot be retrieved here."), label, command, node("p", "hint", "Use --dns dns_acmeproxy with acme.sh. Other compatible clients can use HTTP Basic authentication with this client ID and its saved token. Keep the client's renewal timer enabled.")));
    }
    target.append(detailSection(record.revoked ? "Permanent deletion" : "Revoke access", node("p", "muted", record.revoked ? "Permanently delete this client and its validation history after DNS cleanup." : "Revocation immediately disables this client and queues cleanup of outstanding DNS validations."), action(record.revoked ? "Delete client" : "Revoke client", () => record.revoked ? deleteClient(record) : revokeClient(record), "danger")));
  } else if (currentTab === "orders") {
    target.append(detailSection("ACME order", keyValues([["Order ID", record.id], ["Client ID", record.account_id], ["State", record.state], ["Phase", record.phase], ["Certificate type", record.staging ? "Staging · not browser trusted" : "Production"], ["Created", formatDate(record.created_at)]])));
    const [label, status] = acmeCertificateStatus(record);
    target.append(detailSection("Certificate", node("span", "status " + status, label), acmeCertificateExpiry(record)));
    if (record.error) target.append(detailSection("Order error", node("p", "error", record.error)));
    target.append(node("p", "hint", "The ACME client keeps the private key and controls renewal. Inspect or retry the request from that client."));
  }
}
function openDownloads(id) {
  const target = $("download-options");
  target.replaceChildren();
  for (const [label, file] of [["Certificate chain", "fullchain.pem"], ["Private key", "privkey.pem"], ["PEM bundle", "bundle.pem"]]) target.append(action(label, () => downloadCertificate(id, file), "secondary"));
  $("download-dialog").showModal();
}
function renderOverview() {
  if (!data) return;
  const fresh = !data.providers.length && !data.clients.length && !certificatesData?.length;
  $("setup-guide").hidden = !fresh;
  $("overview-certificates-panel").hidden = fresh;
  if (certificatesData) {
    renderCertificateTable($("overview-certificate-list"), certificatesData, true);
    if (currentTab === "overview") $("page-description").textContent = `${certificatesData.length} managed certificate${certificatesData.length === 1 ? "" : "s"} · ${data.clients.filter(client => !client.revoked).length} active gateway clients`;
  }
  const attention = $("overview-attention"); attention.replaceChildren();
  for (const cert of certificatesData || []) {
    const [status] = certificateStatus(cert);
    if (!cert.last_error && status !== "Expired") continue;
    const card = node("section", "attention");
    const text = node("div");
    text.append(node("h2", "", cert.domains[0] + " needs attention"), node("p", "", cert.last_error || "The current certificate has expired."));
    if (cert.downloadable && cert.expires_at > Date.now() / 1000) text.append(node("p", "hint", "The current certificate is still valid until " + formatDate(cert.expires_at) + "."));
    card.append(text, routeLink("Review issue", resourcePath("certificates", cert.id), "secondary"));
    attention.append(card);
  }
  if (data.failed) {
    const card = node("section", "attention");
    card.append(node("p", "", `${data.failed} DNS validation${data.failed === 1 ? "" : "s"} need attention.`), routeLink("Inspect DNS validations", "/activity/validations", "secondary"));
    attention.append(card);
  }
  const connections = $("overview-connections"); connections.replaceChildren();
  for (const [title, description, path] of [
    ["DNS providers", `${data.providers.length} configured`, "/providers"],
    ["DNS gateway clients", `${data.clients.filter(client => !client.revoked).length} active · client-managed renewal`, "/dns-gateway"],
    ["ACME endpoint", acmeSettingsData ? acmeSettingsData.settings.mode === "disabled" ? "Disabled" : "HTTP-01 · enabled" : "Loading endpoint status…", "/acme-endpoint"],
  ]) { const row = node("div", "row"); row.append(identity(title, description), routeLink("Open", path, "subtle")); connections.append(row); }
  const events = $("overview-activity"); events.replaceChildren();
  if (!data.audit.length) empty(events, "No events yet");
  data.audit.slice(0, 4).forEach(event => { const row = node("div", "row"); row.append(identity(event.action, `${event.target} · ${formatDate(event.at)}`)); events.append(row); });
}

function acmeCertificateStatus(order) {
  if (order.state === "valid") {
    if (order.revoked) return ["Revoked", "failed"];
    if (Number.isFinite(order.certificate_expires_at))
      return order.certificate_expires_at <= Date.now() / 1000 ? ["Expired", "failed"] : ["Valid", "active"];
    return ["Issued", "active"];
  }
  return ({ invalid: ["Failed", "failed"], processing: ["Issuing", "present_pending"], ready: ["Awaiting CSR", "present_pending"], pending: ["Verifying HTTP-01", "present_pending"] })[order.state] || [order.state, ""];
}
function acmeCertificateExpiry(order) {
  if (order.state !== "valid") return node("p", "acme-expiry muted", order.state === "invalid" ? "No certificate issued" : "Certificate not issued yet");
  const expires = order.certificate_expires_at;
  if (!Number.isFinite(expires)) return node("p", "acme-expiry muted", "Expiry unavailable");
  const remaining = expires - Date.now() / 1000;
  const expired = remaining <= 0;
  const date = new Date(expires * 1000);
  const time = node("time", "", date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }));
  time.dateTime = date.toISOString();
  time.title = date.toLocaleString();
  const days = expired ? Math.floor(-remaining / 86400) : Math.ceil(remaining / 86400);
  const relative = expired ? days ? `${days} ${days === 1 ? "day" : "days"} ago` : "less than a day ago" : `${days} ${days === 1 ? "day" : "days"} remaining`;
  const line = node("p", "acme-expiry" + (expired ? " error" : ""), expired ? "Expired " : "Expires ");
  line.append(time, document.createTextNode(" · " + relative));
  return line;
}
function renderAcmeClients(result) {
  const list = $("acme-client-list");
  const focusId = list.contains(document.activeElement) ? document.activeElement.id : null;
  list.replaceChildren();
  $("acme-client-count").textContent = result.accounts.length;
  if (!result.accounts.length) return empty(list, "No registered clients yet. Point an ACME client at the directory URL on the Connection tab to register.");
  const head = node("div", "acme-client-head");
  head.setAttribute("aria-hidden", "true");
  ["Client", "Registration", "Requests"].forEach(label => head.append(node("span", "", label)));
  list.append(head);
  const ordersByClient = new Map();
  result.orders.forEach(order => {
    if (!ordersByClient.has(order.account_id)) ordersByClient.set(order.account_id, []);
    ordersByClient.get(order.account_id).push(order);
  });
  result.accounts.forEach(client => {
    const contacts = client.contact.map(contact => contact.replace(/^mailto:/i, ""));
    const name = contacts.join(", ") || "Client " + client.id.slice(0, 8);
    const orders = ordersByClient.get(client.id) || [];
    const item = node("article", "acme-client");
    item.setAttribute("aria-label", name);
    const row = node("div", "acme-client-row");
    const info = node("div", "acme-client-identity");
    info.append(node("strong", "", name), node("span", "row-subtitle", "Registered " + formatDate(client.created_at)));
    const registrationStatus = node("div", "acme-client-status");
    registrationStatus.append(node("span", "status " + (client.status === "deactivated" ? "" : "active"), client.status === "deactivated" ? "Deactivated" : "Registered"));
    const requests = node("section", "acme-client-requests");
    requests.id = "acme-client-requests-" + client.id;
    requests.setAttribute("aria-label", "Recent certificate requests for " + name);
    requests.hidden = !acmeClientRequestsOpen.has(client.id);
    const actions = node("div", "acme-client-actions");
    const toggle = action(requests.hidden ? "View requests ↓" : "Hide requests ↑", () => {
      requests.hidden = !requests.hidden;
      if (requests.hidden) acmeClientRequestsOpen.delete(client.id);
      else acmeClientRequestsOpen.add(client.id);
      toggle.textContent = requests.hidden ? "View requests ↓" : "Hide requests ↑";
      toggle.setAttribute("aria-expanded", String(!requests.hidden));
    });
    toggle.id = "acme-client-toggle-" + client.id;
    toggle.setAttribute("aria-controls", requests.id);
    toggle.setAttribute("aria-expanded", String(!requests.hidden));
    actions.append(node("span", "row-subtitle", `${orders.length} recent ${orders.length === 1 ? "request" : "requests"}`), toggle);
    row.append(info, registrationStatus, actions);
    requests.append(node("h3", "", "Recent certificate requests"));
    if (!orders.length) requests.append(node("p", "muted", "No recent requests for this client."));
    orders.forEach(order => {
      const request = node("div", "acme-client-request");
      const details = node("div", "acme-request-info");
      details.append(routeLink(order.domains.join(", "), resourcePath("orders", order.id)), node("span", "row-subtitle", `Requested ${formatDate(order.created_at)} · ${order.staging ? "Staging" : "Production"}`), acmeCertificateExpiry(order));
      const [label, status] = acmeCertificateStatus(order);
      request.append(details, node("span", "status " + status, label));
      if (order.phase && !["valid", "invalid"].includes(order.state)) details.append(node("p", "hint", order.phase));
      if (order.error) request.append(node("p", "error acme-request-error", order.error));
      requests.append(request);
    });
    const registration = node("details", "acme-registration");
    registration.open = acmeClientRegistrationOpen.has(client.id);
    const summary = node("summary", "", "Registration details");
    summary.id = "acme-client-registration-" + client.id;
    const values = node("dl", "acme-registration-values");
    for (const [label, value] of [["Client ID", client.id], ["Contact", contacts.join(", ") || "Not provided"], ["Key fingerprint", client.thumbprint]]) {
      values.append(node("dt", "", label), node("dd", "", value));
    }
    registration.append(summary, values);
    registration.addEventListener("toggle", () => {
      // Ignore queued toggle events from rows replaced by a refresh.
      if (!registration.isConnected) return;
      if (registration.open) acmeClientRegistrationOpen.add(client.id);
      else acmeClientRegistrationOpen.delete(client.id);
    });
    item.append(row, requests, registration);
    list.append(item);
  });
  if (focusId) $(focusId)?.focus({ preventScroll: true });
}
function acmeModeHelp() {
  const mode = $("acme-mode").value;
  $("acme-mode-help").textContent = mode === "disabled" ? "The ACME endpoint is unavailable. Existing DNS gateway clients and managed certificates continue to work." : "Every requested hostname must pass HTTP-01 verification before issuance. Clients register automatically; no gateway token is needed.";
  $("acme-base-url").required = mode !== "disabled";
  $("acme-terms").required = mode !== "disabled";
}
$("acme-settings-form").addEventListener("input", () => { acmeSettingsDirty = true; });
$("acme-settings-form").addEventListener("change", () => { acmeSettingsDirty = true; acmeModeHelp(); });
async function loadAcmeSettings() {
  const session = sessionVersion;
  const request = ++acmeRequest;
  const result = await api("/acme/settings");
  if (!token || session !== sessionVersion || request !== acmeRequest) return;
  acmeSettingsData = result;
  $("acme-settings-save").disabled = acmeSettingsSaving;
  const settings = result.settings;
  $("acme-endpoint-status").textContent = settings.mode === "disabled" ? "Disabled" : "Enabled";
  $("acme-endpoint-status").className = "status" + (settings.mode === "disabled" ? "" : " active");
  if (!acmeSettingsDirty) {
    $("acme-mode").value = settings.mode;
    $("acme-base-url").value = settings.base_url || location.origin;
    $("acme-networks").value = settings.allowed_networks.join("\n");
    $("acme-validation-networks").value = settings.validation_networks.join("\n");
    $("acme-domains").value = settings.allowed_domains.join("\n");
    $("acme-environment").value = settings.staging ? "staging" : "production";
    $("acme-terms").checked = settings.terms_agreed;
    acmeModeHelp();
  }
  const directory = settings.base_url ? settings.base_url + "/acme/directory" : "";
  $("acme-directory-url").value = directory;
  $("acme-connection-status").textContent = settings.mode === "disabled" ? "Save an enabled access mode to accept ACME clients." : `${settings.staging ? "Staging: issued certificates will not be browser trusted." : "Production: certificates are issued by Let's Encrypt."} All requested hostnames require HTTP-01 verification. Wildcard certificates are unsupported.`;
  const quote = value => "'" + value.replaceAll("'", "'\"'\"'") + "'";
  $("acme-command").value = directory ? `certbot certonly --standalone --non-interactive --agree-tos \\\n  --server ${quote(directory)} \\\n  --email you@example.com -d ha.example.com \\\n  --issuance-timeout 1200` : "Configure the server URL first.";
  renderAcmeClients(result);
  const orders = $("acme-order-list"); orders.replaceChildren();
  if (!result.orders.length) empty(orders, "No ACME orders yet");
  for (const order of result.orders) {
    const row = node("div", "row certificate-row");
    const info = identity(order.domains.join(", "), `${order.staging ? "Staging" : "Production"} · ${order.state} · ${order.phase}`);
    info.append(acmeCertificateExpiry(order));
    row.append(info);
    if (order.error) row.append(node("p", "error", order.error));
    row.append(routeLink("View details", resourcePath("orders", order.id), "subtle"));
    orders.append(row);
  }
  renderOverview();
  renderCurrentDetail();
}
$("acme-settings-refresh").onclick = () => loadAcmeSettings().catch(error => notify(error.message, true));
$("orders-refresh").onclick = () => loadAcmeSettings().catch(error => notify(error.message, true));
$("acme-settings-form").onsubmit = async event => {
  event.preventDefault();
  acmeSettingsSaving = true;
  const button = event.submitter; button.disabled = true;
  $("acme-settings-error").textContent = "";
  const lines = id => $(id).value.split(/\n/).map(s => s.trim()).filter(Boolean);
  try {
    await api("/acme/settings", "PUT", {
      mode: $("acme-mode").value,
      base_url: $("acme-base-url").value.trim(),
      allowed_networks: lines("acme-networks"), allowed_domains: lines("acme-domains"),
      validation_networks: lines("acme-validation-networks"),
      staging: $("acme-environment").value === "staging", terms_agreed: $("acme-terms").checked,
    });
    acmeSettingsDirty = false;
    await loadAcmeSettings();
    notify("ACME settings saved.");
  } catch (error) { $("acme-settings-error").textContent = error.message; }
  finally { acmeSettingsSaving = false; button.disabled = !acmeSettingsData; }
};
