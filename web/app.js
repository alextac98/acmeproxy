"use strict";
const $ = (id) => document.getElementById(id);
let token = "",
  data = null,
  currentTab = "providers",
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
const tabs = {
  providers: ["DNS providers", "+ Add provider", "/providers"],
  clients: ["Clients", "+ Add client", "/clients"],
  challenges: ["DNS validations", null, "/validations"],
  activity: ["Activity", null, "/activity"],
  about: ["About", null, "/about"],
};
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
    : "";
  $("challenge-note").hidden = !data.failed;
  renderProviders();
  renderClients();
  renderChallenges();
  if (currentTab === "activity" && activityBefore === null && !activityLoading)
    await loadActivity().catch(showActivityError);
}
function logout() {
  token = "";
  clearNotice();
  clearInterval(refreshTimer);
  data = null;
  activityRequest++;
  activityLoading = false;
  activityData = null;
  activityBefore = null;
  activityPrevious = [];
  activitySearch = "";
  activityRetentionDirty = false;
  $("activity-search-form").reset();
  $("activity-retention-form").reset();
  $("activity-status").textContent = "";
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
  token = $("admin-token").value.trim();
  try {
    await refresh();
    $("admin-token").value = "";
    $("login").hidden = true;
    $("workspace").hidden = false;
    switchTab(tabFromLocation(), "replace");
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
function tabFromLocation() {
  return Object.keys(tabs).find((tab) => tabs[tab][2] === location.pathname) || "providers";
}
function switchTab(tab, navigation = "push") {
  if (tab !== currentTab && !$("notice").classList.contains("error")) clearNotice();
  if (navigation !== "none" && location.pathname !== tabs[tab][2]) {
    history[navigation === "replace" ? "replaceState" : "pushState"](
      null, "", tabs[tab][2],
    );
  }
  const changed = currentTab !== tab;
  currentTab = tab;
  document.title = tabs[tab][0] + " · ACME Proxy";
  $("page-title").textContent = tabs[tab][0];
  $("gateway-summary").hidden = tab === "about";
  $("add-button").hidden = !tabs[tab][1];
  $("add-button").textContent = tabs[tab][1];
  Object.keys(tabs).forEach((key) => ($(key + "-panel").hidden = key !== tab));
  document
    .querySelectorAll("[data-tab]")
    .forEach((link) => {
      const selected = link.dataset.tab === tab;
      link.classList.toggle("selected", selected);
      if (selected) {
        link.setAttribute("aria-current", "page");
        if (link.closest("nav") && !$("workspace").hidden)
          link.scrollIntoView({ block: "nearest", inline: "nearest" });
      } else link.removeAttribute("aria-current");
    });
  if (changed && tab === "activity" && data)
    loadActivity().catch(showActivityError);
}
document
  .querySelectorAll("[data-tab], aside .brand")
  .forEach((link) => link.addEventListener("click", (event) => {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    switchTab(link.dataset.tab || "providers");
  }));
window.addEventListener("popstate", () => {
  document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
  switchTab(tabFromLocation(), "none");
});
switchTab(tabFromLocation(), "replace");
$("add-button").onclick = () =>
  currentTab === "providers" ? openProvider() : openClient();
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
  if (!data.providers.length)
    return empty(
      list,
      "Connect your first DNS provider",
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
  const revokedList = $("revoked-client-list");
  list.replaceChildren();
  revokedList.replaceChildren();
  const revokedCount = data.clients.filter((c) => c.revoked).length;
  $("revoked-client-count").textContent = revokedCount;
  $("revoked-clients").hidden = !revokedCount;
  if (!revokedCount) $("revoked-clients").open = false;
  if (!data.clients.some((c) => !c.revoked))
    empty(
      list,
      "No active clients",
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
    else
      buttons.append(
        action("Delete", () =>
          confirm(
            "Permanently delete client?",
            `Delete ${c.name} and its DNS validation history permanently. This cannot be undone. Any outstanding DNS records must be cleaned up first.`,
            async () => {
              await api("/clients/" + c.id + "/permanent", "DELETE");
              await refresh();
              notify("Client permanently deleted.");
            },
          ),
        ),
      );
    row.append(buttons);
    (c.revoked ? revokedList : list).append(row);
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
  if (!data.challenges.length)
    return empty(list, "No DNS validations yet");
  const domains = new Map();
  [...data.challenges]
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
  activityLoading = true;
  activityControls();
  try {
    const query = new URLSearchParams({ search });
    if (before !== null) query.set("before", before);
    const result = await api("/activity?" + query);
    if (request !== activityRequest) return;
    const moved = before !== activityBefore || search !== activitySearch;
    activityData = result;
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
  loadActivity(null, $("activity-search").value.trim(), []).catch(showActivityError);
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
    notify("Provider saved.");
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
