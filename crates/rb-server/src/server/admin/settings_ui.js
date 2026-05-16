import { $, api, jsonApi, state, status } from "./state.js";
import { escapeAttribute, escapeHtml } from "./render_helpers.js";

let actions = {
  refresh: async () => {},
  render() {}
};

export function renderSettings(nextActions) {
  actions = nextActions;
  if (!state.token) {
    $("content").innerHTML = `
      <div class="empty">
        <strong>Login or initialize first</strong>
        <span>Settings are available after a superuser session is active.</span>
      </div>
    `;
    return;
  }

  const settings = state.settings || {};
  const meta = settings.meta || {};
  const batch = settings.batch || {};
  const rateLimits = settings.rateLimits || {};
  const outbox = Array.isArray(state.mailOutbox) ? state.mailOutbox : [];
  $("content").innerHTML = `
    <div class="panel-head">
      <h2>Settings</h2>
      <button type="button" id="refresh">Refresh</button>
    </div>
    <form class="settings-form" id="settings-form">
      <div class="settings-section">
        <h3>App</h3>
        <div class="settings-grid">
          <div class="field">
            <label for="settings-app-name">App name</label>
            <input id="settings-app-name" required value="${escapeAttribute(meta.appName || "Rusty Base")}">
          </div>
          <div class="field">
            <label for="settings-app-url">App URL</label>
            <input id="settings-app-url" inputmode="url" value="${escapeAttribute(meta.appURL || "")}">
          </div>
          <div class="field">
            <label for="settings-sender-name">Sender name</label>
            <input id="settings-sender-name" value="${escapeAttribute(meta.senderName || "")}">
          </div>
          <div class="field">
            <label for="settings-sender-address">Sender address</label>
            <input id="settings-sender-address" inputmode="email" value="${escapeAttribute(meta.senderAddress || "")}">
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Batch</h3>
        <div class="settings-grid">
          <label class="check-field">
            <input id="settings-batch-enabled" type="checkbox" ${batch.enabled === false ? "" : "checked"}>
            Enabled
          </label>
          <div class="field">
            <label for="settings-batch-max-requests">Max requests</label>
            <input id="settings-batch-max-requests" type="number" min="1" step="1" value="${escapeAttribute(batch.maxRequests == null ? 50 : batch.maxRequests)}">
          </div>
          <div class="field">
            <label for="settings-batch-timeout">Timeout</label>
            <input id="settings-batch-timeout" type="number" min="1" step="1" value="${escapeAttribute(batch.timeout == null ? 30 : batch.timeout)}">
          </div>
          <div class="field">
            <label for="settings-batch-max-body-size">Max body size</label>
            <input id="settings-batch-max-body-size" type="number" min="0" step="1" value="${escapeAttribute(batch.maxBodySize == null ? 0 : batch.maxBodySize)}">
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Rate limits</h3>
        <label class="check-field">
          <input id="settings-rate-limits-enabled" type="checkbox" ${rateLimits.enabled ? "checked" : ""}>
          Enabled
        </label>
      </div>
      <div class="settings-section">
        <div class="panel-head compact">
          <h3>Dev mail outbox</h3>
          <button type="button" id="clear-mail-outbox" ${outbox.length ? "" : "disabled"}>Clear</button>
        </div>
        ${state.mailOutboxError ? `<div class="error">${escapeHtml(state.mailOutboxError)}</div>` : mailOutboxHtml(outbox)}
      </div>
      ${state.settingsError ? `<div class="error">${escapeAttribute(state.settingsError)}</div>` : ""}
      <div class="editor-actions">
        <button type="button" id="refresh-settings">Reset</button>
        <button type="submit" class="primary">Save</button>
      </div>
    </form>
  `;
  $("refresh").addEventListener("click", actions.refresh);
  $("refresh-settings").addEventListener("click", actions.refresh);
  $("settings-form").addEventListener("submit", saveSettings);
  $("clear-mail-outbox").addEventListener("click", clearMailOutbox);
}

async function saveSettings(event) {
  event.preventDefault();
  state.settingsError = "";

  const patch = {
    meta: {
      appName: value("settings-app-name").trim(),
      appURL: value("settings-app-url").trim(),
      senderName: value("settings-sender-name").trim(),
      senderAddress: value("settings-sender-address").trim()
    },
    batch: {
      enabled: checked("settings-batch-enabled"),
      maxRequests: numberValue("settings-batch-max-requests"),
      timeout: numberValue("settings-batch-timeout"),
      maxBodySize: numberValue("settings-batch-max-body-size")
    },
    rateLimits: {
      enabled: checked("settings-rate-limits-enabled")
    }
  };

  try {
    state.settings = await jsonApi("/api/settings", patch, "PATCH");
    status("Settings saved");
    actions.render();
  } catch (error) {
    state.settingsError = error.message;
    status(error.message, true);
    actions.render();
  }
}

async function clearMailOutbox() {
  try {
    await api("/api/dev/mail/outbox", { method: "DELETE" });
    state.mailOutbox = [];
    status("Mail outbox cleared");
    actions.render();
  } catch (error) {
    state.mailOutboxError = error.message;
    status(error.message, true);
    actions.render();
  }
}

function mailOutboxHtml(items) {
  if (!items.length) {
    return `<div class="empty compact"><strong>No dev mails</strong><span>Auth action requests will appear here.</span></div>`;
  }

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Kind</th>
            <th>Recipient</th>
            <th>Subject</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          ${items.map((item) => `
            <tr>
              <td>${escapeHtml(item.kind || "")}</td>
              <td>${escapeHtml(item.recipient || "")}</td>
              <td>${escapeHtml(item.subject || "")}</td>
              <td>${escapeHtml(item.created || "")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function value(id) {
  return $(id)?.value || "";
}

function checked(id) {
  return Boolean($(id)?.checked);
}

function numberValue(id) {
  const value = Number($(id)?.value || 0);
  return Number.isFinite(value) ? value : 0;
}
