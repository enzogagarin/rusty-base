import { $, state } from "../state.js";
import { escapeHtml } from "../render_helpers.js";

const BASE_RULES = [
  ["listRule", "List rule", "collection-rule-list", "published = true"],
  ["viewRule", "View rule", "collection-rule-view", "owner = @request.auth.id"],
  ["createRule", "Create rule", "collection-rule-create", "@request.body.owner = @request.auth.id"],
  ["updateRule", "Update rule", "collection-rule-update", "owner = @request.auth.id"],
  ["deleteRule", "Delete rule", "collection-rule-delete", "owner = @request.auth.id"]
];

const AUTH_RULES = [
  ["authRule", "Auth rule", "collection-rule-auth", ""],
  ["manageRule", "Manage rule", "collection-rule-manage", "@request.auth.id = id"]
];

export function collectionRuleToolsHtml(draft) {
  if (!draft.ok || !draft.value || typeof draft.value !== "object" || Array.isArray(draft.value)) {
    return "";
  }

  const payload = draft.value;
  const type = ["base", "auth", "view"].includes(payload.type) ? payload.type : "base";
  const rules = type === "view"
    ? BASE_RULES.slice(0, 2)
    : BASE_RULES;
  const authRules = type === "auth" ? AUTH_RULES : [];

  return `
    <div class="field-tools">
      <div class="field-tools-head">
        <h2>Rules</h2>
        <span class="muted">${escapeHtml(ruleSummary(payload, rules.concat(authRules)))}</span>
      </div>
      <div class="rule-tools-grid">
        ${rules.map((rule) => ruleTextarea(payload, rule)).join("")}
        ${authRules.map((rule) => ruleTextarea(payload, rule)).join("")}
      </div>
    </div>
  `;
}

export function bindCollectionRuleTools({ readPayload, showError }) {
  document.querySelectorAll("[data-collection-rule]").forEach((input) => {
    input.addEventListener("input", () => {
      syncCollectionRulesFromControls({ readPayload, showError });
    });
  });
}

function syncCollectionRulesFromControls({ readPayload, showError }) {
  const jsonInput = $("collection-json-input");
  let payload = null;
  try {
    payload = readPayload();
  } catch (error) {
    showError(error.message, jsonInput);
    return false;
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    showError("Collection JSON must be an object", jsonInput);
    return false;
  }

  document.querySelectorAll("[data-collection-rule]").forEach((input) => {
    const key = input.dataset.collectionRule;
    const value = input.value.trim();
    payload[key] = value || null;
  });

  state.collectionEditorText = JSON.stringify(payload, null, 2);
  state.collectionEditorError = "";
  if (jsonInput) {
    jsonInput.value = state.collectionEditorText;
  }
  return true;
}

function ruleTextarea(payload, [key, label, id, placeholder]) {
  return `
    <div class="field">
      <label for="${id}">${escapeHtml(label)}</label>
      <textarea id="${id}" data-collection-rule="${key}" spellcheck="false" placeholder="${escapeHtml(placeholder)}">${escapeHtml(payload[key] || "")}</textarea>
    </div>
  `;
}

function ruleSummary(payload, rules) {
  const count = rules.filter(([key]) => String(payload[key] || "").trim()).length;
  return `${count} active`;
}
