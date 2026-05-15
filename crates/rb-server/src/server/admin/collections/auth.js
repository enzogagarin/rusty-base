import { $, state } from "../state.js";
import { escapeAttribute, escapeHtml } from "../render_helpers.js";

const TOKEN_DEFAULTS = {
  authToken: 604800,
  passwordResetToken: 1800,
  emailChangeToken: 1800,
  verificationToken: 259200,
  fileToken: 180
};

export function collectionAuthToolsHtml(draft) {
  if (!draft.ok || !draft.value || draft.value.type !== "auth") {
    return "";
  }

  const payload = draft.value;
  const passwordAuth = payload.passwordAuth && typeof payload.passwordAuth === "object"
    ? payload.passwordAuth
    : { enabled: true, identityFields: defaultIdentityFields(payload) };
  const otp = payload.otp && typeof payload.otp === "object"
    ? payload.otp
    : { enabled: defaultIdentityFields(payload).includes("email"), duration: 180, length: 8 };
  const mfa = payload.mfa && typeof payload.mfa === "object"
    ? payload.mfa
    : { enabled: false, duration: 1800, rule: "" };

  return `
    <div class="field-tools">
      <div class="field-tools-head">
        <h2>Auth</h2>
        <span class="muted">password, OTP, MFA</span>
      </div>
      <div class="auth-tools-grid">
        <label class="check-field">
          <input id="collection-auth-password-enabled" type="checkbox" ${passwordAuth.enabled === false ? "" : "checked"}>
          Password auth
        </label>
        <div class="field">
          <label for="collection-auth-identity-fields">Identity fields</label>
          <input id="collection-auth-identity-fields" placeholder="email, username" value="${escapeAttribute(identityFieldsValue(passwordAuth, payload))}">
        </div>
        <div class="field field-wide">
          <label for="collection-auth-rule">Auth rule</label>
          <textarea id="collection-auth-rule" spellcheck="false" placeholder="@request.auth.id = id">${escapeHtml(payload.authRule || "")}</textarea>
        </div>
        <div class="field field-wide">
          <label for="collection-manage-rule">Manage rule</label>
          <textarea id="collection-manage-rule" spellcheck="false" placeholder="@request.auth.id = id">${escapeHtml(payload.manageRule || "")}</textarea>
        </div>
        ${tokenDurationField("auth-token-duration", "Auth token", tokenDuration(payload, "authToken"))}
        ${tokenDurationField("password-reset-token-duration", "Password reset", tokenDuration(payload, "passwordResetToken"))}
        ${tokenDurationField("email-change-token-duration", "Email change", tokenDuration(payload, "emailChangeToken"))}
        ${tokenDurationField("verification-token-duration", "Verification", tokenDuration(payload, "verificationToken"))}
        ${tokenDurationField("file-token-duration", "File token", tokenDuration(payload, "fileToken"))}
        <label class="check-field">
          <input id="collection-otp-enabled" type="checkbox" ${otp.enabled ? "checked" : ""}>
          OTP
        </label>
        ${numberField("collection-otp-duration", "OTP duration", otp.duration || 180, 1)}
        ${numberField("collection-otp-length", "OTP length", otp.length || 8, 4, "")}
        <label class="check-field">
          <input id="collection-mfa-enabled" type="checkbox" ${mfa.enabled ? "checked" : ""}>
          MFA
        </label>
        ${numberField("collection-mfa-duration", "MFA duration", mfa.duration || 1800, 1)}
        <div class="field field-wide">
          <label for="collection-mfa-rule">MFA rule</label>
          <textarea id="collection-mfa-rule" spellcheck="false" placeholder="@request.auth.emailVisibility = true">${escapeHtml(mfa.rule || "")}</textarea>
        </div>
      </div>
    </div>
  `;
}

export function bindCollectionAuthTools({ readPayload, showError }) {
  authInputIds().forEach((id) => {
    const input = $(id);
    if (!input) {
      return;
    }
    input.addEventListener(input.type === "checkbox" ? "change" : "input", () => {
      syncCollectionAuthFromControls({ readPayload, showError });
    });
  });
}

function syncCollectionAuthFromControls({ readPayload, showError }) {
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
  if (payload.type !== "auth") {
    return true;
  }

  payload.authRule = controlValue("collection-auth-rule");
  payload.manageRule = controlValue("collection-manage-rule") || null;
  payload.passwordAuth = {
    enabled: checked("collection-auth-password-enabled"),
    identityFields: commaList(controlValue("collection-auth-identity-fields"))
  };
  payload.authToken = durationConfig("auth-token-duration", TOKEN_DEFAULTS.authToken);
  payload.passwordResetToken = durationConfig("password-reset-token-duration", TOKEN_DEFAULTS.passwordResetToken);
  payload.emailChangeToken = durationConfig("email-change-token-duration", TOKEN_DEFAULTS.emailChangeToken);
  payload.verificationToken = durationConfig("verification-token-duration", TOKEN_DEFAULTS.verificationToken);
  payload.fileToken = durationConfig("file-token-duration", TOKEN_DEFAULTS.fileToken);
  payload.otp = {
    enabled: checked("collection-otp-enabled"),
    duration: numericValue("collection-otp-duration", 180),
    length: numericValue("collection-otp-length", 8)
  };
  payload.mfa = {
    enabled: checked("collection-mfa-enabled"),
    duration: numericValue("collection-mfa-duration", 1800),
    rule: controlValue("collection-mfa-rule")
  };

  state.collectionEditorText = JSON.stringify(payload, null, 2);
  state.collectionEditorError = "";
  if (jsonInput) {
    jsonInput.value = state.collectionEditorText;
  }
  return true;
}

function authInputIds() {
  return [
    "collection-auth-password-enabled",
    "collection-auth-identity-fields",
    "collection-auth-rule",
    "collection-manage-rule",
    "auth-token-duration",
    "password-reset-token-duration",
    "email-change-token-duration",
    "verification-token-duration",
    "file-token-duration",
    "collection-otp-enabled",
    "collection-otp-duration",
    "collection-otp-length",
    "collection-mfa-enabled",
    "collection-mfa-duration",
    "collection-mfa-rule"
  ];
}

function defaultIdentityFields(payload) {
  return Array.isArray(payload.fields)
    ? payload.fields
      .filter((field) => field && (field.name === "email" || field.name === "username"))
      .map((field) => field.name)
    : [];
}

function identityFieldsValue(passwordAuth, payload) {
  const fields = Array.isArray(passwordAuth.identityFields) && passwordAuth.identityFields.length
    ? passwordAuth.identityFields
    : defaultIdentityFields(payload);
  return fields.join(", ");
}

function tokenDuration(payload, key) {
  return payload[key] && Number(payload[key].duration)
    ? Number(payload[key].duration)
    : TOKEN_DEFAULTS[key];
}

function tokenDurationField(id, label, value) {
  return numberField(id, label, value, 1);
}

function numberField(id, label, value, min, suffix = " seconds") {
  return `
    <div class="field">
      <label for="${id}">${escapeHtml(label)}${escapeHtml(suffix)}</label>
      <input id="${id}" type="number" min="${min}" step="1" value="${escapeAttribute(String(value))}">
    </div>
  `;
}

function durationConfig(id, fallback) {
  return { duration: numericValue(id, fallback) };
}

function numericValue(id, fallback) {
  const input = $(id);
  const value = input ? Number(input.value) : fallback;
  return Number.isFinite(value) ? Math.trunc(value) : fallback;
}

function controlValue(id) {
  const input = $(id);
  return input ? input.value.trim() : "";
}

function checked(id) {
  const input = $(id);
  return Boolean(input && input.checked);
}

function commaList(value) {
  const seen = new Set();
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter((item) => {
      if (!item || seen.has(item)) {
        return false;
      }
      seen.add(item);
      return true;
    });
}
