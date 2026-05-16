import { $, state } from "../state.js";
import { escapeAttribute, escapeHtml } from "../render_helpers.js";

const TOKEN_DEFAULTS = {
  authToken: 604800,
  passwordResetToken: 1800,
  emailChangeToken: 1800,
  verificationToken: 259200,
  fileToken: 180
};

const TEMPLATE_DEFAULTS = {
  verificationTemplate: {
    subject: "Verify your {APP_NAME} email",
    body: "Use this token to verify your email address.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n"
  },
  passwordResetTemplate: {
    subject: "Reset your {APP_NAME} password",
    body: "Use this token to reset your password.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n"
  },
  emailChangeTemplate: {
    subject: "Confirm your {APP_NAME} email change",
    body: "Use this token to confirm your new email address.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n"
  }
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
  const oauth2 = oauthConfig(payload);
  const provider = oauthProvider(oauth2);
  const mappedFields = oauthMappedFields(oauth2);
  const verificationTemplate = templateConfig(payload, "verificationTemplate");
  const passwordResetTemplate = templateConfig(payload, "passwordResetTemplate");
  const emailChangeTemplate = templateConfig(payload, "emailChangeTemplate");

  return `
    <div class="field-tools">
      <div class="field-tools-head">
        <h2>Auth</h2>
        <span class="muted">password, OTP, MFA, OAuth2</span>
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
        <label class="check-field">
          <input id="collection-oauth-enabled" type="checkbox" ${oauth2.enabled ? "checked" : ""}>
          OAuth2
        </label>
        <div class="field">
          <label for="collection-oauth-provider-name">Provider</label>
          <input id="collection-oauth-provider-name" placeholder="github" value="${escapeAttribute(provider.name || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-provider-display-name">Display name</label>
          <input id="collection-oauth-provider-display-name" placeholder="GitHub" value="${escapeAttribute(provider.displayName || provider.display_name || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-client-id">Client ID</label>
          <input id="collection-oauth-client-id" value="${escapeAttribute(provider.clientId || provider.client_id || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-client-secret">Client secret</label>
          <input id="collection-oauth-client-secret" type="password" value="${escapeAttribute(provider.clientSecret || provider.client_secret || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-auth-url">Auth URL</label>
          <input id="collection-oauth-auth-url" placeholder="built-in for github/google" value="${escapeAttribute(provider.authUrl || provider.auth_url || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-token-url">Token URL</label>
          <input id="collection-oauth-token-url" placeholder="required with user info URL" value="${escapeAttribute(provider.tokenUrl || provider.token_url || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-user-info-url">User info URL</label>
          <input id="collection-oauth-user-info-url" placeholder="required with token URL" value="${escapeAttribute(provider.userInfoUrl || provider.user_info_url || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-scopes">Scopes</label>
          <input id="collection-oauth-scopes" placeholder="user:email, read:user" value="${escapeAttribute(providerScopesValue(provider))}">
        </div>
        <div class="field">
          <label for="collection-oauth-map-id">Map ID</label>
          <input id="collection-oauth-map-id" placeholder="id or sub" value="${escapeAttribute(mappedFields.id || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-map-name">Map name</label>
          <input id="collection-oauth-map-name" placeholder="name" value="${escapeAttribute(mappedFields.name || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-map-username">Map username</label>
          <input id="collection-oauth-map-username" placeholder="login" value="${escapeAttribute(mappedFields.username || "")}">
        </div>
        <div class="field">
          <label for="collection-oauth-map-avatar-url">Map avatar URL</label>
          <input id="collection-oauth-map-avatar-url" placeholder="avatar_url" value="${escapeAttribute(mappedFields.avatarURL || mappedFields.avatarUrl || mappedFields.avatar_url || "")}">
        </div>
        ${templateToolsHtml("verification", "Verification mail", verificationTemplate)}
        ${templateToolsHtml("password-reset", "Password reset mail", passwordResetTemplate)}
        ${templateToolsHtml("email-change", "Email change mail", emailChangeTemplate)}
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
  payload.oauth2 = {
    enabled: checked("collection-oauth-enabled"),
    mappedFields: {
      id: controlValue("collection-oauth-map-id"),
      name: controlValue("collection-oauth-map-name"),
      username: controlValue("collection-oauth-map-username"),
      avatarURL: controlValue("collection-oauth-map-avatar-url")
    },
    providers: oauthProvidersFromControls(payload)
  };
  payload.verificationTemplate = templateFromControls(payload, "verification", "verificationTemplate");
  payload.passwordResetTemplate = templateFromControls(payload, "password-reset", "passwordResetTemplate");
  payload.emailChangeTemplate = templateFromControls(payload, "email-change", "emailChangeTemplate");

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
    "collection-mfa-rule",
    "collection-oauth-enabled",
    "collection-oauth-provider-name",
    "collection-oauth-provider-display-name",
    "collection-oauth-client-id",
    "collection-oauth-client-secret",
    "collection-oauth-auth-url",
    "collection-oauth-token-url",
    "collection-oauth-user-info-url",
    "collection-oauth-scopes",
    "collection-oauth-map-id",
    "collection-oauth-map-name",
    "collection-oauth-map-username",
    "collection-oauth-map-avatar-url",
    "collection-template-verification-subject",
    "collection-template-verification-body",
    "collection-template-password-reset-subject",
    "collection-template-password-reset-body",
    "collection-template-email-change-subject",
    "collection-template-email-change-body"
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

function templateToolsHtml(prefix, label, template) {
  return `
    <div class="field field-wide">
      <label for="collection-template-${prefix}-subject">${escapeHtml(label)} subject</label>
      <input id="collection-template-${prefix}-subject" value="${escapeAttribute(template.subject || "")}">
    </div>
    <div class="field field-wide">
      <label for="collection-template-${prefix}-body">${escapeHtml(label)} body</label>
      <textarea id="collection-template-${prefix}-body" spellcheck="false">${escapeHtml(template.body || "")}</textarea>
    </div>
  `;
}

function templateConfig(payload, key) {
  const template = payload[key] && typeof payload[key] === "object" && !Array.isArray(payload[key])
    ? payload[key]
    : {};
  const defaults = TEMPLATE_DEFAULTS[key] || {};
  return {
    subject: template.subject || defaults.subject || "",
    body: template.body || defaults.body || "",
    html: template.html || ""
  };
}

function templateFromControls(payload, prefix, key) {
  const current = templateConfig(payload, key);
  const defaults = TEMPLATE_DEFAULTS[key] || {};
  return {
    subject: controlValue(`collection-template-${prefix}-subject`) || defaults.subject || "",
    body: controlRawValue(`collection-template-${prefix}-body`) || defaults.body || "",
    html: current.html || ""
  };
}

function oauthConfig(payload) {
  const oauth2 = payload.oauth2 && typeof payload.oauth2 === "object" && !Array.isArray(payload.oauth2)
    ? payload.oauth2
    : {};
  return {
    enabled: Boolean(oauth2.enabled),
    mappedFields: oauthMappedFields(oauth2),
    providers: Array.isArray(oauth2.providers) ? oauth2.providers : []
  };
}

function oauthProvider(oauth2) {
  return oauth2.providers.find((provider) => provider && typeof provider === "object" && !Array.isArray(provider)) || {};
}

function oauthMappedFields(oauth2) {
  return oauth2.mappedFields && typeof oauth2.mappedFields === "object" && !Array.isArray(oauth2.mappedFields)
    ? oauth2.mappedFields
    : {};
}

function providerScopesValue(provider) {
  return Array.isArray(provider.scopes) ? provider.scopes.join(", ") : "";
}

function oauthProvidersFromControls(payload) {
  const existing = oauthConfig(payload).providers
    .filter((provider) => provider && typeof provider === "object" && !Array.isArray(provider));
  const provider = {
    name: controlValue("collection-oauth-provider-name"),
    displayName: controlValue("collection-oauth-provider-display-name"),
    clientId: controlValue("collection-oauth-client-id"),
    clientSecret: controlValue("collection-oauth-client-secret"),
    authUrl: controlValue("collection-oauth-auth-url"),
    tokenUrl: controlValue("collection-oauth-token-url"),
    userInfoUrl: controlValue("collection-oauth-user-info-url"),
    scopes: commaList(controlValue("collection-oauth-scopes"))
  };
  const rest = existing.slice(1);
  return provider.name ? [provider, ...rest] : rest;
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

function controlRawValue(id) {
  const input = $(id);
  return input ? input.value : "";
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
