import { $, api, jsonApi, state, status } from "../state.js";
import {
  collectionIsAuth,
  collectionRecordsPath,
  editableRecordPayload,
  recordFieldInputDisplayValue,
  recordFieldIsMulti,
  recordPath,
  userCollectionFields
} from "../data_helpers.js";
import { escapeAttribute, escapeHtml } from "../render_helpers.js";
import {
  applyRecordFileDeletes,
  bindRecordFileControls,
  recordEditorFileDeletes,
  recordEditorFileUploads,
  recordFileValueHtml,
  recordFormDataPayload
} from "./files.js";
import { invalidateRelationOptions, relationFieldInputHtml } from "./relations.js";
import {
  clearRecordFieldValidationFeedback,
  clearRecordValidationFeedback,
  recordFieldValidation,
  recordValidationMessage,
  recordValidationSummaryHtml,
  validationDataFromError
} from "./validation.js";

export function recordEditorHtml(actions) {
  if (!state.editorMode) {
    return "";
  }

  const title = state.editorMode === "edit" ? `Edit ${state.editorRecordId}` : "Create record";
  const collection = actions.currentCollection();
  const draft = recordEditorDraft();
  return `
    <div class="record-editor">
      <h2>${escapeHtml(title)}</h2>
      ${state.editorError ? `<div class="error">${escapeHtml(state.editorError)}</div>` : ""}
      ${recordValidationSummaryHtml(collection)}
      ${recordFieldFormHtml(collection, draft)}
      <textarea id="record-json-input" spellcheck="false">${escapeHtml(state.editorText)}</textarea>
      <div class="editor-actions">
        <button type="button" id="cancel-record">Cancel</button>
        <button type="button" id="save-record" class="primary">Save</button>
      </div>
    </div>
  `;
}

export function bindRecordEditorControls(actions) {
  const save = $("save-record");
  if (save) {
    save.addEventListener("click", async () => {
      await saveRecord(actions);
    });
  }
  const cancel = $("cancel-record");
  if (cancel) {
    cancel.addEventListener("click", () => {
      closeRecordEditor();
      actions.render();
    });
  }
  const jsonInput = $("record-json-input");
  if (jsonInput) {
    jsonInput.addEventListener("input", () => {
      state.editorText = jsonInput.value;
      clearRecordValidationFeedback();
    });
  }
  document.querySelectorAll("[data-record-field]").forEach((input) => {
    const eventName = input.type === "checkbox" || input.tagName === "SELECT" ? "change" : "input";
    input.addEventListener(eventName, () => {
      syncRecordFieldFromInput(input);
    });
  });
  bindRecordFileControls(actions, currentEditorRecordId, clearRecordFieldValidationFeedback);
}

function recordFieldFormHtml(collection, draft) {
  const fields = recordEditorFields(collection);
  if (!fields.length) {
    return "";
  }
  if (!draft.ok) {
    return `
      <div class="record-form">
        <div class="field-tools-head">
          <h2>Fields</h2>
          <span class="muted">Fix the record JSON to use field inputs.</span>
        </div>
      </div>
    `;
  }

  return `
    <div class="record-form">
      <div class="field-tools-head">
        <h2>Fields</h2>
        <span class="muted">${fields.length} field${fields.length === 1 ? "" : "s"}</span>
      </div>
      <div class="record-form-grid">
        ${fields.map((field, index) => recordFieldInputHtml(field, draft.value[field.name], index)).join("")}
      </div>
    </div>
  `;
}

function recordFieldInputHtml(field, value, index) {
  const name = field.name || "";
  const type = field.type || field.kind || "text";
  const inputId = `record-field-${index}`;
  const common = `id="${inputId}" data-record-field="${escapeAttribute(name)}" data-record-type="${escapeAttribute(type)}" data-record-multi="${recordFieldIsMulti(field) ? "true" : "false"}"`;
  const validation = recordFieldValidation(name);
  const fieldClass = validation ? "field has-error" : "field";
  const fieldError = validation ? `<div class="field-error">${escapeHtml(recordValidationMessage(validation))}</div>` : "";
  const label = `
    <label for="${inputId}">
      <span>${escapeHtml(name)}</span>
      <span class="pill">${escapeHtml(type)}</span>
      ${field.required ? `<span class="pill">required</span>` : ""}
    </label>
  `;

  if (type === "bool") {
    return `
      <div class="${fieldClass}">
        ${label}
        <label class="check-field"><input ${common} type="checkbox" ${value === true ? "checked" : ""}>true</label>
        ${fieldError}
      </div>
    `;
  }

  if (type === "password") {
    return `
      <div class="${fieldClass}">
        ${label}
        <input ${common} type="password" value="${escapeAttribute(recordFieldInputDisplayValue(value))}" autocomplete="new-password">
        ${fieldError}
      </div>
    `;
  }

  if (type === "editor" || type === "json") {
    return `
      <div class="${fieldClass}">
        ${label}
        <textarea ${common} spellcheck="false">${escapeHtml(recordFieldInputDisplayValue(value))}</textarea>
        ${fieldError}
      </div>
    `;
  }

  if (type === "select" && Array.isArray(field.values) && field.values.length && !recordFieldIsMulti(field)) {
    const options = [`<option value=""></option>`].concat(field.values.map((option) => `
      <option value="${escapeAttribute(option)}" ${String(value ?? "") === String(option) ? "selected" : ""}>${escapeHtml(option)}</option>
    `)).join("");
    return `
      <div class="${fieldClass}">
        ${label}
        <select ${common}>${options}</select>
        ${fieldError}
      </div>
    `;
  }

  if (type === "relation") {
    return relationFieldInputHtml(field, value, common, label, fieldClass, fieldError);
  }

  if (type === "file") {
    const accept = Array.isArray(field.mimeTypes) && field.mimeTypes.length
      ? ` accept="${escapeAttribute(field.mimeTypes.join(","))}"`
      : "";
    return `
      <div class="${fieldClass}">
        ${label}
        ${recordFileValueHtml(name, value, currentEditorRecordId())}
        <input id="${inputId}" data-record-file="${escapeAttribute(name)}" data-record-multi="${recordFieldIsMulti(field) ? "true" : "false"}" type="file"${recordFieldIsMulti(field) ? " multiple" : ""}${accept}>
        ${fieldError}
      </div>
    `;
  }

  const inputType = type === "number" ? "number" : "text";
  const placeholder = type === "relation" && recordFieldIsMulti(field)
    ? "record ids, comma separated"
    : type === "relation"
      ? "record id"
      : "";
  return `
    <div class="${fieldClass}">
      ${label}
      <input ${common} type="${inputType}" value="${escapeAttribute(recordFieldInputDisplayValue(value))}" placeholder="${escapeAttribute(placeholder)}">
      ${fieldError}
    </div>
  `;
}

function recordEditorDraft() {
  try {
    return { ok: true, value: JSON.parse(state.editorText || "{}") };
  } catch (error) {
    return { ok: false, error };
  }
}

function recordEditorFields(collection) {
  const fields = userCollectionFields(collection);
  if (!collectionIsAuth(collection)) {
    return fields;
  }

  return fields.concat([
    {
      name: "password",
      type: "password",
      required: state.editorMode === "create"
    },
    {
      name: "passwordConfirm",
      type: "password",
      required: state.editorMode === "create"
    }
  ]);
}

export function openCreateEditor() {
  state.editorMode = "create";
  state.editorRecordId = "";
  state.editorText = "{}";
  state.editorError = "";
  state.editorValidation = {};
}

export function openEditEditor(id) {
  const record = state.records.find((item) => item.id === id);
  if (!record) {
    state.editorError = "Record not found";
    state.editorValidation = {};
    return;
  }
  state.editorMode = "edit";
  state.editorRecordId = id;
  state.editorText = JSON.stringify(editableRecordPayload(record), null, 2);
  state.editorError = "";
  state.editorValidation = {};
}

export function closeRecordEditor() {
  state.editorMode = "";
  state.editorRecordId = "";
  state.editorText = "";
  state.editorError = "";
  state.editorValidation = {};
}

function currentEditorRecordId() {
  return state.editorMode === "edit" ? state.editorRecordId : "";
}

function readRecordEditorPayload() {
  const input = $("record-json-input");
  const text = input ? input.value : state.editorText;
  return JSON.parse(text || "{}");
}

function syncRecordFieldFromInput(input) {
  let payload = null;
  try {
    payload = readRecordEditorPayload();
  } catch (_) {
    status("Fix record JSON before using field inputs", true);
    return;
  }

  try {
    const value = recordFieldInputValue(input);
    if (value === undefined) {
      delete payload[input.dataset.recordField];
    } else {
      payload[input.dataset.recordField] = value;
    }
  } catch (error) {
    status(error.message, true);
    return;
  }

  state.editorText = JSON.stringify(payload, null, 2);
  const jsonInput = $("record-json-input");
  if (jsonInput) {
    jsonInput.value = state.editorText;
  }
  clearRecordFieldValidationFeedback(input);
}

function recordFieldInputValue(input) {
  const type = input.dataset.recordType || "text";
  const multi = input.dataset.recordMulti === "true";
  if (type === "bool") {
    return input.checked;
  }
  if (input.tagName === "SELECT" && input.multiple) {
    return Array.from(input.selectedOptions).map((option) => option.value).filter(Boolean);
  }
  if (input.tagName === "SELECT") {
    return input.value || undefined;
  }

  const raw = (input.value || "").trim();
  if (!raw) {
    return undefined;
  }
  if (type === "number") {
    const number = Number(raw);
    if (!Number.isFinite(number)) {
      throw new Error("Number field must be numeric");
    }
    return number;
  }
  if (type === "json") {
    return JSON.parse(raw);
  }
  if (multi) {
    return raw.split(",").map((value) => value.trim()).filter(Boolean);
  }
  return raw;
}

async function saveRecord(actions) {
  const collection = actions.currentCollection();
  const input = $("record-json-input");
  if (!collection || !input) {
    return;
  }

  let payload = null;
  try {
    payload = JSON.parse(input.value || "{}");
  } catch (error) {
    state.editorText = input.value;
    state.editorError = error.message;
    state.editorValidation = {};
    actions.render();
    return;
  }

  try {
    applyRecordFileDeletes(payload, recordEditorFileDeletes());
    const uploads = recordEditorFileUploads();
    const method = state.editorMode === "edit" ? "PATCH" : "POST";
    const path = state.editorMode === "edit"
      ? recordPath(collection.name, state.editorRecordId)
      : collectionRecordsPath(collection.name);
    await saveRecordPayload(collection, path, payload, uploads, method);
    closeRecordEditor();
    invalidateRelationOptions(collection.name);
    status("Saved");
    await actions.loadRecords(true);
    actions.render();
  } catch (error) {
    state.editorText = input.value;
    state.editorError = error.message;
    state.editorValidation = validationDataFromError(error);
    actions.render();
  }
}

async function saveRecordPayload(collection, path, payload, uploads, method) {
  if (!uploads.length) {
    await jsonApi(path, payload, method);
    return;
  }

  await api(path, {
    method,
    body: recordFormDataPayload(collection, payload, uploads)
  });
}
