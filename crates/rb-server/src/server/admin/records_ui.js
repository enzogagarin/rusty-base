import { $, api, confirmDangerousAction, jsonApi, state, status } from "./state.js";
import {
  collectionRecordsPath,
  editableRecordPayload,
  normalizedRecordPerPage,
  recordFieldInputDisplayValue,
  recordFieldIsMulti,
  recordFieldValuePreview,
  recordPath,
  recordPreview,
  relationOptionLabel,
  relationTargetCollectionName,
  userCollectionFields
} from "./data_helpers.js";
import { escapeAttribute, escapeHtml } from "./render_helpers.js";

let actions = {
  currentCollection: () => null,
  render() {},
  loadRecords: async () => {},
  resetRecordBrowser() {},
  setView: async () => {}
};
const relationOptionLoads = new Map();

export async function ensureRelationOptionsForCollection(collection) {
  const targets = userCollectionFields(collection)
    .filter((field) => (field.type || field.kind) === "relation")
    .map(relationTargetCollectionName)
    .filter(Boolean);
  const uniqueTargets = [...new Set(targets)];
  await Promise.all(uniqueTargets.map((target) => ensureRelationOptions(target)));
}

async function ensureRelationOptions(targetCollection) {
  if (Object.prototype.hasOwnProperty.call(state.relationOptions, targetCollection)) {
    return;
  }
  if (relationOptionLoads.has(targetCollection)) {
    await relationOptionLoads.get(targetCollection);
    return;
  }

  const params = new URLSearchParams();
  params.set("page", "1");
  params.set("perPage", "100");
  params.set("sort", "-updated");
  params.set("fields", "id,name,title,label,email,username,created,updated,collectionName");
  const load = api(`${collectionRecordsPath(targetCollection)}?${params.toString()}`)
    .then((page) => {
      state.relationOptions[targetCollection] = Array.isArray(page.items) ? page.items : [];
      delete state.relationOptionErrors[targetCollection];
    })
    .catch((error) => {
      state.relationOptions[targetCollection] = [];
      state.relationOptionErrors[targetCollection] = error.message;
    })
    .finally(() => {
      relationOptionLoads.delete(targetCollection);
    });
  relationOptionLoads.set(targetCollection, load);
  await load;
}

export function renderRecords(nextActions) {
  actions = nextActions;
  const collection = actions.currentCollection();
  if (!state.token) {
    $("content").innerHTML = `
      <div class="empty">
        <strong>Login or initialize first</strong>
        <span>Records are available after a superuser session is active.</span>
      </div>
    `;
    return;
  }

  if (!collection) {
    const hasCollections = state.collections.length > 0;
    $("content").innerHTML = hasCollections
      ? `
        <div class="empty">
          <strong>Select a collection</strong>
          <span>Choose a collection to browse and edit its records.</span>
          <div class="record-collection-picker">
            ${recordCollectionPickerHtml("record-empty-collection", "", true)}
            <button type="button" id="open-selected-collection" class="primary">Open</button>
          </div>
          <div class="empty-actions">
            <button type="button" id="go-collections">Manage Collections</button>
          </div>
        </div>
      `
      : `
        <div class="empty">
          <strong>No collection selected</strong>
          <span>Create or select a collection before browsing records.</span>
          <div class="empty-actions">
            <button type="button" id="go-collections" class="primary">Go to Collections</button>
          </div>
        </div>
      `;
    bindRecordCollectionPicker("record-empty-collection");
    const openSelected = $("open-selected-collection");
    if (openSelected) {
      openSelected.addEventListener("click", async () => {
        const picker = $("record-empty-collection");
        await selectRecordCollection(picker ? picker.value : "");
      });
    }
    $("go-collections").addEventListener("click", async () => {
      await actions.setView("collections");
    });
    return;
  }

  const recordFields = userCollectionFields(collection);
  const visibleFields = recordFields.slice(0, 6);
  const fieldHeaders = visibleFields.map((field) => `<th>${escapeHtml(field.name || "")}</th>`).join("");
  const rows = state.records.map((record) => `
    <tr>
      <td>${escapeHtml(record.id || "")}</td>
      ${visibleFields.length
        ? visibleFields.map((field) => `<td>${recordValuePreview(record, field)}</td>`).join("")
        : `<td><code class="record-json">${escapeHtml(recordPreview(record))}</code></td>`}
      <td>${escapeHtml(record.created || "-")}</td>
      <td>${escapeHtml(record.updated || "-")}</td>
      <td>
        <div class="record-actions">
          <button type="button" data-edit-record="${escapeAttribute(record.id || "")}">Edit</button>
          <button type="button" class="danger" data-delete-record="${escapeAttribute(record.id || "")}">Delete</button>
        </div>
      </td>
    </tr>
  `).join("");

  $("content").innerHTML = `
    <div class="panel-head">
      <h2>${escapeHtml(collection.name)} records</h2>
      <div class="record-head-controls">
        ${recordCollectionPickerHtml("record-collection-select", collection.name, false)}
        <button type="button" id="new-record" class="primary">New</button>
        <button type="button" id="refresh-records">Refresh</button>
      </div>
    </div>
    ${recordBrowserControlsHtml()}
    ${state.records.length ? `
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th>${visibleFields.length ? fieldHeaders : "<th>Data</th>"}<th>Created</th><th>Updated</th><th>Actions</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    ` : `
      <div class="empty">
        <strong>${state.recordFilter ? "No matching records" : "No records yet"}</strong>
        <span>${state.recordFilter ? "Adjust the filter or clear it to browse this collection." : "Create the first record in this collection."}</span>
      </div>
    `}
    ${recordEditorHtml()}
  `;
  bindRecordCollectionPicker("record-collection-select");
  bindRecordBrowserControls();
  $("new-record").addEventListener("click", () => {
    openCreateEditor();
    actions.render();
  });
  $("refresh-records").addEventListener("click", async () => {
    await actions.loadRecords(false);
    actions.render();
  });
  document.querySelectorAll("[data-edit-record]").forEach((button) => {
    button.addEventListener("click", () => {
      openEditEditor(button.dataset.editRecord || "");
      actions.render();
    });
  });
  document.querySelectorAll("[data-delete-record]").forEach((button) => {
    button.addEventListener("click", async () => {
      await deleteRecord(button.dataset.deleteRecord || "");
    });
  });
  const save = $("save-record");
  if (save) {
    save.addEventListener("click", saveRecord);
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
  document.querySelectorAll("[data-record-file]").forEach((input) => {
    input.addEventListener("change", () => {
      clearRecordFieldValidationFeedback(input);
    });
  });
  document.querySelectorAll("[data-record-file-delete]").forEach((input) => {
    input.addEventListener("change", () => {
      clearRecordFieldValidationFeedback(input);
    });
  });
}

function recordCollectionPickerHtml(id, selectedName, includeEmptyOption) {
  const options = state.collections.map((collection) => {
    const name = collection.name || "";
    return `<option value="${escapeAttribute(name)}" ${name === selectedName ? "selected" : ""}>${escapeHtml(name)}</option>`;
  }).join("");
  return `
    <select id="${escapeAttribute(id)}" aria-label="Collection">
      ${includeEmptyOption ? `<option value="">Choose collection</option>` : ""}
      ${options}
    </select>
  `;
}

function bindRecordCollectionPicker(id) {
  const picker = $(id);
  if (!picker) {
    return;
  }

  picker.addEventListener("change", async () => {
    await selectRecordCollection(picker.value);
  });
}

async function selectRecordCollection(name) {
  const collectionName = String(name || "").trim();
  if (!collectionName) {
    status("Choose a collection", true);
    return;
  }
  if (collectionName === state.selectedCollection) {
    return;
  }

  state.selectedCollection = collectionName;
  localStorage.setItem("rusty-base.admin.collection", state.selectedCollection);
  actions.resetRecordBrowser();
  await actions.loadRecords(true);
  actions.render();
}

function recordBrowserControlsHtml() {
  const perPage = normalizedRecordPerPage(state.recordPerPage);
  const totalItems = Number(state.recordCount) || 0;
  const totalPages = Math.max(1, Number(state.recordTotalPages) || Math.ceil(totalItems / perPage) || 1);
  const page = Math.min(Math.max(1, Number(state.recordPage) || 1), totalPages);
  const start = totalItems ? ((page - 1) * perPage) + 1 : 0;
  const end = totalItems ? Math.min(page * perPage, totalItems) : 0;
  const perPageOptions = [10, 20, 50, 100].map((value) => `
    <option value="${value}" ${perPage === value ? "selected" : ""}>${value}</option>
  `).join("");

  return `
    <div class="record-toolbar">
      <div class="record-toolbar-grid">
        <div class="field">
          <label for="record-filter">Filter</label>
          <input id="record-filter" value="${escapeAttribute(state.recordFilter)}" placeholder="published = true">
        </div>
        <div class="field">
          <label for="record-sort">Sort</label>
          <input id="record-sort" value="${escapeAttribute(state.recordSort)}" placeholder="-created">
        </div>
        <div class="field">
          <label for="record-per-page">Per page</label>
          <select id="record-per-page">${perPageOptions}</select>
        </div>
        <div class="record-query-actions">
          <button type="button" id="apply-record-query" class="primary">Apply</button>
          <button type="button" id="clear-record-query">Clear</button>
        </div>
      </div>
      <div class="record-pager">
        <span class="muted">${start}-${end} of ${totalItems}</span>
        <div class="record-query-actions">
          <button type="button" id="record-prev-page" ${page <= 1 ? "disabled" : ""}>Prev</button>
          <span class="record-page-summary">Page ${page} / ${totalPages}</span>
          <button type="button" id="record-next-page" ${page >= totalPages ? "disabled" : ""}>Next</button>
        </div>
      </div>
    </div>
  `;
}

function recordValuePreview(record, field) {
  const type = field.type || field.kind || "text";
  if (type === "relation") {
    return relationFieldValuePreview(record, field);
  }
  return recordFieldValuePreview(record, field);
}

function relationFieldValuePreview(record, field) {
  const value = record[field.name];
  if (value == null || value === "" || (Array.isArray(value) && !value.length)) {
    return `<span class="muted">-</span>`;
  }

  const values = Array.isArray(value) ? value : [value];
  const labels = values.map((id) => relationDisplayLabel(record, field, String(id)));
  const text = labels.filter(Boolean).join(", ");
  const preview = text.length > 120 ? `${text.slice(0, 117)}...` : text;
  return escapeHtml(preview || recordFieldInputDisplayValue(value));
}

function relationDisplayLabel(record, field, id) {
  const expanded = record.expand && record.expand[field.name];
  const expandedRecord = Array.isArray(expanded)
    ? expanded.find((item) => String((item && item.id) || "") === id)
    : expanded && String(expanded.id || "") === id
      ? expanded
      : null;
  if (expandedRecord) {
    return relationOptionLabel(expandedRecord);
  }

  const target = relationTargetCollectionName(field);
  const option = (state.relationOptions[target] || [])
    .find((item) => String(item.id || "") === id);
  return option ? relationOptionLabel(option) : id;
}

function bindRecordBrowserControls() {
  const apply = $("apply-record-query");
  if (!apply) {
    return;
  }

  const applyQuery = async () => {
    state.recordFilter = ($("record-filter").value || "").trim();
    state.recordSort = ($("record-sort").value || "").trim();
    state.recordPerPage = normalizedRecordPerPage(Number($("record-per-page").value) || 20);
    localStorage.setItem("rusty-base.admin.recordPerPage", String(state.recordPerPage));
    state.recordPage = 1;
    await actions.loadRecords(true);
    actions.render();
  };

  apply.addEventListener("click", applyQuery);
  ["record-filter", "record-sort"].forEach((id) => {
    const input = $(id);
    input.addEventListener("keydown", async (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        await applyQuery();
      }
    });
  });
  $("record-per-page").addEventListener("change", applyQuery);
  $("clear-record-query").addEventListener("click", async () => {
    state.recordFilter = "";
    state.recordSort = "-created";
    state.recordPage = 1;
    await actions.loadRecords(true);
    actions.render();
  });
  $("record-prev-page").addEventListener("click", async () => {
    if (state.recordPage <= 1) {
      return;
    }
    state.recordPage -= 1;
    await actions.loadRecords(true);
    actions.render();
  });
  $("record-next-page").addEventListener("click", async () => {
    const totalPages = Math.max(1, Number(state.recordTotalPages) || 1);
    if (state.recordPage >= totalPages) {
      return;
    }
    state.recordPage += 1;
    await actions.loadRecords(true);
    actions.render();
  });
}

function recordEditorHtml() {
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

function recordFieldFormHtml(collection, draft) {
  const fields = userCollectionFields(collection);
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
    return relationFieldInputHtml(field, value, inputId, common, label, fieldClass, fieldError);
  }

  if (type === "file") {
    const accept = Array.isArray(field.mimeTypes) && field.mimeTypes.length
      ? ` accept="${escapeAttribute(field.mimeTypes.join(","))}"`
      : "";
    return `
      <div class="${fieldClass}">
        ${label}
        ${recordFileValueHtml(name, value)}
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

function relationFieldInputHtml(field, value, inputId, common, label, fieldClass, fieldError) {
  const target = relationTargetCollectionName(field);
  const options = target ? state.relationOptions[target] : null;
  const error = target ? state.relationOptionErrors[target] : "";
  if (!target || !Array.isArray(options)) {
    return `
      <div class="${fieldClass}">
        ${label}
        <input ${common} data-record-relation-target="${escapeAttribute(target)}" type="text" value="${escapeAttribute(recordFieldInputDisplayValue(value))}" placeholder="${recordFieldIsMulti(field) ? "record ids, comma separated" : "record id"}">
        <span class="muted">${escapeHtml(target ? `Loading ${target} records...` : "Relation target is missing")}</span>
        ${fieldError}
      </div>
    `;
  }

  const selected = new Set((Array.isArray(value) ? value : value ? [value] : []).map(String));
  const optionHtml = options.map((record) => {
    const id = String(record.id || "");
    return `
      <option value="${escapeAttribute(id)}" ${selected.has(id) ? "selected" : ""}>
        ${escapeHtml(relationOptionLabel(record))}
      </option>
    `;
  }).concat([...selected]
    .filter((id) => id && !options.some((record) => String(record.id || "") === id))
    .map((id) => `
      <option value="${escapeAttribute(id)}" selected>${escapeHtml(`${id} (not loaded)`)}</option>
    `)).join("");
  const hint = error
    ? `<span class="field-error">${escapeHtml(error)}</span>`
    : `<span class="muted">${escapeHtml(target)} records</span>`;
  if (recordFieldIsMulti(field)) {
    const size = Math.min(Math.max(options.length || 2, 2), 6);
    return `
      <div class="${fieldClass}">
        ${label}
        <select ${common} data-record-relation-target="${escapeAttribute(target)}" multiple size="${size}">${optionHtml}</select>
        ${hint}
        ${fieldError}
      </div>
    `;
  }

  return `
    <div class="${fieldClass}">
      ${label}
      <select ${common} data-record-relation-target="${escapeAttribute(target)}">
        <option value=""></option>
        ${optionHtml}
      </select>
      ${hint}
      ${fieldError}
    </div>
  `;
}

function recordValidationSummaryHtml(collection) {
  const data = recordEditorValidationData();
  const fieldNames = new Set(userCollectionFields(collection).map((field) => field.name));
  const entries = Object.entries(data).filter(([name]) => !fieldNames.has(name));
  if (!entries.length) {
    return "";
  }

  return `
    <div class="validation-summary" id="record-validation-summary">
      <strong>Validation details</strong>
      <ul>
        ${entries.map(([name, detail]) => `<li><code>${escapeHtml(name)}</code>: ${escapeHtml(recordValidationMessage(detail))}</li>`).join("")}
      </ul>
    </div>
  `;
}

function recordFieldValidation(name) {
  const data = recordEditorValidationData();
  const detail = data[name];
  return detail && typeof detail === "object" && !Array.isArray(detail) ? detail : null;
}

function recordEditorValidationData() {
  const data = state.editorValidation;
  return data && typeof data === "object" && !Array.isArray(data) ? data : {};
}

function recordValidationMessage(detail) {
  if (!detail || typeof detail !== "object") {
    return "Invalid value";
  }
  return detail.message || detail.code || "Invalid value";
}

function recordFileValueHtml(fieldName, value) {
  const names = Array.isArray(value)
    ? value
    : value
      ? [value]
      : [];
  if (!names.length) {
    return `<span class="muted">-</span>`;
  }
  return `
    <div class="record-file-list">
      ${names.map((name) => `
        <label>
          <input type="checkbox" data-record-file-delete="${escapeAttribute(fieldName)}" value="${escapeAttribute(name)}">
          <code>${escapeHtml(name)}</code>
        </label>
      `).join("")}
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

function openCreateEditor() {
  state.editorMode = "create";
  state.editorRecordId = "";
  state.editorText = "{}";
  state.editorError = "";
  state.editorValidation = {};
}

function openEditEditor(id) {
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

async function saveRecord() {
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

function recordEditorFileUploads() {
  const uploads = [];
  document.querySelectorAll("[data-record-file]").forEach((input) => {
    Array.from(input.files || []).forEach((file) => {
      if (file && input.dataset.recordFile) {
        const fieldName = state.editorMode === "edit" && input.dataset.recordMulti === "true"
          ? `${input.dataset.recordFile}+`
          : input.dataset.recordFile;
        uploads.push({ fieldName, file });
      }
    });
  });
  return uploads;
}

function recordEditorFileDeletes() {
  const deletes = {};
  document.querySelectorAll("[data-record-file-delete]:checked").forEach((input) => {
    const fieldName = input.dataset.recordFileDelete || "";
    const fileName = input.value || "";
    if (!fieldName || !fileName) {
      return;
    }
    if (!deletes[fieldName]) {
      deletes[fieldName] = [];
    }
    deletes[fieldName].push(fileName);
  });
  return deletes;
}

function applyRecordFileDeletes(payload, deletes) {
  Object.entries(deletes).forEach(([fieldName, names]) => {
    if (names.length) {
      payload[`${fieldName}-`] = names;
    }
  });
}

function recordFormDataPayload(collection, payload, uploads) {
  const form = new FormData();
  const uploadedFields = new Set(uploads.map((upload) => upload.fieldName.replace(/\+$/, "")));
  const fileFields = new Set(userCollectionFields(collection)
    .filter((field) => (field.type || field.kind) === "file")
    .map((field) => field.name));

  Object.entries(payload).forEach(([name, value]) => {
    if (uploadedFields.has(name) && fileFields.has(name)) {
      return;
    }
    appendRecordFormValue(form, collection, name, value);
  });
  uploads.forEach((upload) => {
    form.append(upload.fieldName, upload.file, upload.file.name);
  });
  return form;
}

function appendRecordFormValue(form, collection, name, value) {
  if (value === undefined) {
    return;
  }

  const field = userCollectionFields(collection).find((item) => item.name === name);
  const type = field ? (field.type || field.kind || "text") : "";
  if (type === "file") {
    return;
  }
  if (type === "relation" && recordFieldIsMulti(field) && Array.isArray(value)) {
    value.forEach((item) => form.append(name, String(item)));
    return;
  }
  if (name.endsWith("-") && Array.isArray(value)) {
    value.forEach((item) => form.append(name, String(item)));
    return;
  }
  if ((type === "json" || type === "array" || type === "geoPoint") && value != null) {
    form.append(name, JSON.stringify(value));
    return;
  }
  if (type === "select" && recordFieldIsMulti(field) && value != null) {
    form.append(name, JSON.stringify(value));
    return;
  }
  if (typeof value === "boolean") {
    form.append(name, value ? "true" : "false");
    return;
  }
  if (typeof value === "number") {
    form.append(name, String(value));
    return;
  }
  if (value == null) {
    form.append(name, "");
    return;
  }
  form.append(name, typeof value === "string" ? value : JSON.stringify(value));
}

function validationDataFromError(error) {
  const body = error && error.body;
  const data = body && body.data;
  return data && typeof data === "object" && !Array.isArray(data) ? data : {};
}

function clearRecordValidationFeedback() {
  state.editorError = "";
  state.editorValidation = {};
  const summary = $("record-validation-summary");
  if (summary) {
    summary.remove();
  }
  const editorError = document.querySelector(".record-editor > .error");
  if (editorError) {
    editorError.remove();
  }
  document.querySelectorAll(".field.has-error").forEach((field) => {
    field.classList.remove("has-error");
  });
  document.querySelectorAll(".field-error").forEach((fieldError) => {
    fieldError.remove();
  });
}

function clearRecordFieldValidationFeedback(input) {
  const fieldName = input.dataset.recordField || input.dataset.recordFile || input.dataset.recordFileDelete;
  if (!fieldName || !state.editorValidation[fieldName]) {
    return;
  }

  delete state.editorValidation[fieldName];
  const field = input.closest(".field");
  if (field) {
    field.classList.remove("has-error");
    const fieldError = field.querySelector(".field-error");
    if (fieldError) {
      fieldError.remove();
    }
  }
  if (!Object.keys(recordEditorValidationData()).length) {
    const editorError = document.querySelector(".record-editor > .error");
    if (editorError) {
      editorError.remove();
    }
    state.editorError = "";
  }
}

async function deleteRecord(id) {
  const collection = actions.currentCollection();
  if (!collection || !id || !confirmDangerousAction(`Delete record ${id} from ${collection.name}?`, id)) {
    return;
  }

  try {
    await api(recordPath(collection.name, id), { method: "DELETE" });
    if (state.editorRecordId === id) {
      closeRecordEditor();
    }
    invalidateRelationOptions(collection.name);
    status("Deleted");
    await actions.loadRecords(true);
    actions.render();
  } catch (error) {
    status(error.message, true);
  }
}

function invalidateRelationOptions(collectionName) {
  if (!collectionName) {
    return;
  }
  delete state.relationOptions[collectionName];
  delete state.relationOptionErrors[collectionName];
}
