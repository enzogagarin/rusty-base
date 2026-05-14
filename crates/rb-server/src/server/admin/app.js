import { $, api, confirmDangerousAction, jsonApi, state, status, tokenKey } from "./state.js";
import { closeCollectionEditor, renderCollections } from "./collections_ui.js";
import {
  collectionPath,
  collectionRecordsPath,
  editableRecordPayload,
  recordFieldInputDisplayValue,
  recordFieldIsMulti,
  recordFieldValuePreview,
  recordPath,
  recordPreview,
  userCollectionFields
} from "./data_helpers.js";
import { escapeAttribute, escapeHtml, metric, row, title } from "./render_helpers.js";

async function refresh() {
  state.error = "";
  try {
    const health = await api("/api/health");
    state.health = health.message || "ok";
  } catch (error) {
    state.health = "offline";
    state.error = error.message;
  }

  if (state.token) {
    try {
      const collections = await api("/api/collections?fields=items.id,items.name,items.type,items.system,totalItems");
      state.collections = collections.items || [];
      ensureSelectedCollection();
    } catch (error) {
      state.collections = [];
      state.collectionDetails = {};
      state.selectedCollection = "";
      state.records = [];
      state.recordCount = 0;
      state.recordTotalPages = 1;
      state.error = error.message;
    }

    if (state.selectedCollection) {
      await loadRecords(false);
    }

    try {
      state.settings = await api("/api/settings?fields=meta.appName,meta.appURL,batch.enabled,batch.maxRequests,rateLimits.enabled");
    } catch (error) {
      state.settings = null;
      state.error = error.message;
    }
  } else {
    state.collections = [];
    state.collectionDetails = {};
    state.selectedCollection = "";
    state.records = [];
    state.recordCount = 0;
    state.recordTotalPages = 1;
    state.settings = null;
  }

  render();
}

function render() {
  $("health").textContent = state.health;
  $("session").textContent = state.token ? "Superuser token active" : "No token";
  status(state.error || "Ready", Boolean(state.error));
  document.querySelectorAll(".nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === state.view);
  });

  const appName = state.settings && state.settings.meta ? state.settings.meta.appName : "Rusty Base";
  $("metrics").innerHTML = [
    metric("App", appName),
    metric("Collections", String(state.collections.length)),
    metric("Records", state.selectedCollection ? String(state.recordCount) : "-")
  ].join("");

  $("view-title").textContent = title(state.view);
  if (state.view === "collections") {
    renderCollections({ render, refresh, loadRecords, resetRecordBrowser });
  } else if (state.view === "records") {
    renderRecords();
  } else if (state.view === "settings") {
    renderSettings();
  } else {
    renderOverview();
  }
}

function renderOverview() {
  $("content").innerHTML = `
    <div class="panel-head">
      <h2>Instance</h2>
      <button type="button" id="refresh">Refresh</button>
    </div>
    <div class="panel-body">
      ${row("Health", state.health)}
      ${row("Session", state.token ? "active" : "none")}
      ${row("Collections", String(state.collections.length))}
    </div>
  `;
  $("refresh").addEventListener("click", refresh);
}

function renderRecords() {
  const collection = currentCollection();
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
    $("content").innerHTML = `
      <div class="empty">
        <strong>No collection selected</strong>
        <span>Create or select a collection before browsing records.</span>
        <div class="empty-actions">
          <button type="button" id="go-collections" class="primary">Go to Collections</button>
        </div>
      </div>
    `;
    $("go-collections").addEventListener("click", async () => {
      await setView("collections");
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
        ? visibleFields.map((field) => `<td>${recordFieldValuePreview(record, field)}</td>`).join("")
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
      <div class="record-actions">
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
  bindRecordBrowserControls();
  $("new-record").addEventListener("click", () => {
    openCreateEditor();
    render();
  });
  $("refresh-records").addEventListener("click", async () => {
    await loadRecords(false);
    render();
  });
  document.querySelectorAll("[data-edit-record]").forEach((button) => {
    button.addEventListener("click", () => {
      openEditEditor(button.dataset.editRecord || "");
      render();
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
      render();
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

function recordBrowserControlsHtml() {
  const perPage = normalizedRecordPerPage();
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
    await loadRecords(true);
    render();
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
    await loadRecords(true);
    render();
  });
  $("record-prev-page").addEventListener("click", async () => {
    if (state.recordPage <= 1) {
      return;
    }
    state.recordPage -= 1;
    await loadRecords(true);
    render();
  });
  $("record-next-page").addEventListener("click", async () => {
    const totalPages = Math.max(1, Number(state.recordTotalPages) || 1);
    if (state.recordPage >= totalPages) {
      return;
    }
    state.recordPage += 1;
    await loadRecords(true);
    render();
  });
}

function recordEditorHtml() {
  if (!state.editorMode) {
    return "";
  }

  const title = state.editorMode === "edit" ? `Edit ${state.editorRecordId}` : "Create record";
  const collection = currentCollection();
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

function closeRecordEditor() {
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
  const collection = currentCollection();
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
    render();
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
    status("Saved");
    await loadRecords(true);
    render();
  } catch (error) {
    state.editorText = input.value;
    state.editorError = error.message;
    state.editorValidation = validationDataFromError(error);
    render();
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
  const collection = currentCollection();
  if (!collection || !id || !confirmDangerousAction(`Delete record ${id} from ${collection.name}?`, id)) {
    return;
  }

  try {
    await api(recordPath(collection.name, id), { method: "DELETE" });
    if (state.editorRecordId === id) {
      closeRecordEditor();
    }
    status("Deleted");
    await loadRecords(true);
    render();
  } catch (error) {
    status(error.message, true);
  }
}

function renderSettings() {
  const settings = state.settings || {};
  const meta = settings.meta || {};
  const batch = settings.batch || {};
  const rateLimits = settings.rateLimits || {};
  $("content").innerHTML = `
    <div class="panel-head">
      <h2>Settings</h2>
      <button type="button" id="refresh">Refresh</button>
    </div>
    <div class="panel-body">
      ${row("App name", meta.appName || "-")}
      ${row("App URL", meta.appURL || "-")}
      ${row("Batch", batch.enabled === false ? "disabled" : "enabled")}
      ${row("Max requests", batch.maxRequests == null ? "-" : String(batch.maxRequests))}
      ${row("Rate limits", rateLimits.enabled ? "enabled" : "disabled")}
    </div>
  `;
  $("refresh").addEventListener("click", refresh);
}

async function setView(view) {
  state.view = view;
  if (view === "records") {
    ensureSelectedCollection();
    await loadRecords(true);
  }
  render();
}

function ensureSelectedCollection() {
  if (state.collections.some((collection) => collection.name === state.selectedCollection)) {
    return;
  }
  const previousCollection = state.selectedCollection;
  state.selectedCollection = state.collections[0] ? state.collections[0].name : "";
  if (state.selectedCollection) {
    localStorage.setItem("rusty-base.admin.collection", state.selectedCollection);
  }
  if (previousCollection !== state.selectedCollection) {
    resetRecordBrowser();
  }
}

function currentCollection() {
  return state.collectionDetails[state.selectedCollection]
    || state.collections.find((collection) => collection.name === state.selectedCollection)
    || null;
}

async function loadRecords(showErrors = true) {
  let collection = currentCollection();
  if (!state.token || !collection) {
    state.records = [];
    state.recordCount = 0;
    state.recordTotalPages = 1;
    return;
  }

  try {
    collection = await ensureCollectionDetails(collection.name);
    const page = await api(recordListPath(collection.name));
    state.records = page.items || [];
    state.recordCount = page.totalItems == null ? state.records.length : page.totalItems;
    state.recordPage = Number(page.page) || state.recordPage || 1;
    state.recordPerPage = normalizedRecordPerPage(Number(page.perPage) || state.recordPerPage);
    state.recordTotalPages = Number(page.totalPages) || Math.max(1, Math.ceil(state.recordCount / state.recordPerPage));
    if (showErrors) {
      state.error = "";
    }
  } catch (error) {
    state.records = [];
    state.recordCount = 0;
    state.recordTotalPages = 1;
    if (showErrors) {
      state.error = error.message;
    }
  }
}

function recordListPath(collectionName) {
  state.recordPage = Math.max(1, Number(state.recordPage) || 1);
  state.recordPerPage = normalizedRecordPerPage();

  const params = new URLSearchParams();
  params.set("page", String(state.recordPage));
  params.set("perPage", String(state.recordPerPage));
  const sort = String(state.recordSort || "").trim();
  const filter = String(state.recordFilter || "").trim();
  if (sort) {
    params.set("sort", sort);
  }
  if (filter) {
    params.set("filter", filter);
  }
  return `${collectionRecordsPath(collectionName)}?${params.toString()}`;
}

function normalizedRecordPerPage(value = state.recordPerPage) {
  const perPage = Number(value) || 20;
  return [10, 20, 50, 100].includes(perPage) ? perPage : 20;
}

function resetRecordBrowser() {
  state.records = [];
  state.recordCount = 0;
  state.recordPage = 1;
  state.recordTotalPages = 1;
  state.recordFilter = "";
  state.recordSort = "-created";
  closeRecordEditor();
}

async function ensureCollectionDetails(collectionName) {
  const cached = state.collectionDetails[collectionName];
  if (cached && Array.isArray(cached.fields)) {
    return cached;
  }

  const collection = await api(collectionPath(collectionName));
  state.collectionDetails[collection.name || collectionName] = collection;
  return collection;
}

document.querySelectorAll(".nav button").forEach((button) => {
  button.addEventListener("click", () => {
    setView(button.dataset.view);
  });
});

$("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const body = await jsonApi("/api/collections/_superusers/auth-with-password", {
      identity: $("email").value,
      password: $("password").value
    });
    state.token = body.token || "";
    localStorage.setItem(tokenKey, state.token);
    status("Logged in");
    await refresh();
  } catch (error) {
    status(error.message, true);
  }
});

$("init").addEventListener("click", async () => {
  try {
    await jsonApi("/api/collections", {
      name: "_superusers",
      type: "auth",
      fields: [{ name: "email", type: "email" }]
    }).catch(() => null);
    await jsonApi("/api/collections/_superusers/records", {
      email: $("email").value,
      password: $("password").value,
      passwordConfirm: $("password").value
    });
    const body = await jsonApi("/api/collections/_superusers/auth-with-password", {
      identity: $("email").value,
      password: $("password").value
    });
    state.token = body.token || "";
    localStorage.setItem(tokenKey, state.token);
    status("Initialized and logged in");
    await refresh();
  } catch (error) {
    status(error.message, true);
  }
});

$("logout").addEventListener("click", async () => {
  state.token = "";
  localStorage.removeItem(tokenKey);
  state.collections = [];
  state.collectionDetails = {};
  resetRecordBrowser();
  state.settings = null;
  closeCollectionEditor();
  await refresh();
});

refresh();
