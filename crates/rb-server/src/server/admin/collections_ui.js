import { $, api, confirmDangerousAction, jsonApi, state, status } from "./state.js";
import { collectionPath, editableCollectionPayload } from "./data_helpers.js";
import { escapeAttribute, escapeHtml } from "./render_helpers.js";

let actions = {
  render() {},
  refresh: async () => {},
  loadRecords: async () => {},
  resetRecordBrowser() {}
};

export function renderCollections(nextActions) {
  actions = nextActions;
  if (!state.token) {
    $("content").innerHTML = `
      <div class="empty">
        <strong>Login or initialize first</strong>
        <span>Collections are only available after a superuser session is active.</span>
      </div>
    `;
    return;
  }

  const rows = state.collections.map((collection) => `
    <tr>
      <td>
        <button type="button" class="link-button" data-collection-name="${escapeAttribute(collection.name || "")}">
          ${escapeHtml(collection.name || "")}
        </button>
      </td>
      <td><span class="pill">${escapeHtml(collection.type || "")}</span></td>
      <td>${collection.system ? "system" : "base"}</td>
      <td>
        <div class="record-actions">
          <button type="button" data-collection-select="${escapeAttribute(collection.name || "")}">Select</button>
          <button type="button" data-collection-edit="${escapeAttribute(collection.name || "")}">Edit</button>
          ${collection.system ? "" : `<button type="button" data-collection-truncate="${escapeAttribute(collection.name || "")}">Truncate</button>`}
          ${collection.system ? "" : `<button type="button" class="danger" data-collection-delete="${escapeAttribute(collection.name || "")}">Delete</button>`}
        </div>
      </td>
    </tr>
  `).join("");

  const body = state.collections.length ? `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Scope</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  ` : `
    <div class="empty">
      <strong>No collections yet</strong>
      <span>Create a collection to start browsing and editing records.</span>
    </div>
  `;

  $("content").innerHTML = `
    <div class="panel-head">
      <h2>Collections</h2>
      <div class="record-actions">
        <button type="button" id="new-collection" class="primary">New</button>
        <button type="button" id="refresh">Refresh</button>
      </div>
    </div>
    ${body}
    ${collectionEditorHtml()}
  `;
  $("new-collection").addEventListener("click", () => {
    openCollectionEditor();
    actions.render();
  });
  $("refresh").addEventListener("click", actions.refresh);
  document.querySelectorAll("[data-collection-name]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.selectedCollection = button.dataset.collectionName || "";
      localStorage.setItem("rusty-base.admin.collection", state.selectedCollection);
      actions.resetRecordBrowser();
      state.view = "records";
      await actions.loadRecords(true);
      actions.render();
    });
  });
  document.querySelectorAll("[data-collection-select]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.selectedCollection = button.dataset.collectionSelect || "";
      localStorage.setItem("rusty-base.admin.collection", state.selectedCollection);
      actions.resetRecordBrowser();
      state.view = "records";
      await actions.loadRecords(true);
      actions.render();
    });
  });
  document.querySelectorAll("[data-collection-edit]").forEach((button) => {
    button.addEventListener("click", async () => {
      await openEditCollectionEditor(button.dataset.collectionEdit || "");
    });
  });
  document.querySelectorAll("[data-collection-truncate]").forEach((button) => {
    button.addEventListener("click", async () => {
      await truncateCollection(button.dataset.collectionTruncate || "");
    });
  });
  document.querySelectorAll("[data-collection-delete]").forEach((button) => {
    button.addEventListener("click", async () => {
      await deleteCollection(button.dataset.collectionDelete || "");
    });
  });
  const save = $("save-collection");
  if (save) {
    save.addEventListener("click", saveCollection);
  }
  const collectionName = $("collection-name-input");
  if (collectionName) {
    collectionName.addEventListener("input", syncCollectionMetaFromControls);
  }
  const collectionType = $("collection-type-select");
  if (collectionType) {
    collectionType.addEventListener("change", () => {
      if (syncCollectionMetaFromControls()) {
        actions.render();
      }
    });
  }
  const collectionViewQuery = $("collection-view-query-input");
  if (collectionViewQuery) {
    collectionViewQuery.addEventListener("input", syncCollectionMetaFromControls);
  }
  const cancel = $("cancel-collection");
  if (cancel) {
    cancel.addEventListener("click", () => {
      closeCollectionEditor();
      actions.render();
    });
  }
  const addField = $("add-collection-field");
  if (addField) {
    addField.addEventListener("click", addCollectionField);
  }
  const cancelFieldEdit = $("cancel-field-edit");
  if (cancelFieldEdit) {
    cancelFieldEdit.addEventListener("click", () => {
      closeCollectionFieldEditor();
      actions.render();
    });
  }
  const fieldType = $("new-field-type");
  if (fieldType) {
    fieldType.addEventListener("change", syncCollectionFieldToolControls);
    syncCollectionFieldToolControls();
  }
  document.querySelectorAll("[data-field-edit]").forEach((button) => {
    button.addEventListener("click", () => {
      openCollectionFieldEditor(Number(button.dataset.fieldEdit));
    });
  });
  document.querySelectorAll("[data-field-remove]").forEach((button) => {
    button.addEventListener("click", () => {
      removeCollectionField(Number(button.dataset.fieldRemove));
    });
  });
}

function collectionEditorHtml() {
  if (!state.collectionEditorOpen) {
    return "";
  }

  const title = state.collectionEditorMode === "edit"
    ? `Edit ${state.collectionEditorName}`
    : "Create collection";
  const draft = collectionEditorDraft();
  return `
    <div class="record-editor">
      <h2>${escapeHtml(title)}</h2>
      ${state.collectionEditorError ? `<div class="error">${escapeHtml(state.collectionEditorError)}</div>` : ""}
      ${collectionMetaToolsHtml(draft)}
      ${collectionFieldToolsHtml(draft)}
      <textarea id="collection-json-input" spellcheck="false">${escapeHtml(state.collectionEditorText)}</textarea>
      <div class="editor-actions">
        <button type="button" id="cancel-collection">Cancel</button>
        <button type="button" id="save-collection" class="primary">Save</button>
      </div>
    </div>
  `;
}

function collectionMetaToolsHtml(draft) {
  if (!draft.ok) {
    return "";
  }

  const payload = draft.value && typeof draft.value === "object" && !Array.isArray(draft.value)
    ? draft.value
    : {};
  const selectedType = ["base", "auth", "view"].includes(payload.type) ? payload.type : "base";
  return `
    <div class="field-tools">
      <div class="field-tools-head">
        <h2>Collection</h2>
        <span class="muted">${escapeHtml(selectedType)}</span>
      </div>
      <div class="collection-tools-form">
        <div class="field">
          <label for="collection-name-input">Name</label>
          <input id="collection-name-input" placeholder="posts" value="${escapeAttribute(payload.name || "")}">
        </div>
        <div class="field">
          <label for="collection-type-select">Type</label>
          <select id="collection-type-select">
            ${collectionTypeOptions(selectedType)}
          </select>
        </div>
        ${selectedType === "view" ? `
          <div class="field field-wide">
            <label for="collection-view-query-input">View SQL</label>
            <textarea id="collection-view-query-input" spellcheck="false" placeholder="SELECT id, created, updated FROM ...">${escapeHtml(payload.viewQuery || "")}</textarea>
          </div>
        ` : ""}
      </div>
    </div>
  `;
}

function collectionFieldToolsHtml(draft) {
  if (!draft.ok) {
    return `
      <div class="field-tools">
        <div class="field-tools-head">
          <h2>Fields</h2>
          <span class="muted">Fix the collection JSON to use field tools.</span>
        </div>
      </div>
    `;
  }

  const fields = Array.isArray(draft.value.fields) ? draft.value.fields : [];
  const editIndex = activeCollectionFieldEditIndex(fields);
  const editingField = editIndex >= 0 ? fields[editIndex] : null;
  const rows = fields.map((field, index) => `
    <tr>
      <td>${escapeHtml(field.name || "")}</td>
      <td><span class="pill">${escapeHtml(field.type || field.kind || "")}</span></td>
      <td>${field.required ? "required" : "-"}</td>
      <td>${escapeHtml(collectionFieldExtra(field))}</td>
      <td>
        <div class="record-actions">
          <button type="button" data-field-edit="${index}">${index === editIndex ? "Editing" : "Edit"}</button>
          <button type="button" class="danger" data-field-remove="${index}">Remove</button>
        </div>
      </td>
    </tr>
  `).join("");
  const editing = Boolean(editingField);
  const fieldName = editingField ? editingField.name || "" : "";
  const fieldType = editingField ? editingField.type || editingField.kind || "text" : "text";
  const fieldOption = editingField ? collectionFieldToolOption(editingField) : "";
  const fieldMin = editingField && editingField.minSelect != null ? String(editingField.minSelect) : "";
  const fieldMax = editingField && editingField.maxSelect != null ? String(editingField.maxSelect) : "";

  return `
    <div class="field-tools">
      <div class="field-tools-head">
        <h2>Fields</h2>
        <span class="muted">${editing ? `Editing ${escapeHtml(fieldName)}` : `${fields.length} user field${fields.length === 1 ? "" : "s"}`}</span>
      </div>
      ${fields.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>Required</th><th>Options</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      ` : `<div class="empty"><strong>No user fields yet</strong><span>Add a field or edit the JSON directly.</span></div>`}
      <div class="field-tools-form">
        <div class="field">
          <label for="new-field-name">Name</label>
          <input id="new-field-name" placeholder="title" value="${escapeAttribute(fieldName)}">
        </div>
        <div class="field">
          <label for="new-field-type">Type</label>
          <select id="new-field-type">
            ${collectionFieldTypeOptions(fieldType)}
          </select>
        </div>
        <div class="field">
          <label for="new-field-option">Options</label>
          <input id="new-field-option" placeholder="draft, published / posts / text/plain" value="${escapeAttribute(fieldOption)}">
        </div>
        <div class="field">
          <label for="new-field-min-select">Min</label>
          <input id="new-field-min-select" type="number" min="0" step="1" placeholder="0" value="${escapeAttribute(fieldMin)}">
        </div>
        <div class="field">
          <label for="new-field-max-select">Max</label>
          <input id="new-field-max-select" type="number" min="1" step="1" placeholder="1" value="${escapeAttribute(fieldMax)}">
        </div>
        <label class="check-field"><input id="new-field-required" type="checkbox" ${editingField && editingField.required ? "checked" : ""}>Required</label>
        <label class="check-field"><input id="new-field-protected" type="checkbox" ${editingField && editingField.protected ? "checked" : ""}>Protected</label>
        ${editing ? `<button type="button" id="cancel-field-edit">Cancel</button>` : ""}
        <button type="button" id="add-collection-field" class="primary">${editing ? "Update" : "Add"}</button>
      </div>
    </div>
  `;
}

function openCollectionEditor() {
  state.collectionEditorOpen = true;
  state.collectionEditorMode = "create";
  state.collectionEditorName = "";
  state.collectionEditorText = JSON.stringify({
    name: "posts",
    type: "base",
    fields: [
      { name: "title", type: "text" }
    ]
  }, null, 2);
  state.collectionEditorError = "";
  state.collectionFieldEditIndex = -1;
}

async function openEditCollectionEditor(name) {
  if (!name) {
    return;
  }

  try {
    const collection = await api(collectionPath(name));
    state.collectionEditorOpen = true;
    state.collectionEditorMode = "edit";
    state.collectionEditorName = collection.name || name;
    state.collectionEditorText = JSON.stringify(editableCollectionPayload(collection), null, 2);
    state.collectionEditorError = "";
    state.collectionFieldEditIndex = -1;
    actions.render();
  } catch (error) {
    status(error.message, true);
  }
}

export function closeCollectionEditor() {
  state.collectionEditorOpen = false;
  state.collectionEditorMode = "";
  state.collectionEditorName = "";
  state.collectionEditorText = "";
  state.collectionEditorError = "";
  state.collectionFieldEditIndex = -1;
}

function collectionEditorDraft() {
  try {
    return { ok: true, value: JSON.parse(state.collectionEditorText || "{}") };
  } catch (error) {
    return { ok: false, error };
  }
}

function readCollectionEditorPayload() {
  const input = $("collection-json-input");
  const text = input ? input.value : state.collectionEditorText;
  return JSON.parse(text || "{}");
}

function writeCollectionEditorPayload(payload) {
  state.collectionEditorText = JSON.stringify(payload, null, 2);
  state.collectionEditorError = "";
  actions.render();
}

function syncCollectionMetaFromControls() {
  const jsonInput = $("collection-json-input");
  let payload = null;
  try {
    payload = readCollectionEditorPayload();
  } catch (error) {
    showCollectionFieldToolError(error.message, jsonInput);
    return;
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    showCollectionFieldToolError("Collection JSON must be an object", jsonInput);
    return;
  }

  payload.name = $("collection-name-input") ? $("collection-name-input").value.trim() : "";
  payload.type = $("collection-type-select") ? $("collection-type-select").value : "base";
  if (payload.type === "view") {
    payload.viewQuery = $("collection-view-query-input")
      ? $("collection-view-query-input").value.trim()
      : payload.viewQuery || "";
  } else {
    delete payload.viewQuery;
  }
  state.collectionEditorText = JSON.stringify(payload, null, 2);
  state.collectionEditorError = "";
  if (jsonInput) {
    jsonInput.value = state.collectionEditorText;
  }
  return true;
}

function activeCollectionFieldEditIndex(fields) {
  const index = Number(state.collectionFieldEditIndex);
  if (!Number.isInteger(index) || index < 0 || index >= fields.length) {
    state.collectionFieldEditIndex = -1;
    return -1;
  }
  return index;
}

function collectionTypeOptions(selectedType) {
  return ["base", "auth", "view"].map((type) => `
    <option value="${type}" ${type === selectedType ? "selected" : ""}>${type}</option>
  `).join("");
}

function collectionFieldTypeOptions(selectedType) {
  return [
    "text",
    "email",
    "number",
    "bool",
    "date",
    "select",
    "relation",
    "file",
    "json",
    "url",
    "editor"
  ].map((type) => `
    <option value="${type}" ${type === selectedType ? "selected" : ""}>${type}</option>
  `).join("");
}

function collectionFieldToolOption(field) {
  const fieldType = field.type || field.kind || "text";
  if (fieldType === "select" && Array.isArray(field.values)) {
    return field.values.join(", ");
  }
  if (fieldType === "relation") {
    return field.collection || "";
  }
  if (fieldType === "file" && Array.isArray(field.mimeTypes)) {
    return field.mimeTypes.join(", ");
  }
  return "";
}

function syncCollectionFieldToolControls() {
  const fieldType = $("new-field-type") ? $("new-field-type").value : "text";
  const option = $("new-field-option");
  if (option) {
    option.disabled = !["select", "relation", "file"].includes(fieldType);
    option.placeholder = {
      select: "draft, published",
      relation: "target collection",
      file: "text/plain, image/png"
    }[fieldType] || "";
    if (option.disabled) {
      option.value = "";
    }
  }
  const minSelect = $("new-field-min-select");
  if (minSelect) {
    minSelect.disabled = fieldType !== "relation";
    if (minSelect.disabled) {
      minSelect.value = "";
    }
  }
  const maxSelect = $("new-field-max-select");
  if (maxSelect) {
    maxSelect.disabled = !["select", "relation", "file"].includes(fieldType);
    if (maxSelect.disabled) {
      maxSelect.value = "";
    }
  }
  const protectedFile = $("new-field-protected");
  if (protectedFile) {
    protectedFile.disabled = fieldType !== "file";
    if (protectedFile.disabled) {
      protectedFile.checked = false;
    }
  }
}

function addCollectionField() {
  const jsonInput = $("collection-json-input");
  let payload = null;
  try {
    payload = readCollectionEditorPayload();
  } catch (error) {
    showCollectionFieldToolError(error.message, jsonInput);
    return;
  }

  const name = ($("new-field-name") ? $("new-field-name").value : "").trim();
  const fieldType = $("new-field-type") ? $("new-field-type").value : "text";
  const option = ($("new-field-option") ? $("new-field-option").value : "").trim();
  const required = Boolean($("new-field-required") && $("new-field-required").checked);
  const protectedFile = Boolean($("new-field-protected") && $("new-field-protected").checked);
  let minSelect = null;
  let maxSelect = null;
  try {
    minSelect = optionalIntegerFieldValue("new-field-min-select", "Min", 0);
    maxSelect = optionalIntegerFieldValue("new-field-max-select", "Max", 1);
  } catch (error) {
    showCollectionFieldToolError(error.message, jsonInput);
    return;
  }

  if (!name) {
    showCollectionFieldToolError("Field name is required", jsonInput);
    return;
  }

  const fields = Array.isArray(payload.fields) ? payload.fields : [];
  const editIndex = activeCollectionFieldEditIndex(fields);
  const existingField = editIndex >= 0 ? fields[editIndex] : null;
  if (fields.some((field, index) => index !== editIndex && field && field.name === name)) {
    showCollectionFieldToolError(`Field '${name}' already exists`, jsonInput);
    return;
  }
  if (fieldType === "relation" && !option) {
    showCollectionFieldToolError("Relation target collection is required", jsonInput);
    return;
  }
  if (fieldType === "select" && !option) {
    showCollectionFieldToolError("Select values are required", jsonInput);
    return;
  }
  if (fieldType !== "relation" && minSelect != null) {
    showCollectionFieldToolError("Min only applies to relation fields", jsonInput);
    return;
  }
  if (!["relation", "file", "select"].includes(fieldType) && maxSelect != null) {
    showCollectionFieldToolError("Max only applies to relation, file, and select fields", jsonInput);
    return;
  }
  if (fieldType !== "file" && protectedFile) {
    showCollectionFieldToolError("Protected only applies to file fields", jsonInput);
    return;
  }

  const field = { name, type: fieldType };
  if (existingField && existingField.id) {
    field.id = existingField.id;
  }
  if (required) {
    field.required = true;
  }
  if (fieldType === "relation") {
    field.collection = option;
    field.maxSelect = maxSelect || 1;
    if (minSelect != null) {
      if (minSelect > field.maxSelect) {
        showCollectionFieldToolError("Min cannot be greater than Max", jsonInput);
        return;
      }
      field.minSelect = minSelect;
    }
  } else if (fieldType === "select" && option) {
    field.values = option.split(",").map((value) => value.trim()).filter(Boolean);
    if (!field.values.length) {
      showCollectionFieldToolError("Select values are required", jsonInput);
      return;
    }
    if (maxSelect != null) {
      field.maxSelect = maxSelect;
    }
  } else if (fieldType === "file") {
    field.maxSelect = maxSelect || 1;
    field.mimeTypes = option.split(",").map((value) => value.trim()).filter(Boolean);
    if (protectedFile) {
      field.protected = true;
    }
  }

  payload.fields = editIndex >= 0
    ? fields.map((item, index) => index === editIndex ? field : item)
    : fields.concat(field);
  state.collectionFieldEditIndex = -1;
  writeCollectionEditorPayload(payload);
}

function openCollectionFieldEditor(index) {
  const jsonInput = $("collection-json-input");
  let payload = null;
  try {
    payload = readCollectionEditorPayload();
  } catch (error) {
    showCollectionFieldToolError(error.message, jsonInput);
    return;
  }
  const fields = Array.isArray(payload.fields) ? payload.fields : [];
  if (!Number.isInteger(index) || index < 0 || index >= fields.length) {
    return;
  }
  state.collectionEditorText = jsonInput ? jsonInput.value : state.collectionEditorText;
  state.collectionEditorError = "";
  state.collectionFieldEditIndex = index;
  actions.render();
}

function closeCollectionFieldEditor() {
  state.collectionFieldEditIndex = -1;
  state.collectionEditorError = "";
}

function optionalIntegerFieldValue(id, label, min) {
  const input = $(id);
  const raw = input ? input.value.trim() : "";
  if (!raw) {
    return null;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${label} must be an integer greater than or equal to ${min}`);
  }
  return value;
}

function showCollectionFieldToolError(message, jsonInput) {
  state.collectionEditorText = jsonInput ? jsonInput.value : state.collectionEditorText;
  state.collectionEditorError = message;
  actions.render();
}

function removeCollectionField(index) {
  let payload = null;
  try {
    payload = readCollectionEditorPayload();
  } catch (error) {
    state.collectionEditorText = $("collection-json-input") ? $("collection-json-input").value : state.collectionEditorText;
    state.collectionEditorError = error.message;
    actions.render();
    return;
  }

  if (!Array.isArray(payload.fields) || !Number.isInteger(index) || index < 0 || index >= payload.fields.length) {
    return;
  }
  if (state.collectionFieldEditIndex === index) {
    state.collectionFieldEditIndex = -1;
  } else if (state.collectionFieldEditIndex > index) {
    state.collectionFieldEditIndex -= 1;
  }
  payload.fields = payload.fields.filter((_, fieldIndex) => fieldIndex !== index);
  writeCollectionEditorPayload(payload);
}

function collectionFieldExtra(field) {
  const parts = [];
  if (field.collection) {
    parts.push(`target: ${field.collection}`);
  }
  if (Array.isArray(field.values) && field.values.length) {
    parts.push(`values: ${field.values.join(", ")}`);
  }
  if (Array.isArray(field.mimeTypes) && field.mimeTypes.length) {
    parts.push(`mime: ${field.mimeTypes.join(", ")}`);
  }
  if (field.minSelect != null) {
    parts.push(`min: ${field.minSelect}`);
  }
  if (field.maxSelect != null) {
    parts.push(`max: ${field.maxSelect}`);
  }
  if (field.protected) {
    parts.push("protected");
  }
  return parts.join("; ");
}

async function saveCollection() {
  const input = $("collection-json-input");
  if (!input) {
    return;
  }

  let payload = null;
  try {
    payload = JSON.parse(input.value || "{}");
  } catch (error) {
    state.collectionEditorText = input.value;
    state.collectionEditorError = error.message;
    actions.render();
    return;
  }

  try {
    const editing = state.collectionEditorMode === "edit";
    const previousName = state.collectionEditorName;
    const saved = state.collectionEditorMode === "edit"
      ? await jsonApi(collectionPath(state.collectionEditorName), payload, "PATCH")
      : await jsonApi("/api/collections", payload, "POST");
    closeCollectionEditor();
    state.selectedCollection = saved && saved.name ? saved.name : payload.name || "";
    if (state.selectedCollection) {
      localStorage.setItem("rusty-base.admin.collection", state.selectedCollection);
      if (previousName && previousName !== state.selectedCollection) {
        delete state.collectionDetails[previousName];
      }
      state.collectionDetails[state.selectedCollection] = saved;
    }
    actions.resetRecordBrowser();
    state.view = "records";
    status(editing ? "Collection saved" : "Collection created");
    await actions.refresh();
  } catch (error) {
    state.collectionEditorText = input.value;
    state.collectionEditorError = error.message;
    actions.render();
  }
}

async function truncateCollection(name) {
  if (!name || !confirmDangerousAction(`Delete all records in ${name}?`, name)) {
    return;
  }

  try {
    await api(`${collectionPath(name)}/truncate`, { method: "DELETE" });
    if (state.selectedCollection === name) {
      await actions.loadRecords(false);
    }
    status("Collection truncated");
    await actions.refresh();
  } catch (error) {
    status(error.message, true);
  }
}

async function deleteCollection(name) {
  if (!name || !confirmDangerousAction(`Delete collection ${name}?`, name)) {
    return;
  }

  try {
    await api(collectionPath(name), { method: "DELETE" });
    delete state.collectionDetails[name];
    if (state.selectedCollection === name) {
      state.selectedCollection = "";
      localStorage.removeItem("rusty-base.admin.collection");
      actions.resetRecordBrowser();
    }
    status("Collection deleted");
    await actions.refresh();
  } catch (error) {
    status(error.message, true);
  }
}
