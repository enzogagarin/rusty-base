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
  const fieldType = $("new-field-type");
  if (fieldType) {
    fieldType.addEventListener("change", syncCollectionFieldToolControls);
    syncCollectionFieldToolControls();
  }
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
      ${collectionFieldToolsHtml(draft)}
      <textarea id="collection-json-input" spellcheck="false">${escapeHtml(state.collectionEditorText)}</textarea>
      <div class="editor-actions">
        <button type="button" id="cancel-collection">Cancel</button>
        <button type="button" id="save-collection" class="primary">Save</button>
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
  const rows = fields.map((field, index) => `
    <tr>
      <td>${escapeHtml(field.name || "")}</td>
      <td><span class="pill">${escapeHtml(field.type || field.kind || "")}</span></td>
      <td>${field.required ? "required" : "-"}</td>
      <td>${escapeHtml(collectionFieldExtra(field))}</td>
      <td><button type="button" class="danger" data-field-remove="${index}">Remove</button></td>
    </tr>
  `).join("");

  return `
    <div class="field-tools">
      <div class="field-tools-head">
        <h2>Fields</h2>
        <span class="muted">${fields.length} user field${fields.length === 1 ? "" : "s"}</span>
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
          <input id="new-field-name" placeholder="title">
        </div>
        <div class="field">
          <label for="new-field-type">Type</label>
          <select id="new-field-type">
            <option value="text">text</option>
            <option value="email">email</option>
            <option value="number">number</option>
            <option value="bool">bool</option>
            <option value="date">date</option>
            <option value="select">select</option>
            <option value="relation">relation</option>
            <option value="file">file</option>
            <option value="json">json</option>
            <option value="url">url</option>
            <option value="editor">editor</option>
          </select>
        </div>
        <div class="field">
          <label for="new-field-option">Options</label>
          <input id="new-field-option" placeholder="draft, published / posts / text/plain">
        </div>
        <div class="field">
          <label for="new-field-min-select">Min</label>
          <input id="new-field-min-select" type="number" min="0" step="1" placeholder="0">
        </div>
        <div class="field">
          <label for="new-field-max-select">Max</label>
          <input id="new-field-max-select" type="number" min="1" step="1" placeholder="1">
        </div>
        <label class="check-field"><input id="new-field-required" type="checkbox">Required</label>
        <label class="check-field"><input id="new-field-protected" type="checkbox">Protected</label>
        <button type="button" id="add-collection-field" class="primary">Add</button>
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
    fields: [
      { name: "title", type: "text" }
    ]
  }, null, 2);
  state.collectionEditorError = "";
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
  if (fields.some((field) => field && field.name === name)) {
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

  payload.fields = fields.concat(field);
  writeCollectionEditorPayload(payload);
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
