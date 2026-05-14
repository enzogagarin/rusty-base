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
        <input id="new-field-name" placeholder="field name">
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
        <input id="new-field-option" placeholder="select values or relation target">
        <label class="check-field"><input id="new-field-required" type="checkbox">Required</label>
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

function addCollectionField() {
  let payload = null;
  try {
    payload = readCollectionEditorPayload();
  } catch (error) {
    state.collectionEditorText = $("collection-json-input") ? $("collection-json-input").value : state.collectionEditorText;
    state.collectionEditorError = error.message;
    actions.render();
    return;
  }

  const name = ($("new-field-name") ? $("new-field-name").value : "").trim();
  const fieldType = $("new-field-type") ? $("new-field-type").value : "text";
  const option = ($("new-field-option") ? $("new-field-option").value : "").trim();
  const required = Boolean($("new-field-required") && $("new-field-required").checked);
  if (!name) {
    state.collectionEditorError = "Field name is required";
    state.collectionEditorText = $("collection-json-input") ? $("collection-json-input").value : state.collectionEditorText;
    actions.render();
    return;
  }

  const fields = Array.isArray(payload.fields) ? payload.fields : [];
  if (fields.some((field) => field && field.name === name)) {
    state.collectionEditorError = `Field '${name}' already exists`;
    state.collectionEditorText = $("collection-json-input") ? $("collection-json-input").value : state.collectionEditorText;
    actions.render();
    return;
  }
  if (fieldType === "relation" && !option) {
    state.collectionEditorError = "Relation target collection is required";
    state.collectionEditorText = $("collection-json-input") ? $("collection-json-input").value : state.collectionEditorText;
    actions.render();
    return;
  }

  const field = { name, type: fieldType };
  if (required) {
    field.required = true;
  }
  if (fieldType === "relation") {
    if (option) {
      field.collection = option;
    }
    field.maxSelect = 1;
  } else if (fieldType === "select" && option) {
    field.values = option.split(",").map((value) => value.trim()).filter(Boolean);
  } else if (fieldType === "file") {
    field.maxSelect = 1;
  }

  payload.fields = fields.concat(field);
  writeCollectionEditorPayload(payload);
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
  if (field.collection) {
    return `target: ${field.collection}`;
  }
  if (Array.isArray(field.values) && field.values.length) {
    return `values: ${field.values.join(", ")}`;
  }
  if (field.maxSelect != null) {
    return `max: ${field.maxSelect}`;
  }
  return "";
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

