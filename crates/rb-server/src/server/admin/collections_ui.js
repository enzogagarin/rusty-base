import { $, api, confirmDangerousAction, jsonApi, state, status } from "./state.js";
import { collectionPath, editableCollectionPayload } from "./data_helpers.js";
import { escapeAttribute, escapeHtml } from "./render_helpers.js";
import { bindCollectionFieldTools, closeCollectionFieldEditor, collectionFieldToolsHtml } from "./collections/fields.js";
import {
  bindCollectionTransferControls,
  closeCollectionTransfer,
  collectionTransferHtml,
  openCollectionExport,
  openCollectionImport
} from "./collections/import_export.js";
import { bindCollectionMetaTools, collectionMetaToolsHtml } from "./collections/meta.js";

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
        <button type="button" id="export-collections">Export</button>
        <button type="button" id="import-collections">Import</button>
        <button type="button" id="refresh">Refresh</button>
      </div>
    </div>
    ${body}
    ${collectionEditorHtml()}
    ${collectionTransferHtml()}
  `;
  $("new-collection").addEventListener("click", () => {
    closeCollectionTransfer();
    openCollectionEditor();
    actions.render();
  });
  $("export-collections").addEventListener("click", async () => {
    closeCollectionEditor();
    await openCollectionExport(actions.render);
  });
  $("import-collections").addEventListener("click", () => {
    closeCollectionEditor();
    openCollectionImport(actions.render);
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
  bindCollectionMetaTools({
    readPayload: readCollectionEditorPayload,
    render: actions.render,
    showError: showCollectionToolError
  });
  bindCollectionFieldTools({
    readPayload: readCollectionEditorPayload,
    render: actions.render,
    showError: showCollectionToolError,
    writePayload: writeCollectionEditorPayload
  });
  bindCollectionTransferControls({
    refresh: actions.refresh,
    render: actions.render
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

export { closeCollectionTransfer };

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

function showCollectionToolError(message, jsonInput) {
  state.collectionEditorText = jsonInput ? jsonInput.value : state.collectionEditorText;
  state.collectionEditorError = message;
  actions.render();
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
