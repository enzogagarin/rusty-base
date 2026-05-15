import { $, api, jsonApi, state, status } from "../state.js";
import { escapeHtml } from "../render_helpers.js";

let actions = {
  refresh: async () => {},
  render() {}
};

export async function openCollectionExport(render) {
  state.collectionTransferOpen = true;
  state.collectionTransferMode = "export";
  state.collectionTransferError = "";
  state.collectionTransferDeleteMissing = false;
  state.collectionTransferText = "Loading export...";
  render();

  try {
    const payload = await api("/api/collections/meta/export");
    state.collectionTransferText = JSON.stringify(payload, null, 2);
    status("Collections exported");
  } catch (error) {
    state.collectionTransferError = error.message;
    status(error.message, true);
  }
  render();
}

export function openCollectionImport(render) {
  state.collectionTransferOpen = true;
  state.collectionTransferMode = "import";
  state.collectionTransferError = "";
  state.collectionTransferDeleteMissing = false;
  state.collectionTransferText = JSON.stringify({ collections: [] }, null, 2);
  render();
}

export function closeCollectionTransfer() {
  state.collectionTransferOpen = false;
  state.collectionTransferMode = "";
  state.collectionTransferText = "";
  state.collectionTransferError = "";
  state.collectionTransferDeleteMissing = false;
}

export function collectionTransferHtml() {
  if (!state.collectionTransferOpen) {
    return "";
  }

  const importing = state.collectionTransferMode === "import";
  return `
    <div class="record-editor">
      <h2>${importing ? "Import collections" : "Export collections"}</h2>
      ${state.collectionTransferError ? `<div class="error">${escapeHtml(state.collectionTransferError)}</div>` : ""}
      ${importing ? `
        <label class="check-field">
          <input id="collection-import-delete-missing" type="checkbox" ${state.collectionTransferDeleteMissing ? "checked" : ""}>
          Delete missing collections
        </label>
      ` : ""}
      <textarea id="collection-transfer-input" spellcheck="false">${escapeHtml(state.collectionTransferText)}</textarea>
      <div class="editor-actions">
        <button type="button" id="cancel-collection-transfer">Close</button>
        ${importing ? `<button type="button" id="run-collection-import" class="primary">Import</button>` : `<button type="button" id="refresh-collection-export">Refresh export</button>`}
      </div>
    </div>
  `;
}

export function bindCollectionTransferControls(nextActions) {
  actions = nextActions;
  if (!state.collectionTransferOpen) {
    return;
  }

  $("cancel-collection-transfer").addEventListener("click", () => {
    closeCollectionTransfer();
    actions.render();
  });

  if (state.collectionTransferMode === "export") {
    $("refresh-collection-export").addEventListener("click", async () => {
      await openCollectionExport(actions.render);
    });
    return;
  }

  const deleteMissing = $("collection-import-delete-missing");
  deleteMissing.addEventListener("change", () => {
    state.collectionTransferDeleteMissing = deleteMissing.checked;
  });
  $("run-collection-import").addEventListener("click", importCollections);
}

async function importCollections() {
  const input = $("collection-transfer-input");
  let payload = null;
  try {
    payload = JSON.parse(input.value || "{}");
  } catch (error) {
    state.collectionTransferText = input.value;
    state.collectionTransferError = error.message;
    actions.render();
    return;
  }

  if (Array.isArray(payload)) {
    payload = { collections: payload };
  }
  payload.deleteMissing = Boolean($("collection-import-delete-missing")?.checked);

  try {
    await jsonApi("/api/collections/import", payload, "PUT");
    closeCollectionTransfer();
    status("Collections imported");
    await actions.refresh();
  } catch (error) {
    state.collectionTransferText = input.value;
    state.collectionTransferError = error.message;
    status(error.message, true);
    actions.render();
  }
}
