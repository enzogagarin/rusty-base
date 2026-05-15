import { $, api, confirmDangerousAction, state, status } from "../state.js";
import {
  collectionIsView,
  normalizedRecordPerPage,
  recordFieldValuePreview,
  recordPath,
  recordPreview,
  userCollectionFields
} from "../data_helpers.js";
import { escapeAttribute, escapeHtml } from "../render_helpers.js";
import { closeRecordEditor, openCreateEditor, openEditEditor } from "./editor.js";
import { invalidateRelationOptions, relationFieldValuePreview } from "./relations.js";

export function recordNoCollectionHtml() {
  const hasCollections = state.collections.length > 0;
  return hasCollections
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
}

export function bindRecordNoCollectionControls(actions) {
  bindRecordCollectionPicker("record-empty-collection", actions);
  const openSelected = $("open-selected-collection");
  if (openSelected) {
    openSelected.addEventListener("click", async () => {
      const picker = $("record-empty-collection");
      await selectRecordCollection(picker ? picker.value : "", actions);
    });
  }
  $("go-collections").addEventListener("click", async () => {
    await actions.setView("collections");
  });
}

export function recordsBrowserHtml(collection) {
  const readOnly = collectionIsView(collection);
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
      ${readOnly ? "" : `<td>
        <div class="record-actions">
          <button type="button" data-edit-record="${escapeAttribute(record.id || "")}">Edit</button>
          <button type="button" class="danger" data-delete-record="${escapeAttribute(record.id || "")}">Delete</button>
        </div>
      </td>`}
    </tr>
  `).join("");

  return `
    <div class="panel-head">
      <h2>${escapeHtml(collection.name)} records</h2>
      <div class="record-head-controls">
        ${recordCollectionPickerHtml("record-collection-select", collection.name, false)}
        ${readOnly ? `<span class="pill">Read-only</span>` : `<button type="button" id="new-record" class="primary">New</button>`}
        <button type="button" id="refresh-records">Refresh</button>
      </div>
    </div>
    ${recordBrowserControlsHtml()}
    ${state.records.length ? `
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th>${visibleFields.length ? fieldHeaders : "<th>Data</th>"}<th>Created</th><th>Updated</th>${readOnly ? "" : "<th>Actions</th>"}</tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    ` : `
      <div class="empty">
        <strong>${state.recordFilter ? "No matching records" : "No records yet"}</strong>
        <span>${state.recordFilter ? "Adjust the filter or clear it to browse this collection." : readOnly ? "This view has no matching rows." : "Create the first record in this collection."}</span>
      </div>
    `}
  `;
}

export function bindRecordBrowserControls(actions) {
  bindRecordCollectionPicker("record-collection-select", actions);
  bindRecordQueryControls(actions);
  const newRecord = $("new-record");
  if (newRecord) {
    newRecord.addEventListener("click", () => {
      openCreateEditor();
      actions.render();
    });
  }
  const refreshRecords = $("refresh-records");
  if (refreshRecords) {
    refreshRecords.addEventListener("click", async () => {
      await actions.loadRecords(false);
      actions.render();
    });
  }
  document.querySelectorAll("[data-edit-record]").forEach((button) => {
    button.addEventListener("click", () => {
      openEditEditor(button.dataset.editRecord || "");
      actions.render();
    });
  });
  document.querySelectorAll("[data-delete-record]").forEach((button) => {
    button.addEventListener("click", async () => {
      await deleteRecord(button.dataset.deleteRecord || "", actions);
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

function bindRecordCollectionPicker(id, actions) {
  const picker = $(id);
  if (!picker) {
    return;
  }

  picker.addEventListener("change", async () => {
    await selectRecordCollection(picker.value, actions);
  });
}

async function selectRecordCollection(name, actions) {
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

function bindRecordQueryControls(actions) {
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

async function deleteRecord(id, actions) {
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
