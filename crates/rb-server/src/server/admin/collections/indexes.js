import { $, state } from "../state.js";
import { escapeHtml } from "../render_helpers.js";

export function collectionIndexToolsHtml(draft, warnings = []) {
  if (!draft.ok) {
    return `
      <div class="field-tools">
        <div class="field-tools-head">
          <h2>Indexes</h2>
          <span class="muted">Fix the collection JSON to use index tools.</span>
        </div>
      </div>
    `;
  }

  const indexes = Array.isArray(draft.value.indexes) ? draft.value.indexes : [];
  const indexWarnings = Array.isArray(warnings) ? warnings : [];
  const rows = indexes.map((index, itemIndex) => `
    <tr>
      <td><code class="record-json">${escapeHtml(index)}</code></td>
      <td>
        <div class="record-actions">
          <button type="button" class="danger" data-index-remove="${itemIndex}">Remove</button>
        </div>
      </td>
    </tr>
  `).join("");

  return `
    <div class="field-tools">
      <div class="field-tools-head">
        <h2>Indexes</h2>
        <span class="muted">${indexes.length} index${indexes.length === 1 ? "" : "es"}</span>
      </div>
      ${collectionIndexWarningsHtml(indexWarnings)}
      ${indexes.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>SQL</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      ` : `<div class="empty"><strong>No indexes yet</strong><span>Add a safe scalar index or edit the JSON directly.</span></div>`}
      <div class="collection-index-form">
        <div class="field">
          <label for="new-index-sql">Index SQL</label>
          <input id="new-index-sql" placeholder="CREATE INDEX idx_posts_title ON posts (title)" value="">
        </div>
        <button type="button" id="add-collection-index" class="primary">Add</button>
      </div>
    </div>
  `;
}

function collectionIndexWarningsHtml(warnings) {
  if (!warnings.length) {
    return "";
  }

  const items = warnings.map((warning) => {
    const index = warning && warning.index ? `<code class="record-json">${escapeHtml(warning.index)}</code>` : "";
    const message = warning && (warning.message || warning.code)
      ? warning.message || warning.code
      : "Index metadata was saved but not executed.";
    return `<li><strong>${escapeHtml(message)}</strong>${index}</li>`;
  }).join("");

  return `
    <div class="collection-index-warnings">
      <strong>Index warnings</strong>
      <ul>${items}</ul>
    </div>
  `;
}

export function bindCollectionIndexTools(callbacks) {
  const addIndex = $("add-collection-index");
  if (addIndex) {
    addIndex.addEventListener("click", () => {
      addCollectionIndex(callbacks);
    });
  }

  document.querySelectorAll("[data-index-remove]").forEach((button) => {
    button.addEventListener("click", () => {
      removeCollectionIndex(Number(button.dataset.indexRemove), callbacks);
    });
  });
}

function addCollectionIndex({ readPayload, showError, writePayload }) {
  const jsonInput = $("collection-json-input");
  let payload = null;
  try {
    payload = readPayload();
  } catch (error) {
    showError(error.message, jsonInput);
    return;
  }

  const sql = ($("new-index-sql") ? $("new-index-sql").value : "").trim();
  if (!sql) {
    showError("Index SQL is required", jsonInput);
    return;
  }

  const indexes = Array.isArray(payload.indexes) ? payload.indexes : [];
  if (indexes.includes(sql)) {
    showError("Index already exists", jsonInput);
    return;
  }
  payload.indexes = indexes.concat(sql);
  writePayload(payload);
}

function removeCollectionIndex(index, { readPayload, render, writePayload }) {
  let payload = null;
  try {
    payload = readPayload();
  } catch (error) {
    state.collectionEditorText = $("collection-json-input") ? $("collection-json-input").value : state.collectionEditorText;
    state.collectionEditorError = error.message;
    render();
    return;
  }

  if (!Array.isArray(payload.indexes) || !Number.isInteger(index) || index < 0 || index >= payload.indexes.length) {
    return;
  }
  payload.indexes = payload.indexes.filter((_, itemIndex) => itemIndex !== index);
  writePayload(payload);
}
