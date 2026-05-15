import { $, state } from "../state.js";
import { escapeAttribute, escapeHtml } from "../render_helpers.js";

export function collectionMetaToolsHtml(draft) {
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

export function bindCollectionMetaTools({ readPayload, render, showError }) {
  const collectionName = $("collection-name-input");
  if (collectionName) {
    collectionName.addEventListener("input", () => {
      syncCollectionMetaFromControls({ readPayload, showError });
    });
  }

  const collectionType = $("collection-type-select");
  if (collectionType) {
    collectionType.addEventListener("change", () => {
      if (syncCollectionMetaFromControls({ readPayload, showError })) {
        render();
      }
    });
  }

  const collectionViewQuery = $("collection-view-query-input");
  if (collectionViewQuery) {
    collectionViewQuery.addEventListener("input", () => {
      syncCollectionMetaFromControls({ readPayload, showError });
    });
  }
}

function syncCollectionMetaFromControls({ readPayload, showError }) {
  const jsonInput = $("collection-json-input");
  let payload = null;
  try {
    payload = readPayload();
  } catch (error) {
    showError(error.message, jsonInput);
    return false;
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    showError("Collection JSON must be an object", jsonInput);
    return false;
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

function collectionTypeOptions(selectedType) {
  return ["base", "auth", "view"].map((type) => `
    <option value="${type}" ${type === selectedType ? "selected" : ""}>${type}</option>
  `).join("");
}
