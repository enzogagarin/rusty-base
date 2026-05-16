import { $, state } from "../state.js";
import { escapeAttribute, escapeHtml } from "../render_helpers.js";
import {
  applyCollectionFieldAdvancedOptions,
  collectionFieldAdvancedOptionsHtml,
  readCollectionFieldAdvancedOptions,
  syncCollectionFieldAdvancedOptionControls
} from "./field_options.js";

export function collectionFieldToolsHtml(draft) {
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
      ${collectionFieldAdvancedOptionsHtml(editingField, fieldType)}
    </div>
  `;
}

export function bindCollectionFieldTools(callbacks) {
  const addField = $("add-collection-field");
  if (addField) {
    addField.addEventListener("click", () => {
      addCollectionField(callbacks);
    });
  }

  const cancelFieldEdit = $("cancel-field-edit");
  if (cancelFieldEdit) {
    cancelFieldEdit.addEventListener("click", () => {
      closeCollectionFieldEditor();
      callbacks.render();
    });
  }

  const fieldType = $("new-field-type");
  if (fieldType) {
    fieldType.addEventListener("change", () => {
      syncCollectionFieldToolControls();
      syncCollectionFieldAdvancedOptionControls();
    });
    syncCollectionFieldToolControls();
    syncCollectionFieldAdvancedOptionControls();
  }

  document.querySelectorAll("[data-field-edit]").forEach((button) => {
    button.addEventListener("click", () => {
      openCollectionFieldEditor(Number(button.dataset.fieldEdit), callbacks);
    });
  });

  document.querySelectorAll("[data-field-remove]").forEach((button) => {
    button.addEventListener("click", () => {
      removeCollectionField(Number(button.dataset.fieldRemove), callbacks);
    });
  });
}

export function closeCollectionFieldEditor() {
  state.collectionFieldEditIndex = -1;
  state.collectionEditorError = "";
}

function activeCollectionFieldEditIndex(fields) {
  const index = Number(state.collectionFieldEditIndex);
  if (!Number.isInteger(index) || index < 0 || index >= fields.length) {
    state.collectionFieldEditIndex = -1;
    return -1;
  }
  return index;
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

function addCollectionField({ readPayload, showError, writePayload }) {
  const jsonInput = $("collection-json-input");
  let payload = null;
  try {
    payload = readPayload();
  } catch (error) {
    showError(error.message, jsonInput);
    return;
  }

  const name = ($("new-field-name") ? $("new-field-name").value : "").trim();
  const fieldType = $("new-field-type") ? $("new-field-type").value : "text";
  const option = ($("new-field-option") ? $("new-field-option").value : "").trim();
  const required = Boolean($("new-field-required") && $("new-field-required").checked);
  const protectedFile = Boolean($("new-field-protected") && $("new-field-protected").checked);
  let minSelect = null;
  let maxSelect = null;
  let advancedOptions = null;
  try {
    minSelect = optionalIntegerFieldValue("new-field-min-select", "Min", 0);
    maxSelect = optionalIntegerFieldValue("new-field-max-select", "Max", 1);
    advancedOptions = readCollectionFieldAdvancedOptions(fieldType);
  } catch (error) {
    showError(error.message, jsonInput);
    return;
  }

  if (!name) {
    showError("Field name is required", jsonInput);
    return;
  }

  const fields = Array.isArray(payload.fields) ? payload.fields : [];
  const editIndex = activeCollectionFieldEditIndex(fields);
  const existingField = editIndex >= 0 ? fields[editIndex] : null;
  if (fields.some((field, index) => index !== editIndex && field && field.name === name)) {
    showError(`Field '${name}' already exists`, jsonInput);
    return;
  }
  if (fieldType === "relation" && !option) {
    showError("Relation target collection is required", jsonInput);
    return;
  }
  if (fieldType === "select" && !option) {
    showError("Select values are required", jsonInput);
    return;
  }
  if (fieldType !== "relation" && minSelect != null) {
    showError("Min only applies to relation fields", jsonInput);
    return;
  }
  if (!["relation", "file", "select"].includes(fieldType) && maxSelect != null) {
    showError("Max only applies to relation, file, and select fields", jsonInput);
    return;
  }
  if (fieldType !== "file" && protectedFile) {
    showError("Protected only applies to file fields", jsonInput);
    return;
  }

  const field = { name, type: fieldType };
  if (existingField && existingField.id) {
    field.id = existingField.id;
  }
  if (required) {
    field.required = true;
  }
  applyCollectionFieldAdvancedOptions(field, advancedOptions);
  if (fieldType === "relation") {
    field.collection = option;
    field.maxSelect = maxSelect || 1;
    if (minSelect != null) {
      if (minSelect > field.maxSelect) {
        showError("Min cannot be greater than Max", jsonInput);
        return;
      }
      field.minSelect = minSelect;
    }
  } else if (fieldType === "select" && option) {
    field.values = option.split(",").map((value) => value.trim()).filter(Boolean);
    if (!field.values.length) {
      showError("Select values are required", jsonInput);
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
  writePayload(payload);
}

function openCollectionFieldEditor(index, { readPayload, render, showError }) {
  const jsonInput = $("collection-json-input");
  let payload = null;
  try {
    payload = readPayload();
  } catch (error) {
    showError(error.message, jsonInput);
    return;
  }
  const fields = Array.isArray(payload.fields) ? payload.fields : [];
  if (!Number.isInteger(index) || index < 0 || index >= fields.length) {
    return;
  }
  state.collectionEditorText = jsonInput ? jsonInput.value : state.collectionEditorText;
  state.collectionEditorError = "";
  state.collectionFieldEditIndex = index;
  render();
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

function removeCollectionField(index, { readPayload, render, writePayload }) {
  let payload = null;
  try {
    payload = readPayload();
  } catch (error) {
    state.collectionEditorText = $("collection-json-input") ? $("collection-json-input").value : state.collectionEditorText;
    state.collectionEditorError = error.message;
    render();
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
  writePayload(payload);
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
  if (field.hidden) {
    parts.push("hidden");
  }
  if (field.presentable) {
    parts.push("presentable");
  }
  if (field.cascadeDelete) {
    parts.push("cascade");
  }
  if (field.min != null) {
    parts.push(`min: ${field.min}`);
  }
  if (field.max != null) {
    parts.push(`max: ${field.max}`);
  }
  if (field.maxSize != null) {
    parts.push(`size: ${field.maxSize}`);
  }
  if (field.pattern) {
    parts.push(`pattern: ${field.pattern}`);
  }
  return parts.join("; ");
}
