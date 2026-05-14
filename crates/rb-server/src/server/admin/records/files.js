import { state, status } from "../state.js";
import { filePath, recordFieldIsMulti, userCollectionFields } from "../data_helpers.js";
import { escapeAttribute, escapeHtml } from "../render_helpers.js";

export function recordFileValueHtml(fieldName, value, recordId) {
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
        <div class="record-file-item">
          <label>
            <input type="checkbox" data-record-file-delete="${escapeAttribute(fieldName)}" value="${escapeAttribute(name)}">
            <code>${escapeHtml(name)}</code>
          </label>
          ${recordId ? `<button type="button" class="link-button" data-record-file-download="${escapeAttribute(name)}">Download</button>` : ""}
        </div>
      `).join("")}
    </div>
  `;
}

export function bindRecordFileControls(actions, currentEditorRecordId, clearRecordFieldValidationFeedback) {
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
  document.querySelectorAll("[data-record-file-download]").forEach((button) => {
    button.addEventListener("click", async () => {
      await downloadRecordFile(button.dataset.recordFileDownload || "", actions, currentEditorRecordId);
    });
  });
}

export function recordEditorFileUploads() {
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

export function recordEditorFileDeletes() {
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

export function applyRecordFileDeletes(payload, deletes) {
  Object.entries(deletes).forEach(([fieldName, names]) => {
    if (names.length) {
      payload[`${fieldName}-`] = names;
    }
  });
}

export async function downloadRecordFile(filename, actions, currentEditorRecordId) {
  const collection = actions.currentCollection();
  const recordId = currentEditorRecordId();
  if (!collection || !recordId || !filename) {
    return;
  }

  try {
    const response = await fetch(filePath(collection.name, recordId, filename), {
      headers: state.token ? { Authorization: `Bearer ${state.token}` } : {}
    });
    if (!response.ok) {
      throw new Error(await recordFileResponseError(response));
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    status("File downloaded");
  } catch (error) {
    status(error.message, true);
  }
}

async function recordFileResponseError(response) {
  const text = await response.text();
  try {
    const body = JSON.parse(text);
    return body && body.message ? body.message : `${response.status}`;
  } catch (_) {
    return text || `${response.status}`;
  }
}

export function recordFormDataPayload(collection, payload, uploads) {
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
