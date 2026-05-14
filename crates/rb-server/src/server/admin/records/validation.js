import { $, state } from "../state.js";
import { userCollectionFields } from "../data_helpers.js";
import { escapeHtml } from "../render_helpers.js";

export function recordValidationSummaryHtml(collection) {
  const data = recordEditorValidationData();
  const fieldNames = new Set(userCollectionFields(collection).map((field) => field.name));
  const entries = Object.entries(data).filter(([name]) => !fieldNames.has(name));
  if (!entries.length) {
    return "";
  }

  return `
    <div class="validation-summary" id="record-validation-summary">
      <strong>Validation details</strong>
      <ul>
        ${entries.map(([name, detail]) => `<li><code>${escapeHtml(name)}</code>: ${escapeHtml(recordValidationMessage(detail))}</li>`).join("")}
      </ul>
    </div>
  `;
}

export function recordFieldValidation(name) {
  const data = recordEditorValidationData();
  const detail = data[name];
  return detail && typeof detail === "object" && !Array.isArray(detail) ? detail : null;
}

export function recordEditorValidationData() {
  const data = state.editorValidation;
  return data && typeof data === "object" && !Array.isArray(data) ? data : {};
}

export function recordValidationMessage(detail) {
  if (!detail || typeof detail !== "object") {
    return "Invalid value";
  }
  return detail.message || detail.code || "Invalid value";
}

export function validationDataFromError(error) {
  const body = error && error.body;
  const data = body && body.data;
  return data && typeof data === "object" && !Array.isArray(data) ? data : {};
}

export function clearRecordValidationFeedback() {
  state.editorError = "";
  state.editorValidation = {};
  const summary = $("record-validation-summary");
  if (summary) {
    summary.remove();
  }
  const editorError = document.querySelector(".record-editor > .error");
  if (editorError) {
    editorError.remove();
  }
  document.querySelectorAll(".field.has-error").forEach((field) => {
    field.classList.remove("has-error");
  });
  document.querySelectorAll(".field-error").forEach((fieldError) => {
    fieldError.remove();
  });
}

export function clearRecordFieldValidationFeedback(input) {
  const fieldName = input.dataset.recordField || input.dataset.recordFile || input.dataset.recordFileDelete;
  if (!fieldName || !state.editorValidation[fieldName]) {
    return;
  }

  delete state.editorValidation[fieldName];
  const field = input.closest(".field");
  if (field) {
    field.classList.remove("has-error");
    const fieldError = field.querySelector(".field-error");
    if (fieldError) {
      fieldError.remove();
    }
  }
  if (!Object.keys(recordEditorValidationData()).length) {
    const editorError = document.querySelector(".record-editor > .error");
    if (editorError) {
      editorError.remove();
    }
    state.editorError = "";
  }
}
