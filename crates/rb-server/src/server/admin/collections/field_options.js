import { $ } from "../state.js";
import { escapeAttribute } from "../render_helpers.js";

const MIN_MAX_TYPES = ["text", "email", "number"];
const PATTERN_TYPES = ["text", "email"];
const MAX_SIZE_TYPES = ["file", "json", "editor"];
const DOMAIN_TYPES = ["email", "url"];

export function collectionFieldAdvancedOptionsHtml(field, fieldType) {
  const type = fieldType || "text";
  return `
    <div class="field-options-grid">
      <label class="check-field"><input id="new-field-hidden" type="checkbox" ${field && field.hidden ? "checked" : ""}>Hidden</label>
      <label class="check-field"><input id="new-field-presentable" type="checkbox" ${field && field.presentable ? "checked" : ""}>Presentable</label>
      <label class="check-field"><input id="new-field-cascade-delete" type="checkbox" ${field && field.cascadeDelete ? "checked" : ""}>Cascade delete</label>
      <div class="field">
        <label for="new-field-min-value">${type === "number" ? "Min value" : "Min length"}</label>
        <input id="new-field-min-value" type="number" min="0" step="1" value="${escapeAttribute(optionValue(field, "min"))}">
      </div>
      <div class="field">
        <label for="new-field-max-value">${type === "number" ? "Max value" : "Max length"}</label>
        <input id="new-field-max-value" type="number" min="0" step="1" value="${escapeAttribute(optionValue(field, "max"))}">
      </div>
      <div class="field">
        <label for="new-field-max-size">Max size</label>
        <input id="new-field-max-size" type="number" min="1" step="1" value="${escapeAttribute(optionValue(field, "maxSize"))}">
      </div>
      <div class="field field-wide">
        <label for="new-field-pattern">Pattern</label>
        <input id="new-field-pattern" placeholder="^[A-Z].+" value="${escapeAttribute(field && field.pattern ? field.pattern : "")}">
      </div>
      <div class="field">
        <label for="new-field-only-domains">Only domains</label>
        <input id="new-field-only-domains" placeholder="example.com" value="${escapeAttribute(listValue(field, "onlyDomains"))}">
      </div>
      <div class="field">
        <label for="new-field-except-domains">Except domains</label>
        <input id="new-field-except-domains" placeholder="blocked.example.com" value="${escapeAttribute(listValue(field, "exceptDomains"))}">
      </div>
      <div class="field">
        <label for="new-field-thumbs">Thumbs</label>
        <input id="new-field-thumbs" placeholder="100x100, 320x0" value="${escapeAttribute(listValue(field, "thumbs"))}">
      </div>
    </div>
  `;
}

export function syncCollectionFieldAdvancedOptionControls() {
  const fieldType = $("new-field-type") ? $("new-field-type").value : "text";
  toggleNumeric("new-field-min-value", MIN_MAX_TYPES.includes(fieldType));
  toggleNumeric("new-field-max-value", MIN_MAX_TYPES.includes(fieldType));
  toggleNumeric("new-field-max-size", MAX_SIZE_TYPES.includes(fieldType));

  const pattern = $("new-field-pattern");
  if (pattern) {
    pattern.disabled = !PATTERN_TYPES.includes(fieldType);
    if (pattern.disabled) {
      pattern.value = "";
    }
  }
  toggleList("new-field-only-domains", DOMAIN_TYPES.includes(fieldType));
  toggleList("new-field-except-domains", DOMAIN_TYPES.includes(fieldType));
  toggleList("new-field-thumbs", fieldType === "file");

  const cascadeDelete = $("new-field-cascade-delete");
  if (cascadeDelete) {
    cascadeDelete.disabled = fieldType !== "relation";
    if (cascadeDelete.disabled) {
      cascadeDelete.checked = false;
    }
  }
}

export function readCollectionFieldAdvancedOptions(fieldType) {
  const options = {
    hidden: checked("new-field-hidden"),
    presentable: checked("new-field-presentable"),
    cascadeDelete: checked("new-field-cascade-delete"),
    min: optionalIntegerFieldValue("new-field-min-value", "Min", 0),
    max: optionalIntegerFieldValue("new-field-max-value", "Max", 0),
    maxSize: optionalIntegerFieldValue("new-field-max-size", "Max size", 1),
    pattern: controlValue("new-field-pattern"),
    onlyDomains: commaList(controlValue("new-field-only-domains")),
    exceptDomains: commaList(controlValue("new-field-except-domains")),
    thumbs: commaList(controlValue("new-field-thumbs"))
  };

  if (!MIN_MAX_TYPES.includes(fieldType) && (options.min != null || options.max != null)) {
    throw new Error("Min and Max only apply to text, email, and number fields");
  }
  if (!PATTERN_TYPES.includes(fieldType) && options.pattern) {
    throw new Error("Pattern only applies to text and email fields");
  }
  if (!MAX_SIZE_TYPES.includes(fieldType) && options.maxSize != null) {
    throw new Error("Max size only applies to file, json, and editor fields");
  }
  if (!DOMAIN_TYPES.includes(fieldType) && (options.onlyDomains.length || options.exceptDomains.length)) {
    throw new Error("Domain options only apply to email and url fields");
  }
  if (fieldType !== "file" && options.thumbs.length) {
    throw new Error("Thumbs only apply to file fields");
  }
  if (fieldType !== "relation" && options.cascadeDelete) {
    throw new Error("Cascade delete only applies to relation fields");
  }
  if (
    options.min != null
    && options.max != null
    && (fieldType === "number" ? options.min > options.max : options.max > 0 && options.min > options.max)
  ) {
    throw new Error("Min cannot be greater than Max");
  }

  return options;
}

export function applyCollectionFieldAdvancedOptions(field, options) {
  if (options.hidden) {
    field.hidden = true;
  }
  if (options.presentable) {
    field.presentable = true;
  }
  if (options.cascadeDelete) {
    field.cascadeDelete = true;
  }
  if (options.min != null) {
    field.min = options.min;
  }
  if (options.max != null) {
    field.max = options.max;
  }
  if (options.maxSize != null) {
    field.maxSize = options.maxSize;
  }
  if (options.pattern) {
    field.pattern = options.pattern;
  }
  if (options.onlyDomains.length) {
    field.onlyDomains = options.onlyDomains;
  }
  if (options.exceptDomains.length) {
    field.exceptDomains = options.exceptDomains;
  }
  if (options.thumbs.length) {
    field.thumbs = options.thumbs;
  }
}

function toggleNumeric(id, enabled) {
  const input = $(id);
  if (!input) {
    return;
  }
  input.disabled = !enabled;
  if (input.disabled) {
    input.value = "";
  }
}

function toggleList(id, enabled) {
  const input = $(id);
  if (!input) {
    return;
  }
  input.disabled = !enabled;
  if (input.disabled) {
    input.value = "";
  }
}

function optionValue(field, key) {
  return field && field[key] != null ? String(field[key]) : "";
}

function listValue(field, key) {
  return field && Array.isArray(field[key]) ? field[key].join(", ") : "";
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

function controlValue(id) {
  const input = $(id);
  return input ? input.value.trim() : "";
}

function checked(id) {
  const input = $(id);
  return Boolean(input && input.checked);
}

function commaList(value) {
  const seen = new Set();
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter((item) => {
      if (!item || seen.has(item)) {
        return false;
      }
      seen.add(item);
      return true;
    });
}
