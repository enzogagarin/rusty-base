import { escapeHtml } from "./render_helpers.js";

export function collectionRecordsPath(collectionName) {
  return `/api/collections/${encodeURIComponent(collectionName)}/records`;
}

export function collectionPath(collectionName) {
  return `/api/collections/${encodeURIComponent(collectionName)}`;
}

export function recordPath(collectionName, id) {
  return `${collectionRecordsPath(collectionName)}/${encodeURIComponent(id)}`;
}

export function relationTargetCollectionName(field) {
  return field && (field.collection || field.collectionId || field.targetCollection || "");
}

export function normalizedRecordPerPage(value) {
  const perPage = Number(value) || 20;
  return [10, 20, 50, 100].includes(perPage) ? perPage : 20;
}

export function userCollectionFields(collection) {
  if (!collection || !Array.isArray(collection.fields)) {
    return [];
  }
  return collection.fields.filter((field) => field && field.name && !isResponseOnlyCollectionField(field));
}

export function editableCollectionPayload(collection) {
  const copy = { ...collection };
  delete copy.id;
  delete copy.created;
  delete copy.updated;
  delete copy.system;
  delete copy.indexWarnings;
  if (Array.isArray(copy.fields)) {
    copy.fields = copy.fields.filter((field) => !isResponseOnlyCollectionField(field));
  }
  return copy;
}

export function isResponseOnlyCollectionField(field) {
  if (!field || typeof field !== "object") {
    return false;
  }
  if (field.name === "id" && field.primaryKey) {
    return true;
  }
  return (field.name === "created" || field.name === "updated") && field.type === "autodate";
}

export function recordFieldIsMulti(field) {
  return Number(field.maxSelect || 1) > 1;
}

export function relationOptionLabel(record) {
  if (!record || typeof record !== "object") {
    return "";
  }
  const label = record.name || record.title || record.label || record.username || record.email;
  return label ? `${label} (${record.id || ""})` : String(record.id || "");
}

export function recordFieldInputDisplayValue(value) {
  if (value == null) {
    return "";
  }
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

export function recordFieldValuePreview(record, field) {
  const value = record[field.name];
  if (value == null || value === "") {
    return `<span class="muted">-</span>`;
  }
  const text = recordFieldInputDisplayValue(value);
  const preview = text.length > 120 ? `${text.slice(0, 117)}...` : text;
  if (Array.isArray(value) || typeof value === "object") {
    return `<code class="record-json">${escapeHtml(preview)}</code>`;
  }
  return escapeHtml(preview);
}

export function editableRecordPayload(record) {
  const copy = { ...record };
  delete copy.id;
  delete copy.created;
  delete copy.updated;
  delete copy.collectionId;
  delete copy.collectionName;
  delete copy.expand;
  return copy;
}

export function recordPreview(record) {
  const copy = { ...record };
  delete copy.collectionId;
  delete copy.collectionName;
  const text = JSON.stringify(copy, null, 2);
  return text.length > 360 ? `${text.slice(0, 357)}...` : text;
}
