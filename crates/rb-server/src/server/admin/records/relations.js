import { api, state } from "../state.js";
import {
  collectionRecordsPath,
  recordFieldInputDisplayValue,
  recordFieldIsMulti,
  relationOptionLabel,
  relationTargetCollectionName,
  userCollectionFields
} from "../data_helpers.js";
import { escapeAttribute, escapeHtml } from "../render_helpers.js";

const relationOptionLoads = new Map();

export async function ensureRelationOptionsForCollection(collection) {
  const targets = userCollectionFields(collection)
    .filter((field) => (field.type || field.kind) === "relation")
    .map(relationTargetCollectionName)
    .filter(Boolean);
  const uniqueTargets = [...new Set(targets)];
  await Promise.all(uniqueTargets.map((target) => ensureRelationOptions(target)));
}

async function ensureRelationOptions(targetCollection) {
  if (Object.prototype.hasOwnProperty.call(state.relationOptions, targetCollection)) {
    return;
  }
  if (relationOptionLoads.has(targetCollection)) {
    await relationOptionLoads.get(targetCollection);
    return;
  }

  const params = new URLSearchParams();
  params.set("page", "1");
  params.set("perPage", "100");
  params.set("sort", "-updated");
  params.set("fields", "id,name,title,label,email,username,created,updated,collectionName");
  const load = api(`${collectionRecordsPath(targetCollection)}?${params.toString()}`)
    .then((page) => {
      state.relationOptions[targetCollection] = Array.isArray(page.items) ? page.items : [];
      delete state.relationOptionErrors[targetCollection];
    })
    .catch((error) => {
      state.relationOptions[targetCollection] = [];
      state.relationOptionErrors[targetCollection] = error.message;
    })
    .finally(() => {
      relationOptionLoads.delete(targetCollection);
    });
  relationOptionLoads.set(targetCollection, load);
  await load;
}

export function relationFieldValuePreview(record, field) {
  const value = record[field.name];
  if (value == null || value === "" || (Array.isArray(value) && !value.length)) {
    return `<span class="muted">-</span>`;
  }

  const values = Array.isArray(value) ? value : [value];
  const labels = values.map((id) => relationDisplayLabel(record, field, String(id)));
  const text = labels.filter(Boolean).join(", ");
  const preview = text.length > 120 ? `${text.slice(0, 117)}...` : text;
  return escapeHtml(preview || recordFieldInputDisplayValue(value));
}

function relationDisplayLabel(record, field, id) {
  const expanded = record.expand && record.expand[field.name];
  const expandedRecord = Array.isArray(expanded)
    ? expanded.find((item) => String((item && item.id) || "") === id)
    : expanded && String(expanded.id || "") === id
      ? expanded
      : null;
  if (expandedRecord) {
    return relationOptionLabel(expandedRecord);
  }

  const target = relationTargetCollectionName(field);
  const option = (state.relationOptions[target] || [])
    .find((item) => String(item.id || "") === id);
  return option ? relationOptionLabel(option) : id;
}

export function relationFieldInputHtml(field, value, common, label, fieldClass, fieldError) {
  const target = relationTargetCollectionName(field);
  const options = target ? state.relationOptions[target] : null;
  const error = target ? state.relationOptionErrors[target] : "";
  if (!target || !Array.isArray(options)) {
    return `
      <div class="${fieldClass}">
        ${label}
        <input ${common} data-record-relation-target="${escapeAttribute(target)}" type="text" value="${escapeAttribute(recordFieldInputDisplayValue(value))}" placeholder="${recordFieldIsMulti(field) ? "record ids, comma separated" : "record id"}">
        <span class="muted">${escapeHtml(target ? `Loading ${target} records...` : "Relation target is missing")}</span>
        ${fieldError}
      </div>
    `;
  }

  const selected = new Set((Array.isArray(value) ? value : value ? [value] : []).map(String));
  const optionHtml = options.map((record) => {
    const id = String(record.id || "");
    return `
      <option value="${escapeAttribute(id)}" ${selected.has(id) ? "selected" : ""}>
        ${escapeHtml(relationOptionLabel(record))}
      </option>
    `;
  }).concat([...selected]
    .filter((id) => id && !options.some((record) => String(record.id || "") === id))
    .map((id) => `
      <option value="${escapeAttribute(id)}" selected>${escapeHtml(`${id} (not loaded)`)}</option>
    `)).join("");
  const hint = error
    ? `<span class="field-error">${escapeHtml(error)}</span>`
    : `<span class="muted">${escapeHtml(target)} records</span>`;
  if (recordFieldIsMulti(field)) {
    const size = Math.min(Math.max(options.length || 2, 2), 6);
    return `
      <div class="${fieldClass}">
        ${label}
        <select ${common} data-record-relation-target="${escapeAttribute(target)}" multiple size="${size}">${optionHtml}</select>
        ${hint}
        ${fieldError}
      </div>
    `;
  }

  return `
    <div class="${fieldClass}">
      ${label}
      <select ${common} data-record-relation-target="${escapeAttribute(target)}">
        <option value=""></option>
        ${optionHtml}
      </select>
      ${hint}
      ${fieldError}
    </div>
  `;
}

export function invalidateRelationOptions(collectionName) {
  if (!collectionName) {
    return;
  }
  delete state.relationOptions[collectionName];
  delete state.relationOptionErrors[collectionName];
}
