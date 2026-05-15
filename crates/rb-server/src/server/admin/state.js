export const tokenKey = "rusty-base.admin.token";

export const state = {
  token: localStorage.getItem(tokenKey) || "",
  view: "overview",
  health: "unknown",
  collections: [],
  collectionDetails: {},
  selectedCollection: localStorage.getItem("rusty-base.admin.collection") || "",
  records: [],
  relationOptionErrors: {},
  relationOptions: {},
  recordCount: 0,
  recordPage: 1,
  recordPerPage: Number(localStorage.getItem("rusty-base.admin.recordPerPage") || 20) || 20,
  recordTotalPages: 1,
  recordFilter: "",
  recordSort: "-created",
  editorMode: "",
  editorRecordId: "",
  editorText: "",
  editorError: "",
  editorValidation: {},
  collectionEditorOpen: false,
  collectionEditorMode: "",
  collectionEditorName: "",
  collectionEditorText: "",
  collectionEditorError: "",
  collectionFieldEditIndex: -1,
  settings: null,
  error: ""
};

export const $ = (id) => document.getElementById(id);

export const status = (text, failed = false) => {
  $("status").textContent = text;
  $("status").classList.toggle("error", failed);
};

const headers = () => state.token ? { Authorization: `Bearer ${state.token}` } : {};

export async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...headers(),
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (_) {
    body = text;
  }
  if (!response.ok) {
    const message = body && body.message ? body.message : `${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.body = body;
    throw error;
  }
  return body;
}

export async function jsonApi(path, body, method = "POST") {
  return api(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

export function confirmDangerousAction(message, expected) {
  if (!expected) {
    return false;
  }
  const expectedText = String(expected);
  const typed = window.prompt(`${message}\n\nType "${expectedText}" to confirm.`);
  return typed === expectedText;
}
