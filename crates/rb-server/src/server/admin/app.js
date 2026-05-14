import { $, api, jsonApi, state, status, tokenKey } from "./state.js";
import { closeCollectionEditor, renderCollections } from "./collections_ui.js";
import { closeRecordEditor, ensureRelationOptionsForCollection, renderRecords } from "./records_ui.js";
import { collectionPath, collectionRecordsPath, normalizedRecordPerPage } from "./data_helpers.js";
import { metric, row, title } from "./render_helpers.js";

async function refresh() {
  state.error = "";
  try {
    const health = await api("/api/health");
    state.health = health.message || "ok";
  } catch (error) {
    state.health = "offline";
    state.error = error.message;
  }

  if (state.token) {
    try {
      const collections = await api("/api/collections?fields=items.id,items.name,items.type,items.system,totalItems");
      state.collections = collections.items || [];
      ensureSelectedCollection();
    } catch (error) {
      state.collections = [];
      state.collectionDetails = {};
      state.relationOptionErrors = {};
      state.relationOptions = {};
      state.selectedCollection = "";
      state.records = [];
      state.recordCount = 0;
      state.recordTotalPages = 1;
      state.error = error.message;
    }

    if (state.selectedCollection) {
      await loadRecords(false);
    }

    try {
      state.settings = await api("/api/settings?fields=meta.appName,meta.appURL,batch.enabled,batch.maxRequests,rateLimits.enabled");
    } catch (error) {
      state.settings = null;
      state.error = error.message;
    }
  } else {
    state.collections = [];
    state.collectionDetails = {};
    state.relationOptionErrors = {};
    state.relationOptions = {};
    state.selectedCollection = "";
    state.records = [];
    state.recordCount = 0;
    state.recordTotalPages = 1;
    state.settings = null;
  }

  render();
}

function render() {
  $("health").textContent = state.health;
  $("session").textContent = state.token ? "Superuser token active" : "No token";
  status(state.error || "Ready", Boolean(state.error));
  document.querySelectorAll(".nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === state.view);
  });

  const appName = state.settings && state.settings.meta ? state.settings.meta.appName : "Rusty Base";
  $("metrics").innerHTML = [
    metric("App", appName),
    metric("Collections", String(state.collections.length)),
    metric("Records", state.selectedCollection ? String(state.recordCount) : "-")
  ].join("");

  $("view-title").textContent = title(state.view);
  if (state.view === "collections") {
    renderCollections({ render, refresh, loadRecords, resetRecordBrowser });
  } else if (state.view === "records") {
    renderRecords({ currentCollection, render, loadRecords, setView });
  } else if (state.view === "settings") {
    renderSettings();
  } else {
    renderOverview();
  }
}

function renderOverview() {
  $("content").innerHTML = `
    <div class="panel-head">
      <h2>Instance</h2>
      <button type="button" id="refresh">Refresh</button>
    </div>
    <div class="panel-body">
      ${row("Health", state.health)}
      ${row("Session", state.token ? "active" : "none")}
      ${row("Collections", String(state.collections.length))}
    </div>
  `;
  $("refresh").addEventListener("click", refresh);
}

function renderSettings() {
  const settings = state.settings || {};
  const meta = settings.meta || {};
  const batch = settings.batch || {};
  const rateLimits = settings.rateLimits || {};
  $("content").innerHTML = `
    <div class="panel-head">
      <h2>Settings</h2>
      <button type="button" id="refresh">Refresh</button>
    </div>
    <div class="panel-body">
      ${row("App name", meta.appName || "-")}
      ${row("App URL", meta.appURL || "-")}
      ${row("Batch", batch.enabled === false ? "disabled" : "enabled")}
      ${row("Max requests", batch.maxRequests == null ? "-" : String(batch.maxRequests))}
      ${row("Rate limits", rateLimits.enabled ? "enabled" : "disabled")}
    </div>
  `;
  $("refresh").addEventListener("click", refresh);
}

async function setView(view) {
  state.view = view;
  if (view === "records") {
    ensureSelectedCollection();
    await loadRecords(true);
  }
  render();
}

function ensureSelectedCollection() {
  if (state.collections.some((collection) => collection.name === state.selectedCollection)) {
    return;
  }
  const previousCollection = state.selectedCollection;
  state.selectedCollection = state.collections[0] ? state.collections[0].name : "";
  if (state.selectedCollection) {
    localStorage.setItem("rusty-base.admin.collection", state.selectedCollection);
  }
  if (previousCollection !== state.selectedCollection) {
    resetRecordBrowser();
  }
}

function currentCollection() {
  return state.collectionDetails[state.selectedCollection]
    || state.collections.find((collection) => collection.name === state.selectedCollection)
    || null;
}

async function loadRecords(showErrors = true) {
  let collection = currentCollection();
  if (!state.token || !collection) {
    state.records = [];
    state.recordCount = 0;
    state.recordTotalPages = 1;
    return;
  }

  try {
    collection = await ensureCollectionDetails(collection.name);
    await ensureRelationOptionsForCollection(collection);
    const page = await api(recordListPath(collection.name));
    state.records = page.items || [];
    state.recordCount = page.totalItems == null ? state.records.length : page.totalItems;
    state.recordPage = Number(page.page) || state.recordPage || 1;
    state.recordPerPage = normalizedRecordPerPage(Number(page.perPage) || state.recordPerPage);
    state.recordTotalPages = Number(page.totalPages) || Math.max(1, Math.ceil(state.recordCount / state.recordPerPage));
    if (showErrors) {
      state.error = "";
    }
  } catch (error) {
    state.records = [];
    state.recordCount = 0;
    state.recordTotalPages = 1;
    if (showErrors) {
      state.error = error.message;
    }
  }
}

function recordListPath(collectionName) {
  state.recordPage = Math.max(1, Number(state.recordPage) || 1);
  state.recordPerPage = normalizedRecordPerPage(state.recordPerPage);

  const params = new URLSearchParams();
  params.set("page", String(state.recordPage));
  params.set("perPage", String(state.recordPerPage));
  const sort = String(state.recordSort || "").trim();
  const filter = String(state.recordFilter || "").trim();
  if (sort) {
    params.set("sort", sort);
  }
  if (filter) {
    params.set("filter", filter);
  }
  return `${collectionRecordsPath(collectionName)}?${params.toString()}`;
}

function resetRecordBrowser() {
  state.records = [];
  state.recordCount = 0;
  state.recordPage = 1;
  state.recordTotalPages = 1;
  state.recordFilter = "";
  state.recordSort = "-created";
  closeRecordEditor();
}

async function ensureCollectionDetails(collectionName) {
  const cached = state.collectionDetails[collectionName];
  if (cached && Array.isArray(cached.fields)) {
    return cached;
  }

  const collection = await api(collectionPath(collectionName));
  state.collectionDetails[collection.name || collectionName] = collection;
  return collection;
}

document.querySelectorAll(".nav button").forEach((button) => {
  button.addEventListener("click", () => {
    setView(button.dataset.view);
  });
});

$("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const body = await jsonApi("/api/collections/_superusers/auth-with-password", {
      identity: $("email").value,
      password: $("password").value
    });
    state.token = body.token || "";
    localStorage.setItem(tokenKey, state.token);
    status("Logged in");
    await refresh();
  } catch (error) {
    status(error.message, true);
  }
});

$("init").addEventListener("click", async () => {
  try {
    await jsonApi("/api/collections", {
      name: "_superusers",
      type: "auth",
      fields: [{ name: "email", type: "email" }]
    }).catch(() => null);
    await jsonApi("/api/collections/_superusers/records", {
      email: $("email").value,
      password: $("password").value,
      passwordConfirm: $("password").value
    });
    const body = await jsonApi("/api/collections/_superusers/auth-with-password", {
      identity: $("email").value,
      password: $("password").value
    });
    state.token = body.token || "";
    localStorage.setItem(tokenKey, state.token);
    status("Initialized and logged in");
    await refresh();
  } catch (error) {
    status(error.message, true);
  }
});

$("logout").addEventListener("click", async () => {
  state.token = "";
  localStorage.removeItem(tokenKey);
  state.collections = [];
  state.collectionDetails = {};
  state.relationOptionErrors = {};
  state.relationOptions = {};
  resetRecordBrowser();
  state.settings = null;
  closeCollectionEditor();
  await refresh();
});

refresh();
