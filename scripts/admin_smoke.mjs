import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tempDir = mkdtempSync(join(tmpdir(), "rusty-base-admin-smoke-"));
const dbPath = join(tempDir, "smoke.db");
const port = await freePort();
const addr = `127.0.0.1:${port}`;
const baseUrl = `http://${addr}`;

let server = null;
let serverLog = "";

try {
  console.log(`admin smoke: starting server on ${baseUrl}`);
  await startServer();

  await checkAdminAssets();
  const token = await bootstrapSuperuser();
  await exerciseCollectionsAndRecords(token);

  console.log("admin smoke: restarting server for persistence check");
  await stopServer();
  await startServer();
  await checkPersistedRecord(token);

  console.log("admin smoke: ok");
} finally {
  await stopServer();
  rmSync(tempDir, { recursive: true, force: true });
}

async function startServer() {
  serverLog = "";
  server = spawn(
    "cargo",
    ["run", "-p", "rb-server", "--", "serve", dbPath, addr],
    { cwd: rootDir, stdio: ["ignore", "pipe", "pipe"] }
  );
  server.stdout.on("data", (chunk) => {
    serverLog += chunk.toString();
  });
  server.stderr.on("data", (chunk) => {
    serverLog += chunk.toString();
  });
  await waitForServer();
}

async function stopServer() {
  if (!server) {
    return;
  }
  const current = server;
  server = null;
  if (current.exitCode != null || current.signalCode != null) {
    return;
  }
  await new Promise((resolve) => {
    current.once("close", resolve);
    current.kill();
  });
}

async function waitForServer() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (server && server.exitCode != null) {
      throw new Error(`server exited before ready\n${serverLog}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) {
        return;
      }
    } catch (_) {
      // Keep polling until the listener is ready.
    }
    await sleep(100);
  }
  throw new Error(`server did not become ready\n${serverLog}`);
}

async function checkAdminAssets() {
  console.log("admin smoke: checking admin shell assets");
  const shell = await rawRequest("/_/");
  expectStatus(shell, 200, "admin shell");
  expectHeader(shell, "content-type", "text/html; charset=utf-8", "admin shell content-type");
  const csp = shell.headers.get("content-security-policy") || "";
  expect(csp.includes("script-src 'self'"), "admin shell CSP should restrict scripts to self");
  expect(csp.includes("style-src 'self'"), "admin shell CSP should restrict styles to self");

  for (const path of [
    "/_/admin/app.js",
    "/_/admin/records_ui.js",
    "/_/admin/records/browser.js",
    "/_/admin/records/editor.js",
    "/_/admin/records/files.js",
    "/_/admin/records/relations.js",
    "/_/admin/records/validation.js"
  ]) {
    const asset = await rawRequest(path);
    expectStatus(asset, 200, `${path} asset`);
    expectHeader(asset, "content-type", "text/javascript; charset=utf-8", `${path} content-type`);
    expectHeader(asset, "x-content-type-options", "nosniff", `${path} nosniff`);
  }

  const missing = await rawRequest("/_/admin/records/missing.js");
  expectStatus(missing, 404, "missing nested admin asset");
}

async function bootstrapSuperuser() {
  console.log("admin smoke: bootstrapping superuser");
  await jsonRequest("POST", "/api/collections", {
    name: "_superusers",
    type: "auth",
    fields: [{ name: "email", type: "email" }]
  });
  await jsonRequest("POST", "/api/collections/_superusers/records", {
    id: "su_1",
    email: "root@example.com",
    password: "correct horse",
    passwordConfirm: "correct horse"
  });

  const blocked = await rawRequest("/api/collections");
  expectStatus(blocked, 403, "collection list without superuser token");

  const login = await jsonRequest("POST", "/api/collections/_superusers/auth-with-password", {
    identity: "root@example.com",
    password: "correct horse"
  });
  expect(typeof login.token === "string" && login.token.length > 8, "login should return a token");
  return login.token;
}

async function exerciseCollectionsAndRecords(token) {
  console.log("admin smoke: exercising collection, relation, file, and query flows");
  await jsonRequest("POST", "/api/collections", {
    name: "authors",
    fields: [{ name: "name", type: "text" }]
  }, { token });

  await jsonRequest("POST", "/api/collections", {
    name: "posts",
    fields: [
      { name: "title", type: "text" },
      { name: "published", type: "bool" },
      { name: "author", type: "relation", collection: "authors", maxSelect: 1 },
      { name: "asset", type: "file", maxSelect: 1, protected: true, mimeTypes: ["text/plain"] }
    ],
    viewRule: "author = @request.auth.id"
  }, { token });

  await jsonRequest("POST", "/api/collections/authors/records", {
    id: "author_1",
    name: "Ada"
  }, { token });

  await jsonRequest("POST", "/api/collections/posts/records", {
    id: "post_1",
    title: "Draft",
    published: false,
    author: "author_1"
  }, { token });

  const updated = await jsonRequest("PATCH", "/api/collections/posts/records/post_1", {
    title: "Published",
    published: true
  }, { token });
  expectEqual(updated.title, "Published", "record update title");
  expectEqual(updated.published, true, "record update published");

  const expanded = await jsonRequest("GET", "/api/collections/posts/records/post_1?expand=author", null, { token });
  expectEqual(expanded.expand.author.name, "Ada", "relation expand author name");

  const uploaded = await multipartRequest("PATCH", "/api/collections/posts/records/post_1", {
    token,
    fields: {
      asset: {
        bytes: "admin smoke file",
        name: "smoke.txt",
        type: "text/plain"
      }
    }
  });
  const asset = uploaded.asset;
  expect(typeof asset === "string" && asset.startsWith("smoke_"), "file upload should return stored filename");

  const deniedFile = await rawRequest(`/api/files/posts/post_1/${encodeURIComponent(asset)}`);
  expectStatus(deniedFile, 404, "protected file without auth");

  const downloaded = await rawRequest(`/api/files/posts/post_1/${encodeURIComponent(asset)}`, { token });
  expectStatus(downloaded, 200, "protected file with auth");
  expectEqual(await downloaded.text(), "admin smoke file", "downloaded file bytes");

  const removed = await jsonRequest("PATCH", "/api/collections/posts/records/post_1", {
    "asset-": [asset]
  }, { token });
  expect(!removed.asset, "file delete should clear single file field");
  const removedFile = await rawRequest(`/api/files/posts/post_1/${encodeURIComponent(asset)}`, { token });
  expectStatus(removedFile, 404, "deleted file should not be downloadable");

  await jsonRequest("POST", "/api/collections/posts/records", {
    id: "post_2",
    title: "Hidden",
    published: false,
    author: "author_1"
  }, { token });
  await jsonRequest("POST", "/api/collections/posts/records", {
    id: "post_3",
    title: "Another",
    published: true,
    author: "author_1"
  }, { token });

  const page = await jsonRequest(
    "GET",
    "/api/collections/posts/records?filter=published%20%3D%20true&sort=title&page=1&perPage=2",
    null,
    { token }
  );
  expectEqual(page.totalItems, 2, "filtered totalItems");
  expectEqual(page.items.length, 2, "paginated item count");
  expectEqual(page.items[0].title, "Another", "sorted first item");
}

async function checkPersistedRecord(token) {
  console.log("admin smoke: checking restart persistence");
  const persisted = await jsonRequest("GET", "/api/collections/posts/records/post_1?expand=author", null, { token });
  expectEqual(persisted.title, "Published", "persisted title after restart");
  expectEqual(persisted.expand.author.name, "Ada", "persisted relation expand after restart");
}

async function rawRequest(path, options = {}) {
  const headers = {};
  if (options.token) {
    headers.authorization = `Bearer ${options.token}`;
  }
  return fetch(`${baseUrl}${path}`, {
    method: options.method || "GET",
    headers,
    body: options.body
  });
}

async function jsonRequest(method, path, body, options = {}) {
  const headers = { "content-type": "application/json" };
  if (options.token) {
    headers.authorization = `Bearer ${options.token}`;
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body == null ? undefined : JSON.stringify(body)
  });
  const data = await responseJson(response);
  if (!response.ok) {
    throw new Error(`${method} ${path} failed with ${response.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

async function multipartRequest(method, path, options) {
  const form = new FormData();
  for (const [name, file] of Object.entries(options.fields)) {
    form.append(name, new Blob([file.bytes], { type: file.type }), file.name);
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { authorization: `Bearer ${options.token}` },
    body: form
  });
  const data = await responseJson(response);
  if (!response.ok) {
    throw new Error(`${method} ${path} failed with ${response.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

async function responseJson(response) {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch (_) {
    return text;
  }
}

function expectStatus(response, status, label) {
  expect(response.status === status, `${label}: expected ${status}, got ${response.status}`);
}

function expectHeader(response, name, expected, label) {
  expectEqual(response.headers.get(name), expected, label);
}

function expectEqual(actual, expected, label) {
  expect(Object.is(actual, expected), `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function expect(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const socket = createServer();
    socket.once("error", reject);
    socket.listen(0, "127.0.0.1", () => {
      const address = socket.address();
      socket.close(() => resolvePort(address.port));
    });
  });
}
