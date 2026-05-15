import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tempDir = mkdtempSync(join(tmpdir(), "rusty-base-admin-browser-"));
const dbPath = join(tempDir, "browser-smoke.db");
const serverPort = await freePort();
const chromePort = await freePort();
const addr = `127.0.0.1:${serverPort}`;
const baseUrl = `http://${addr}`;

let server = null;
let chrome = null;
let serverLog = "";
let chromeLog = "";

async function main() {
  try {
    console.log(`admin browser smoke: starting server on ${baseUrl}`);
    await startServer();

    console.log(`admin browser smoke: starting headless Chrome on port ${chromePort}`);
    await startChrome();
    const page = await openAdminPage();
    await exerciseAdminUi(page);
    await page.close();

    console.log("admin browser smoke: ok");
  } finally {
    await stopChrome();
    await stopServer();
    rmSync(tempDir, { recursive: true, force: true });
  }
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
  await new Promise((resolveClose) => {
    current.once("close", resolveClose);
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

async function startChrome() {
  const chromePath = findChrome();
  chromeLog = "";
  chrome = spawn(chromePath, [
    "--headless=new",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-setuid-sandbox",
    "--no-sandbox",
    "--no-first-run",
    "--no-default-browser-check",
    "--remote-debugging-address=127.0.0.1",
    `--remote-debugging-port=${chromePort}`,
    `--user-data-dir=${join(tempDir, "chrome-profile")}`,
    "about:blank"
  ], { stdio: ["ignore", "pipe", "pipe"] });
  chrome.stdout.on("data", (chunk) => {
    chromeLog += chunk.toString();
  });
  chrome.stderr.on("data", (chunk) => {
    chromeLog += chunk.toString();
  });
  await waitForChrome();
}

async function stopChrome() {
  if (!chrome) {
    return;
  }
  const current = chrome;
  chrome = null;
  if (current.exitCode != null || current.signalCode != null) {
    return;
  }
  await new Promise((resolveClose) => {
    current.once("close", resolveClose);
    current.kill();
  });
}

function findChrome() {
  const candidates = [
    process.env.RB_ADMIN_BROWSER_CHROME,
    process.env.CHROME,
    process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser"
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (candidate.includes("/") && existsSync(candidate)) {
      return candidate;
    }
    if (!candidate.includes("/")) {
      const result = spawnSync(candidate, ["--version"], { encoding: "utf8" });
      if (!result.error && result.status === 0) {
        return candidate;
      }
    }
  }

  throw new Error("Chrome/Chromium was not found. Set RB_ADMIN_BROWSER_CHROME to run the admin browser smoke.");
}

async function waitForChrome() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (chrome && chrome.exitCode != null) {
      throw new Error(`Chrome exited before DevTools was ready\n${chromeLog}`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${chromePort}/json/version`);
      if (response.ok) {
        return;
      }
    } catch (_) {
      // Keep polling until DevTools is ready.
    }
    await sleep(100);
  }
  throw new Error(`Chrome DevTools did not become ready\n${chromeLog}`);
}

async function openAdminPage() {
  const targets = await devtoolsJson("/json/list");
  const pageTarget = targets.find((target) => target.type === "page" && target.webSocketDebuggerUrl);
  if (!pageTarget) {
    throw new Error(`No Chrome page target found\n${chromeLog}`);
  }

  const page = await CdpPage.connect(pageTarget.webSocketDebuggerUrl);
  await page.send("Page.enable");
  await page.send("Runtime.enable");
  await page.send("Log.enable");
  page.on("Runtime.exceptionThrown", ({ exceptionDetails }) => {
    page.pageErrors.push(exceptionDetails.exception?.description || exceptionDetails.text || "runtime exception");
  });
  page.on("Page.javascriptDialogOpening", (dialog) => {
    page.dialogs.push(dialog);
  });

  await page.send("Page.navigate", { url: `${baseUrl}/_/` });
  await page.waitFor(
    "document.readyState === 'complete' && document.querySelector('#status')",
    "admin shell load"
  );
  await page.waitFor(
    "document.querySelector('#health')?.textContent.includes('healthy')",
    "health indicator"
  );
  return page;
}

async function devtoolsJson(path) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const response = await fetch(`http://127.0.0.1:${chromePort}${path}`);
    if (response.ok) {
      return response.json();
    }
    await sleep(100);
  }
  throw new Error(`DevTools endpoint failed: ${path}`);
}

async function exerciseAdminUi(page) {
  console.log("admin browser smoke: bootstrapping through the UI");
  await page.eval(`
    document.querySelector("#email").value = "root@example.com";
    document.querySelector("#password").value = "correct horse";
    document.querySelector("#init").click();
    true;
  `);
  await page.waitFor(
    "Boolean(localStorage.getItem('rusty-base.admin.token')) && document.querySelector('#session')?.textContent.includes('Superuser')",
    "superuser session"
  );

  console.log("admin browser smoke: creating related collections through the UI");
  await createCollection(page, {
    name: "ui_authors",
    fields: [
      { name: "name", type: "text", required: true }
    ]
  });
  await createJsonRecord(page, {
    id: "ui_author_1",
    name: "Ada Lovelace"
  });

  await createCollection(page, {
    name: "ui_posts",
    fields: [
      { name: "title", type: "text", required: true },
      { name: "published", type: "bool" },
      { name: "author", type: "relation", collection: "ui_authors", maxSelect: 1 },
      { name: "asset", type: "file", maxSelect: 1, protected: true, mimeTypes: ["text/plain"] }
    ]
  });

  console.log("admin browser smoke: creating relation and file records through the UI");
  await createPostWithFieldEditor(page);
  await createJsonRecord(page, {
    id: "ui_post_2",
    title: "Hidden UI",
    published: false
  });
  await page.waitFor(
    "document.body.textContent.includes('Hello UI') && document.body.textContent.includes('Ada Lovelace') && document.body.textContent.includes('Hidden UI')",
    "relation and record rows"
  );

  console.log("admin browser smoke: filtering, editing, and downloading files through the UI");
  await page.setValue("#record-filter", "published = true");
  await page.setValue("#record-sort", "title");
  await page.click("#apply-record-query");
  await page.waitFor(
    "document.body.textContent.includes('Hello UI') && !document.body.textContent.includes('Hidden UI') && document.body.textContent.includes('1-1 of 1')",
    "filtered record table"
  );

  await exercisePostEditAndFileControls(page);
  await exerciseDestructiveActionGuards(page);

  await page.click("#logout");
  await page.waitFor(
    "!localStorage.getItem('rusty-base.admin.token') && document.querySelector('#session')?.textContent === 'No token'",
    "logout state"
  );

  page.assertNoErrors();
}

async function createCollection(page, payload) {
  await page.click("[data-view='collections']");
  await page.waitFor("document.querySelector('#view-title')?.textContent === 'Collections'", "collections view");
  await page.click("#new-collection");
  await page.waitFor("document.querySelector('#collection-json-input')", `collection editor ${payload.name}`);
  await page.setValue("#collection-json-input", JSON.stringify(payload, null, 2));
  await page.click("#save-collection");
  await page.waitFor(
    `document.querySelector('#view-title')?.textContent === 'Records' && document.body.textContent.includes(${JSON.stringify(`${payload.name} records`)})`,
    `created collection ${payload.name}`
  );
}

async function createJsonRecord(page, payload) {
  await page.click("#new-record");
  await page.waitFor("document.querySelector('#record-json-input')", `record editor ${payload.id}`);
  await page.setValue("#record-json-input", JSON.stringify(payload, null, 2));
  await page.click("#save-record");
  const label = payload.title || payload.name || payload.id;
  await page.waitFor(
    `document.body.textContent.includes(${JSON.stringify(label)}) && !document.querySelector('#record-json-input')`,
    `created record ${payload.id}`
  );
}

async function createPostWithFieldEditor(page) {
  await page.click("#new-record");
  await page.waitFor("document.querySelector('#record-json-input')", "post record editor");
  await page.setValue("#record-json-input", JSON.stringify({ id: "ui_post_1" }, null, 2));
  await page.setValue("[data-record-field='title']", "Hello UI");
  await page.setChecked("[data-record-field='published']", true);
  await page.waitFor(
    "Array.from(document.querySelector(\"[data-record-field='author']\")?.options || []).some((option) => option.value === 'ui_author_1')",
    "relation picker options"
  );
  await page.setSelectValue("[data-record-field='author']", "ui_author_1");
  await page.setFile("[data-record-file='asset']", {
    name: "admin-ui-smoke.txt",
    type: "text/plain",
    bytes: "admin browser smoke file"
  });
  await page.click("#save-record");
  await page.waitFor(
    "document.body.textContent.includes('Hello UI') && document.body.textContent.includes('Ada Lovelace') && !document.querySelector('#record-json-input')",
    "created relation and file record"
  );
}

async function exercisePostEditAndFileControls(page) {
  await page.click("[data-edit-record='ui_post_1']");
  await page.waitFor("document.querySelector('#record-json-input')", "edit record editor");
  await page.waitFor("document.querySelector('[data-record-file-download]')", "file download control");
  const uploadedFileName = await page.eval("document.querySelector('[data-record-file-download]')?.dataset.recordFileDownload || ''");
  if (!uploadedFileName) {
    throw new Error("Uploaded file name was not rendered in the record editor");
  }

  await page.click("[data-record-file-download]");
  await page.waitFor("document.querySelector('#status')?.textContent === 'File downloaded'", "file download status");

  await page.eval(`
    (() => {
      const input = document.querySelector("#record-json-input");
      const payload = JSON.parse(input.value || "{}");
      payload.title = "Hello UI Edited";
      input.value = JSON.stringify(payload, null, 2);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    })();
  `);
  await page.setChecked("[data-record-file-delete='asset']", true);
  await page.click("#save-record");
  await page.waitFor(
    `document.body.textContent.includes('Hello UI Edited') && !document.body.textContent.includes(${JSON.stringify(uploadedFileName)}) && !document.querySelector('#record-json-input')`,
    "edited record row with removed file"
  );
}

async function exerciseDestructiveActionGuards(page) {
  console.log("admin browser smoke: checking destructive action guards");
  await page.clickAndPrompt("[data-delete-record='ui_post_1']", "wrong-confirmation");
  await page.waitFor(
    "document.body.textContent.includes('Hello UI Edited')",
    "record survives rejected delete confirmation"
  );

  await page.clickAndPrompt("[data-delete-record='ui_post_1']", "ui_post_1");
  await page.waitFor(
    "!document.body.textContent.includes('Hello UI Edited') && document.body.textContent.includes('No matching records')",
    "record delete confirmation"
  );

  await page.click("[data-view='collections']");
  await page.waitFor(
    "document.querySelector('#view-title')?.textContent === 'Collections' && document.body.textContent.includes('ui_posts')",
    "collections view before delete guard"
  );
  await page.clickAndPrompt("[data-collection-delete='ui_posts']", "wrong-confirmation");
  await page.waitFor(
    "document.body.textContent.includes('ui_posts')",
    "collection survives rejected delete confirmation"
  );

  await page.clickAndPrompt("[data-collection-delete='ui_posts']", "ui_posts");
  await page.waitFor(
    "!document.body.textContent.includes('ui_posts') && document.querySelector('#view-title')?.textContent === 'Collections'",
    "collection delete confirmation"
  );
}

class CdpPage {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.handlers = new Map();
    this.pageErrors = [];
    this.dialogs = [];
    this.socket.addEventListener("message", (event) => {
      this.handleMessage(event.data);
    });
  }

  static async connect(webSocketUrl) {
    const socket = new WebSocket(webSocketUrl);
    await new Promise((resolveOpen, rejectOpen) => {
      socket.addEventListener("open", resolveOpen, { once: true });
      socket.addEventListener("error", rejectOpen, { once: true });
    });
    return new CdpPage(socket);
  }

  async close() {
    if (this.socket.readyState === WebSocket.OPEN) {
      this.socket.close();
    }
  }

  on(method, handler) {
    const handlers = this.handlers.get(method) || [];
    handlers.push(handler);
    this.handlers.set(method, handlers);
  }

  send(method, params = {}) {
    const id = this.nextId;
    this.nextId += 1;
    const message = JSON.stringify({ id, method, params });
    return new Promise((resolveSend, rejectSend) => {
      this.pending.set(id, { resolveSend, rejectSend });
      this.socket.send(message);
    });
  }

  async eval(expression) {
    const response = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true
    });
    if (response.exceptionDetails) {
      const exception = response.exceptionDetails.exception;
      throw new Error(exception?.description || response.exceptionDetails.text || "evaluation failed");
    }
    return response.result ? response.result.value : undefined;
  }

  async click(selector) {
    await this.eval(`
      (() => {
        const node = document.querySelector(${JSON.stringify(selector)});
        if (!node) {
          throw new Error("Missing selector: " + ${JSON.stringify(selector)});
        }
        node.click();
        return true;
      })();
    `);
  }

  async clickAndPrompt(selector, promptText) {
    const clickPromise = this.click(selector);
    const dialog = await this.waitForDialog(selector);
    if (dialog.type !== "prompt") {
      throw new Error(`Expected prompt dialog for ${selector}, got ${dialog.type || "unknown"}`);
    }
    await this.send("Page.handleJavaScriptDialog", {
      accept: true,
      promptText
    });
    await clickPromise;
  }

  async setValue(selector, value) {
    await this.eval(`
      (() => {
        const node = document.querySelector(${JSON.stringify(selector)});
        if (!node) {
          throw new Error("Missing selector: " + ${JSON.stringify(selector)});
        }
        node.value = ${JSON.stringify(value)};
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
      })();
    `);
  }

  async setChecked(selector, checked) {
    await this.eval(`
      (() => {
        const node = document.querySelector(${JSON.stringify(selector)});
        if (!node) {
          throw new Error("Missing selector: " + ${JSON.stringify(selector)});
        }
        node.checked = ${checked ? "true" : "false"};
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
      })();
    `);
  }

  async setSelectValue(selector, value) {
    await this.eval(`
      (() => {
        const node = document.querySelector(${JSON.stringify(selector)});
        if (!node) {
          throw new Error("Missing selector: " + ${JSON.stringify(selector)});
        }
        node.value = ${JSON.stringify(value)};
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
      })();
    `);
  }

  async setFile(selector, file) {
    await this.eval(`
      (() => {
        const node = document.querySelector(${JSON.stringify(selector)});
        if (!node) {
          throw new Error("Missing selector: " + ${JSON.stringify(selector)});
        }
        const transfer = new DataTransfer();
        transfer.items.add(new File(
          [${JSON.stringify(file.bytes)}],
          ${JSON.stringify(file.name)},
          { type: ${JSON.stringify(file.type)} }
        ));
        node.files = transfer.files;
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
      })();
    `);
  }

  async waitFor(expression, label, timeoutMs = 10000) {
    const deadline = Date.now() + timeoutMs;
    let lastError = "";
    while (Date.now() < deadline) {
      this.assertNoErrors();
      try {
        if (await this.eval(`Boolean(${expression})`)) {
          return;
        }
      } catch (error) {
        lastError = error.message;
      }
      await sleep(100);
    }
    const body = await this.eval("document.body ? document.body.innerText.slice(0, 1000) : ''").catch(() => "");
    throw new Error(`Timed out waiting for ${label}${lastError ? `: ${lastError}` : ""}\n${body}`);
  }

  async waitForDialog(label, timeoutMs = 5000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      this.assertNoErrors();
      const dialog = this.dialogs.shift();
      if (dialog) {
        return dialog;
      }
      await sleep(50);
    }
    throw new Error(`Timed out waiting for prompt dialog from ${label}`);
  }

  assertNoErrors() {
    if (this.pageErrors.length) {
      throw new Error(`Admin page runtime error: ${this.pageErrors.join("\n")}`);
    }
  }

  handleMessage(raw) {
    let message = null;
    try {
      message = JSON.parse(String(raw));
    } catch (error) {
      this.pageErrors.push(`Bad CDP message: ${error.message}`);
      return;
    }

    if (message.id) {
      const pending = this.pending.get(message.id);
      if (pending) {
        this.pending.delete(message.id);
        if (message.error) {
          pending.rejectSend(new Error(message.error.message || JSON.stringify(message.error)));
        } else {
          pending.resolveSend(message.result || {});
        }
      }
      return;
    }

    const handlers = this.handlers.get(message.method) || [];
    for (const handler of handlers) {
      handler(message.params || {});
    }
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

await main();
