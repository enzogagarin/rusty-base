import { execFile, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const targetPocketBaseVersion = "0.38.1";
const settingsSecretProjection =
  "smtp.password,s3.secret,backups.s3.secret,batch.maxRequests";
const settingsFieldsProjection = "meta.appName,batch.maxRequests,smtp.password";
const settingsDefaultComparisonPaths = [
  ["meta", "appName"],
  ["batch", "maxRequests"]
];
const settingsPatchComparisonPaths = [
  ["meta", "appName"],
  ["meta", "appURL"],
  ["batch", "maxRequests"],
  ["smtp", "password"],
  ["s3", "secret"],
  ["backups", "s3", "secret"],
  ["rateLimits", "rules", 0, "label"],
  ["trustedProxy", "useLeftmostIp"]
];
const settingsSecretComparisonPaths = [
  ["smtp", "password"],
  ["s3", "secret"],
  ["backups", "s3", "secret"],
  ["batch", "maxRequests"]
];
const settingsProjectionComparisonPaths = [
  ["meta", "appName"],
  ["batch", "maxRequests"],
  ["smtp", "password"],
  ["s3"]
];
const invalidBatchValidationPaths = [["data", "batch.maxRequests", "code"]];
const invalidBackupValidationPaths = [["data", "backups.s3.secret", "code"]];

const options = parseArgs(process.argv.slice(2));

if (options.help) {
  printHelp();
  process.exit(0);
}

if (!options.pocketbase) {
  fail("missing --pocketbase path");
}

if (!existsSync(options.pocketbase)) {
  fail(`PocketBase binary not found: ${options.pocketbase}`);
}

const tempDir = mkdtempSync(join(tmpdir(), "rusty-base-pocketbase-compare-"));
const state = {
  pocketbase: null,
  rustyBase: null,
  pocketbaseLog: "",
  rustyBaseLog: ""
};

let exitCode = 0;
try {
  const version = await pocketbaseVersion(options.pocketbase);
  if (!version.includes(targetPocketBaseVersion)) {
    throw new Error(
      `PocketBase target mismatch: expected ${targetPocketBaseVersion}, got ${version.trim()}`
    );
  }

  console.log(`pocketbase compare: target ${version.trim()}`);

  if (options.checkOnly) {
    console.log("pocketbase compare: check-only ok");
  } else {
    const result = await runComparison();
    console.log(JSON.stringify(result, null, 2));
  }
} catch (err) {
  console.error(`error: ${err.message || err}`);
  exitCode = 1;
} finally {
  await stopProcess("pocketbase");
  await stopProcess("rustyBase");
  if (!options.keepTemp) {
    rmSync(tempDir, { recursive: true, force: true });
  } else {
    console.log(`pocketbase compare: kept temp dir ${tempDir}`);
  }
}

if (exitCode !== 0) {
  process.exit(exitCode);
}

async function runComparison() {
  if (options.fixture === "health") {
    return compareHealth();
  }
  if (options.fixture === "settings" || options.fixture === "settings-access") {
    return compareSettingsAccess();
  }
  if (options.fixture === "all") {
    const health = await compareHealth();
    const settings = await compareSettingsAccess();
    return {
      target: health.target,
      checks: [...health.checks, ...settings.checks]
    };
  }
  fail(`unknown fixture: ${options.fixture}`);
}

async function compareHealth() {
  const pocketbaseDataDir = join(tempDir, "pb_health_data");
  const rustyBaseDbPath = join(tempDir, "health-rusty-base.db");

  await bootstrapPocketBase(pocketbaseDataDir);

  const outcomes = await withPocketBaseServer(pocketbaseDataDir, async (pocketbaseUrl) =>
    withRustyBaseServer(rustyBaseDbPath, async (rustyBaseUrl) => ({
      pocketbase: await jsonRequest(`${pocketbaseUrl}/api/health`),
      rustyBase: await jsonRequest(`${rustyBaseUrl}/api/health`)
    }))
  );

  return {
    target: {
      pocketbase: targetPocketBaseVersion
    },
    checks: [
      {
        name: "health",
        pocketbase: normalizeHealth(outcomes.pocketbase),
        rustyBase: normalizeHealth(outcomes.rustyBase),
        status:
          normalizeHealth(outcomes.pocketbase).ok && normalizeHealth(outcomes.rustyBase).ok
            ? "matched"
            : "different"
      }
    ]
  };
}

async function compareSettingsAccess() {
  const fixture = loadServerFixture("settings");
  const pocketbaseDataDir = join(tempDir, "pb_settings_data");
  const rustyBaseDbPath = join(tempDir, "settings-rusty-base.db");

  const pocketbaseBefore = await withPocketBaseServer(pocketbaseDataDir, async (baseUrl) =>
    jsonRequest(`${baseUrl}/api/settings`)
  );

  await bootstrapPocketBase(pocketbaseDataDir);

  const pocketbaseAfter = await withPocketBaseServer(pocketbaseDataDir, async (baseUrl) => {
    const blocked = await jsonRequest(`${baseUrl}/api/settings`);
    const login = await jsonRequest(`${baseUrl}/api/collections/_superusers/auth-with-password`, {
      method: "POST",
      body: {
        identity: "root@example.com",
        password: "correct horse"
      }
    });
    const token = login.body && login.body.token;
    const authed = await jsonRequest(`${baseUrl}/api/settings`, { token });
    const settingsFlow = await runSettingsSuperuserFlow(baseUrl, token);
    return { blocked, login, authed, ...settingsFlow };
  });

  const rustyBase = await withRustyBaseServer(rustyBaseDbPath, async (baseUrl) => {
    const before = await jsonRequest(`${baseUrl}/api/settings`);
    await bootstrapRustyBase(baseUrl);
    const blocked = await jsonRequest(`${baseUrl}/api/settings`);
    const login = await jsonRequest(`${baseUrl}/api/collections/_superusers/auth-with-password`, {
      method: "POST",
      body: {
        identity: "root@example.com",
        password: "correct horse"
      }
    });
    const token = login.body && login.body.token;
    const authed = await jsonRequest(`${baseUrl}/api/settings`, { token });
    const settingsFlow = await runSettingsSuperuserFlow(baseUrl, token);
    return { before, blocked, login, authed, ...settingsFlow };
  });

  const pocketbaseLogin = normalizeHttpOutcome(pocketbaseAfter.login);
  const rustyBaseLogin = normalizeHttpOutcome(rustyBase.login);
  const pocketbaseAuthed = normalizeSettingsOutcome(pocketbaseAfter.authed);
  const rustyBaseAuthed = normalizeSettingsOutcome(rustyBase.authed);

  return {
    target: {
      pocketbase: targetPocketBaseVersion
    },
    fixture: {
      area: fixture.area,
      name: fixture.name
    },
    checks: [
      compareCase(
        fixture,
        "settings defaults are readable before superuser bootstrap",
        pocketbaseBefore,
        rustyBase.before,
        { paths: settingsDefaultComparisonPaths }
      ),
      compareCase(
        fixture,
        "settings require superuser after bootstrap",
        pocketbaseAfter.blocked,
        rustyBase.blocked
      ),
      {
        name: "superuser password auth returns a token for settings comparison",
        route: "POST /api/collections/_superusers/auth-with-password",
        pocketbase: pocketbaseLogin,
        rustyBase: rustyBaseLogin,
        status: normalizedMatch(pocketbaseLogin, rustyBaseLogin) ? "matched" : "different"
      },
      {
        name: "superuser can read settings after bootstrap",
        route: "GET /api/settings",
        pocketbase: pocketbaseAuthed,
        rustyBase: rustyBaseAuthed,
        status: normalizedMatch(pocketbaseAuthed, rustyBaseAuthed) ? "matched" : "different"
      },
      compareCase(
        fixture,
        "superuser patch updates settings and redacts secrets",
        pocketbaseAfter.patched,
        rustyBase.patched,
        { paths: settingsPatchComparisonPaths }
      ),
      compareCase(
        fixture,
        "redacted secret placeholders preserve stored secrets",
        pocketbaseAfter.redactedPatch,
        rustyBase.redactedPatch,
        { paths: settingsSecretComparisonPaths }
      ),
      compareCase(
        fixture,
        "settings fields projection returns selected settings",
        pocketbaseAfter.projected,
        rustyBase.projected,
        { paths: settingsProjectionComparisonPaths }
      ),
      compareCase(
        fixture,
        "invalid batch settings return field validation errors",
        pocketbaseAfter.invalidBatch,
        rustyBase.invalidBatch,
        { validationPaths: invalidBatchValidationPaths }
      ),
      compareCase(
        fixture,
        "enabled backup s3 settings require a secret",
        pocketbaseAfter.invalidBackup,
        rustyBase.invalidBackup,
        { validationPaths: invalidBackupValidationPaths }
      )
    ]
  };
}

async function runSettingsSuperuserFlow(baseUrl, token) {
  const patched = await jsonRequest(`${baseUrl}/api/settings`, {
    method: "PATCH",
    token,
    body: settingsPatchBody()
  });
  const redactedPatch = await jsonRequest(
    `${baseUrl}/api/settings?fields=${settingsSecretProjection}`,
    {
      method: "PATCH",
      token,
      body: settingsRedactedPatchBody()
    }
  );
  const projected = await jsonRequest(
    `${baseUrl}/api/settings?fields=${settingsFieldsProjection}`,
    { token }
  );
  const invalidBatch = await jsonRequest(`${baseUrl}/api/settings`, {
    method: "PATCH",
    token,
    body: { batch: { maxRequests: 0 } }
  });
  const invalidBackup = await jsonRequest(`${baseUrl}/api/settings`, {
    method: "PATCH",
    token,
    body: { backups: { s3: { enabled: true, secret: "" } } }
  });
  return { patched, redactedPatch, projected, invalidBatch, invalidBackup };
}

function settingsPatchBody() {
  return {
    meta: {
      appName: "Acme",
      appURL: "https://example.com",
      senderName: "Acme Ops",
      senderAddress: "noreply@example.com",
      hideControls: true
    },
    logs: {
      maxDays: 14,
      minLevel: 1,
      logIp: false,
      logAuthId: true
    },
    batch: {
      enabled: true,
      maxRequests: 2,
      timeout: 30,
      maxBodySize: 2048
    },
    smtp: {
      enabled: true,
      host: "smtp.example.com",
      port: 2525,
      username: "mailer",
      password: "smtp-secret",
      authMethod: "plain",
      tls: false,
      localName: "rusty-base"
    },
    s3: {
      enabled: true,
      bucket: "assets",
      region: "auto",
      endpoint: "https://s3.example.com",
      accessKey: "access",
      secret: "s3-secret",
      forcePathStyle: true
    },
    backups: {
      cron: "0 3 * * *",
      cronMaxKeep: 7,
      s3: {
        enabled: true,
        bucket: "backups",
        region: "auto",
        endpoint: "https://s3.example.com",
        accessKey: "backup-access",
        secret: "backup-secret"
      }
    },
    rateLimits: {
      enabled: true,
      rules: [
        {
          label: "/api/custom",
          audience: "@request.auth.id",
          duration: 15,
          maxRequests: 4
        }
      ]
    },
    trustedProxy: {
      headers: ["X-Forwarded-For", "CF-Connecting-IP"],
      useLeftmostIp: true
    }
  };
}

function settingsRedactedPatchBody() {
  return {
    smtp: { password: "******" },
    s3: { secret: "******" },
    backups: { s3: { secret: "******" } },
    batch: { maxRequests: 3 }
  };
}

async function bootstrapPocketBase(dataDir) {
  await execFileAsync(
    options.pocketbase,
    ["--dir", dataDir, "superuser", "upsert", "root@example.com", "correct horse"],
    { cwd: rootDir, timeout: options.timeoutMs }
  );
}

async function withPocketBaseServer(dataDir, work) {
  const port = await freePort();
  const addr = `127.0.0.1:${port}`;
  const baseUrl = `http://${addr}`;
  await startPocketBase(dataDir, addr, baseUrl);
  try {
    return await work(baseUrl);
  } finally {
    await stopProcess("pocketbase");
  }
}

async function withRustyBaseServer(dbPath, work) {
  const port = await freePort();
  const addr = `127.0.0.1:${port}`;
  const baseUrl = `http://${addr}`;
  await startRustyBase(dbPath, addr, baseUrl);
  try {
    return await work(baseUrl);
  } finally {
    await stopProcess("rustyBase");
  }
}

async function bootstrapRustyBase(baseUrl) {
  await jsonRequest(`${baseUrl}/api/collections`, {
    method: "POST",
    body: {
      name: "_superusers",
      type: "auth",
      fields: [{ name: "email", type: "email" }]
    }
  });
  await jsonRequest(`${baseUrl}/api/collections/_superusers/records`, {
    method: "POST",
    body: {
      id: "su_1",
      email: "root@example.com",
      password: "correct horse",
      passwordConfirm: "correct horse"
    }
  });
}

async function startPocketBase(dataDir, addr, baseUrl) {
  console.log(`pocketbase compare: starting PocketBase on ${baseUrl}`);
  state.pocketbaseLog = "";
  state.pocketbase = spawn(
    options.pocketbase,
    ["--dir", dataDir, "serve", "--http", addr],
    { cwd: rootDir, stdio: ["ignore", "pipe", "pipe"] }
  );
  state.pocketbase.stdout.on("data", (chunk) => {
    state.pocketbaseLog += chunk.toString();
  });
  state.pocketbase.stderr.on("data", (chunk) => {
    state.pocketbaseLog += chunk.toString();
  });
  await waitForServer("pocketbase", baseUrl);
}

async function startRustyBase(dbPath, addr, baseUrl) {
  console.log(`pocketbase compare: starting Rusty Base on ${baseUrl}`);
  state.rustyBaseLog = "";
  if (options.rustyBaseBin) {
    state.rustyBase = spawn(
      options.rustyBaseBin,
      ["serve", dbPath, addr],
      { cwd: rootDir, stdio: ["ignore", "pipe", "pipe"] }
    );
  } else {
    state.rustyBase = spawn(
      "cargo",
      ["run", "-p", "rb-server", "--", "serve", dbPath, addr],
      { cwd: rootDir, stdio: ["ignore", "pipe", "pipe"] }
    );
  }
  state.rustyBase.stdout.on("data", (chunk) => {
    state.rustyBaseLog += chunk.toString();
  });
  state.rustyBase.stderr.on("data", (chunk) => {
    state.rustyBaseLog += chunk.toString();
  });
  await waitForServer("rustyBase", baseUrl);
}

async function waitForServer(name, baseUrl) {
  const started = Date.now();
  while (Date.now() - started < options.timeoutMs) {
    const child = state[name];
    if (child && child.exitCode != null) {
      throw new Error(`${name} exited before ready\n${state[`${name}Log`]}`);
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
  throw new Error(`${name} did not become ready\n${state[`${name}Log`]}`);
}

async function stopProcess(name) {
  const child = state[name];
  if (!child) {
    return;
  }
  state[name] = null;
  if (child.exitCode != null || child.signalCode != null) {
    return;
  }
  await new Promise((resolve) => {
    child.once("close", resolve);
    child.kill();
  });
}

async function jsonRequest(url, opts = {}) {
  const headers = {};
  if (opts.body !== undefined) {
    headers["content-type"] = "application/json";
  }
  if (opts.token) {
    headers.authorization = `Bearer ${opts.token}`;
  }

  const response = await fetch(url, {
    method: opts.method || "GET",
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body)
  });
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (_) {
    body = text;
  }
  return {
    status: response.status,
    body
  };
}

function compareCase(fixture, name, pocketbase, rustyBase, options = {}) {
  const fixtureCase = fixture.cases.find((item) => item.name === name);
  const pocketbaseOutcome = normalizeSettingsOutcome(pocketbase, options);
  const rustyBaseOutcome = normalizeSettingsOutcome(rustyBase, options);
  return {
    name,
    route: fixtureCase && fixtureCase.route,
    expectedStatus: fixtureCase && fixtureCase.expectedStatus,
    expectedCode: fixtureCase && fixtureCase.expectedCode,
    pocketbase: pocketbaseOutcome,
    rustyBase: rustyBaseOutcome,
    status: normalizedMatch(pocketbaseOutcome, rustyBaseOutcome) ? "matched" : "different"
  };
}

function normalizeHealth(response) {
  return {
    ok: response.status === 200,
    code: response.body && response.body.code
  };
}

function normalizeSettingsOutcome(response, options = {}) {
  const body = response.body && typeof response.body === "object" ? response.body : null;
  const outcome = {
    ...normalizeHttpOutcome(response),
    bodyKeys:
      body ? Object.keys(body).sort() : []
  };
  if (options.paths && options.paths.length) {
    outcome.values = normalizePathValues(body, options.paths);
  }
  if (options.validationPaths && options.validationPaths.length) {
    outcome.validationCodes = normalizePathValues(body, options.validationPaths);
  }
  return outcome;
}

function normalizeHttpOutcome(response) {
  return {
    status: response.status,
    code: response.body && response.body.code,
    message: response.body && response.body.message,
    hasToken: Boolean(response.body && response.body.token)
  };
}

function normalizedMatch(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function normalizePathValues(body, paths) {
  const values = {};
  for (const path of paths) {
    values[pathLabel(path)] = normalizePathValue(valueAtPath(body, path));
  }
  return values;
}

function pathLabel(path) {
  return path.join(".");
}

function valueAtPath(value, path) {
  let current = value;
  for (const segment of path) {
    if (current == null || typeof current !== "object" || !(segment in current)) {
      return undefined;
    }
    current = current[segment];
  }
  return current;
}

function normalizePathValue(value) {
  return value === undefined ? { missing: true } : value;
}

function loadServerFixture(name) {
  const path = join(rootDir, "fixtures", "pocketbase", "server", `${name}.json`);
  return JSON.parse(readFileSync(path, "utf8"));
}

async function pocketbaseVersion(binary) {
  try {
    const result = await execFileAsync(binary, ["--version"], {
      cwd: rootDir,
      timeout: options.timeoutMs
    });
    return `${result.stdout}${result.stderr}`.trim();
  } catch (_) {
    const result = await execFileAsync(binary, ["version"], {
      cwd: rootDir,
      timeout: options.timeoutMs
    });
    return `${result.stdout}${result.stderr}`.trim();
  }
}

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  await new Promise((resolve) => server.close(resolve));
  return address.port;
}

function parseArgs(args) {
  const parsed = {
    checkOnly: false,
    help: false,
    keepTemp: false,
    fixture: "health",
    pocketbase: "",
    rustyBaseBin: "",
    timeoutMs: 30000
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
    } else if (arg === "--check-only") {
      parsed.checkOnly = true;
    } else if (arg === "--keep-temp") {
      parsed.keepTemp = true;
    } else if (arg === "--fixture") {
      parsed.fixture = requireValue(args, index, arg);
      index += 1;
    } else if (arg === "--pocketbase") {
      parsed.pocketbase = requireValue(args, index, arg);
      index += 1;
    } else if (arg === "--rusty-base-bin") {
      parsed.rustyBaseBin = requireValue(args, index, arg);
      index += 1;
    } else if (arg === "--timeout-ms") {
      parsed.timeoutMs = Number(requireValue(args, index, arg));
      if (!Number.isFinite(parsed.timeoutMs) || parsed.timeoutMs <= 0) {
        fail("--timeout-ms must be a positive number");
      }
      index += 1;
    } else {
      fail(`unknown argument: ${arg}`);
    }
  }

  return parsed;
}

function requireValue(args, index, name) {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    fail(`${name} requires a value`);
  }
  return value;
}

function printHelp() {
  console.log(`PocketBase comparison harness

Usage:
  node scripts/pocketbase_compare.mjs --pocketbase ./pocketbase
  node scripts/pocketbase_compare.mjs --pocketbase ./pocketbase --fixture settings

Options:
  --pocketbase <path>      PocketBase v${targetPocketBaseVersion} binary
  --rusty-base-bin <path>  Optional prebuilt rb-server binary
  --fixture <name>         health, settings, settings-access, or all; default health
  --check-only             Only verify the PocketBase binary version
  --keep-temp              Keep temporary data directories for inspection
  --timeout-ms <ms>        Startup and command timeout, default 30000
`);
}

function fail(message) {
  console.error(`error: ${message}`);
  console.error("run with --help for usage");
  process.exit(1);
}
