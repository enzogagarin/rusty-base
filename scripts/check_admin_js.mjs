import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const adminHtmlPath = "crates/rb-server/src/server/admin/index.html";
const html = readFileSync(adminHtmlPath, "utf8");
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];

if (scripts.length === 0) {
  console.error(`No scripts found in ${adminHtmlPath}`);
  process.exit(1);
}

const tempDir = mkdtempSync(join(tmpdir(), "rusty-base-admin-js-"));
const checkedScripts = new Set();

try {
  for (const [index, script] of scripts.entries()) {
    const src = script[0].match(/\bsrc=["']([^"']+)["']/i)?.[1];
    if (src) {
      checkScriptPath(adminAssetPath(src));
    } else {
      const scriptPath = join(tempDir, `admin-inline-${index + 1}.mjs`);
      writeFileSync(scriptPath, script[1], "utf8");
      checkScriptPath(scriptPath);
    }
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}

function adminAssetPath(src) {
  const prefix = "/_/admin/";
  if (!src.startsWith(prefix)) {
    console.error(`Unsupported admin script src: ${src}`);
    process.exit(1);
  }
  const scriptPath = `crates/rb-server/src/server/admin/${src.slice(prefix.length)}`;
  if (!existsSync(scriptPath)) {
    console.error(`Missing admin script: ${scriptPath}`);
    process.exit(1);
  }
  return scriptPath;
}

function checkScriptPath(scriptPath) {
  const absolutePath = resolve(scriptPath);
  if (checkedScripts.has(absolutePath)) {
    return;
  }
  checkedScripts.add(absolutePath);

  const source = readFileSync(absolutePath, "utf8");
  const checkPath = join(tempDir, `admin-check-${checkedScripts.size}.mjs`);
  writeFileSync(checkPath, source, "utf8");
  const result = spawnSync(process.execPath, ["--check", checkPath], {
    encoding: "utf8"
  });
  if (result.status !== 0) {
    process.stderr.write(result.stdout);
    process.stderr.write(result.stderr);
    process.exit(result.status || 1);
  }

  for (const specifier of moduleSpecifiers(source)) {
    if (specifier.startsWith("./") || specifier.startsWith("../")) {
      checkScriptPath(resolve(dirname(absolutePath), specifier));
    }
  }
}

function moduleSpecifiers(source) {
  return [
    ...source.matchAll(/\bimport\s+(?:[^"']+\s+from\s+)?["']([^"']+)["']/g)
  ].map((match) => match[1]);
}
