import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const adminHtmlPath = "crates/rb-server/src/server/admin/index.html";
const html = readFileSync(adminHtmlPath, "utf8");
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];

if (scripts.length === 0) {
  console.error(`No inline scripts found in ${adminHtmlPath}`);
  process.exit(1);
}

const tempDir = mkdtempSync(join(tmpdir(), "rusty-base-admin-js-"));

try {
  for (const [index, script] of scripts.entries()) {
    const scriptPath = join(tempDir, `admin-inline-${index + 1}.js`);
    writeFileSync(scriptPath, script[1], "utf8");
    const result = spawnSync(process.execPath, ["--check", scriptPath], {
      encoding: "utf8"
    });
    if (result.status !== 0) {
      process.stderr.write(result.stdout);
      process.stderr.write(result.stderr);
      process.exit(result.status || 1);
    }
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
