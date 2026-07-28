import { test } from "node:test";
import assert from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

// Faithfully simulates a real install: the launcher package and the ONE
// matching platform package sit as siblings in the same node_modules, so the
// launcher's require.resolve finds the platform binary. The platform binary is
// the real host build.
test("launcher execs the resolved platform binary and passes args", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const suffix = `${process.platform}-${process.arch}`;
  const work = mkdtempSync(path.join(tmpdir(), "argus-launcher-"));
  const scope = path.join(work, "node_modules", "@agrus");

  // launcher package (sibling)
  const mainBin = path.join(scope, "argus", "bin");
  mkdirSync(mainBin, { recursive: true });
  copyFileSync(path.join(root, "npm/argus/bin/argus.js"), path.join(mainBin, "argus.js"));
  writeFileSync(
    path.join(scope, "argus", "package.json"),
    JSON.stringify({ name: "@agrus/argus", version: "0.0.0" }),
  );

  // matching platform package with the real host binary
  const platBin = path.join(scope, `argus-${suffix}`, "bin");
  mkdirSync(platBin, { recursive: true });
  execFileSync("go", ["build", "-o", path.join(platBin, "argus"), "./cmd/argus"], {
    cwd: root,
    env: { ...process.env, CGO_ENABLED: "0" },
  });
  writeFileSync(
    path.join(scope, `argus-${suffix}`, "package.json"),
    JSON.stringify({ name: `@agrus/argus-${suffix}`, version: "0.0.0" }),
  );

  const out = execFileSync("node", [path.join(mainBin, "argus.js"), "version"]).toString();
  assert.match(out, /argus \d+\.\d+\.\d+/);
});
