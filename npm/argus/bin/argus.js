#!/usr/bin/env node
"use strict";

// Dependency-free launcher: resolve the os/cpu-matching platform package's
// binary and exec it, propagating argv, stdio, and exit code. No network, no
// deps — the binary was installed by npm as an optionalDependency.
const { execFileSync } = require("child_process");

function resolveBinary() {
  const pkg = `@lucasngucii/argus-${process.platform}-${process.arch}`;
  const file = process.platform === "win32" ? "argus.exe" : "argus";
  try {
    return require.resolve(`${pkg}/bin/${file}`);
  } catch {
    return null;
  }
}

const bin = resolveBinary();
if (!bin) {
  process.stderr.write(
    `argus: no prebuilt binary for ${process.platform}-${process.arch}.\n` +
      `Download from https://github.com/lucasngucii/Argus/releases or run:\n` +
      `  go install github.com/lucasngucii/argus/cmd/argus@latest\n`,
  );
  process.exit(1);
}

try {
  execFileSync(bin, process.argv.slice(2), { stdio: "inherit" });
} catch (err) {
  process.exit(typeof err.status === "number" ? err.status : 1);
}
