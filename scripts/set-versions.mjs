#!/usr/bin/env node
// Set the version across all five packages, and the main package's
// optionalDependencies, to the argument. Built-ins only.
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const version = process.argv[2];
if (!version) {
  console.error("usage: set-versions.mjs <version>");
  process.exit(2);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const suffixes = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"];

const write = (rel, mutate) => {
  const p = path.join(root, rel);
  const j = JSON.parse(readFileSync(p, "utf8"));
  mutate(j);
  writeFileSync(p, JSON.stringify(j, null, 2) + "\n");
};

write("npm/argus/package.json", (j) => {
  j.version = version;
  for (const s of suffixes) j.optionalDependencies[`@lucasngucii/argus-${s}`] = version;
});
for (const s of suffixes) write(`npm/argus-${s}/package.json`, (j) => (j.version = version));
console.log(`set version ${version} across ${suffixes.length + 1} packages`);
