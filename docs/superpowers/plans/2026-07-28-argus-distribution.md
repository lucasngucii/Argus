# Argus Distribution — Implementation Plan (Plan 3 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. REQUIRED before each task: read `CLAUDE.md` + invoke **argus-architect**.

**Goal:** Ship `argus` as a one-line `npm install -g @lucasngucii/argus` (prebuilt native binary, no Go toolchain) plus tagged GitHub Releases with cross-compiled archives + checksums.

**Architecture:** The esbuild/turbo pattern: a dependency-free Node launcher package with `optionalDependencies` on four per-platform packages (each `os`/`cpu`-gated, each holding one prebuilt binary). A CI release workflow cross-compiles the matrix on a `v*` tag (`CGO_ENABLED=0` → no C toolchains), attaches archives to a GitHub Release, and `npm publish`es all five packages. No product behavior changes — only packaging, version stamping, and release automation.

**Tech Stack:** Go 1.26 (`CGO_ENABLED=0`, ldflags version stamping) · Node ≥18 built-ins only (no npm deps, no bundler) · GitHub Actions · `tar` + `shasum`.

## Global Constraints

- Module `github.com/lucasngucii/argus`. Go **1.26**, **`CGO_ENABLED=0`** everywhere.
- The npm packages carry **zero runtime dependencies** and **no build toolchain** — the launcher uses only Node built-ins (`child_process`, `path`); the "build" is copying prebuilt Go binaries. (Honors CLAUDE.md "no JS build toolchain".)
- **Package identity:** main package `@lucasngucii/argus`, executable name `argus`. Platform packages `@lucasngucii/argus-<node-platform>-<node-arch>` using **Node** naming (`darwin`/`linux`, `x64`/`arm64`) — NOT Go's `amd64`. build-dist maps Go `amd64`→`x64`.
- **Platform matrix (tier-1):** `darwin-arm64`, `darwin-x64`, `linux-arm64`, `linux-x64`. Windows is out of scope (roadmap).
- **Version is the git tag.** Source builds report `0.0.0-dev`; releases stamp the tag (minus leading `v`) via ldflags `-X github.com/lucasngucii/argus/internal/version.version=<v>`.
- **Fallback is error-only** — no `postinstall` network download. Unsupported platform → the launcher prints Releases + `go install` guidance and exits non-zero.
- Never publish binaries into git: platform-package `bin/` dirs are gitignored; only `package.json` templates and the JS launcher are committed.
- Commit identity `lucasngucii <lucasalehwork@gmail.com>`; **never** a `Co-Authored-By: Claude` trailer. Conventional commits, one logical change each.

## Consumes from Plans 1–2 (do not change behavior)

```go
// internal/version — the ONLY Go file this plan modifies.
package version
func String() string // currently returns the hard-coded "0.1.0-dev"
```
The `cmd/argus` entrypoint and all `internal/*` behavior are untouched.

## File Structure

```
internal/version/version.go        # MODIFY: hard-coded const -> ldflags-settable var
Makefile                           # MODIFY: stamp version in the build target
npm/argus/package.json             # NEW: main package (bin + optionalDependencies)
npm/argus/bin/argus.js             # NEW: dependency-free Node launcher
npm/argus-darwin-arm64/package.json# NEW: platform template (os/cpu gated)
npm/argus-darwin-x64/package.json  # NEW
npm/argus-linux-arm64/package.json # NEW
npm/argus-linux-x64/package.json   # NEW
scripts/build-dist.sh              # NEW: cross-compile + archive + checksum + assemble
scripts/set-versions.mjs           # NEW: stamp version into all 5 package.json files
test/launcher.test.mjs             # NEW: launcher integration test (node:test)
.github/workflows/ci.yml           # NEW: vet + build + test on push/PR
.github/workflows/release.yml      # NEW: tag v* -> build, release, npm publish
.gitignore                         # MODIFY: ignore npm/argus-*/bin/
README.md                          # MODIFY: npm install as the primary path
```

---

### Task 1: Version stamping via ldflags

**Files:**
- Modify: `internal/version/version.go`
- Test: `internal/version/version_test.go` (exists)
- Modify: `Makefile`

**Interfaces:**
- Consumes: nothing.
- Produces: `version.String() string` (unchanged signature); a package `var version` overridable at link time with `-X github.com/lucasngucii/argus/internal/version.version=<v>`.

- [ ] **Step 1: Write the failing test.** Append to `internal/version/version_test.go`:

```go
func TestDefaultVersionIsDevPlaceholder(t *testing.T) {
	if got := String(); got != "0.0.0-dev" {
		t.Fatalf("default String() = %q, want %q (ldflags override is applied at build)", got, "0.0.0-dev")
	}
}
```

- [ ] **Step 2: Run → FAIL.** `CGO_ENABLED=0 go test ./internal/version/ -run TestDefaultVersionIsDevPlaceholder` → FAIL (current value is `0.1.0-dev`).

- [ ] **Step 3: Implement.** Replace the body of `internal/version/version.go`:

```go
// Package version reports the Argus build version.
package version

// version is the build version. It defaults to a dev placeholder and is
// overridden at link time by release builds via:
//
//	-ldflags "-X github.com/lucasngucii/argus/internal/version.version=<tag>"
var version = "0.0.0-dev"

// String returns the current Argus semantic version.
func String() string { return version }
```

- [ ] **Step 4: Run → PASS.** `CGO_ENABLED=0 go test ./internal/version/` (both the new test and the existing `TestStringIsSemver` pass).

- [ ] **Step 5: Verify the override works.** Run:

```bash
CGO_ENABLED=0 go run -ldflags "-X github.com/lucasngucii/argus/internal/version.version=1.2.3" ./cmd/argus version
```
Expected: prints `argus 1.2.3`.

- [ ] **Step 6: Stamp the Makefile build.** Replace the `build:` line in `Makefile`:

```make
export CGO_ENABLED=0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
build: ; go build -ldflags "-X github.com/lucasngucii/argus/internal/version.version=$(VERSION)" -o bin/argus ./cmd/argus
test: ; go test ./...
bench: ; go test -run=x -bench=. ./...
```

- [ ] **Step 7: Verify + commit.** `make build && ./bin/argus version` prints a git-describe version. Then:

```bash
git add internal/version/version.go internal/version/version_test.go Makefile
git commit -m "feat(version): ldflags-settable build version (0.0.0-dev default)"
```

---

### Task 2: npm main package + dependency-free launcher

**Files:**
- Create: `npm/argus/package.json`, `npm/argus/bin/argus.js`
- Test: `test/launcher.test.mjs`

**Interfaces:**
- Consumes: a platform package `@lucasngucii/argus-<platform>-<arch>` exposing its binary at `bin/argus` (built in Task 3).
- Produces: the launcher contract — `argus <args…>` execs the resolved native binary with inherited stdio and propagates its exit code; on no match, exits 1 with guidance.

- [ ] **Step 1: Write the failing test.** Create `test/launcher.test.mjs`:

```js
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
  const scope = path.join(work, "node_modules", "@lucasngucii");

  // launcher package (sibling)
  const mainBin = path.join(scope, "argus", "bin");
  mkdirSync(mainBin, { recursive: true });
  copyFileSync(path.join(root, "npm/argus/bin/argus.js"), path.join(mainBin, "argus.js"));
  writeFileSync(path.join(scope, "argus", "package.json"),
    JSON.stringify({ name: "@lucasngucii/argus", version: "0.0.0" }));

  // matching platform package with the real host binary
  const platBin = path.join(scope, `argus-${suffix}`, "bin");
  mkdirSync(platBin, { recursive: true });
  execFileSync("go", ["build", "-o", path.join(platBin, "argus"), "./cmd/argus"],
    { cwd: root, env: { ...process.env, CGO_ENABLED: "0" } });
  writeFileSync(path.join(scope, `argus-${suffix}`, "package.json"),
    JSON.stringify({ name: `@lucasngucii/argus-${suffix}`, version: "0.0.0" }));

  const out = execFileSync("node", [path.join(mainBin, "argus.js"), "version"]).toString();
  assert.match(out, /argus \d+\.\d+\.\d+/);
});
```

- [ ] **Step 2: Run → FAIL.** `node --test test/launcher.test.mjs` → FAIL (`npm/argus/bin/argus.js` does not exist).

- [ ] **Step 3: Implement the launcher.** Create `npm/argus/bin/argus.js`:

```js
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
    `  go install github.com/lucasngucii/argus/cmd/argus@latest\n`
  );
  process.exit(1);
}

try {
  execFileSync(bin, process.argv.slice(2), { stdio: "inherit" });
} catch (err) {
  process.exit(typeof err.status === "number" ? err.status : 1);
}
```

- [ ] **Step 4: Create the main package.json.** Create `npm/argus/package.json`:

```json
{
  "name": "@lucasngucii/argus",
  "version": "0.0.0",
  "description": "Argus — a permission gate for AI coding agents.",
  "bin": { "argus": "bin/argus.js" },
  "files": ["bin/argus.js"],
  "optionalDependencies": {
    "@lucasngucii/argus-darwin-arm64": "0.0.0",
    "@lucasngucii/argus-darwin-x64": "0.0.0",
    "@lucasngucii/argus-linux-arm64": "0.0.0",
    "@lucasngucii/argus-linux-x64": "0.0.0"
  },
  "engines": { "node": ">=18" },
  "license": "MIT",
  "repository": { "type": "git", "url": "https://github.com/lucasngucii/Argus.git" }
}
```

- [ ] **Step 5: Run → PASS.** `node --test test/launcher.test.mjs` → PASS.

- [ ] **Step 6: Commit.**

```bash
git add npm/argus/package.json npm/argus/bin/argus.js test/launcher.test.mjs
git commit -m "feat(dist): npm launcher package (dependency-free, os/cpu resolve)"
```

---

### Task 3: Platform package templates + build-dist + version stamping

**Files:**
- Create: `npm/argus-darwin-arm64/package.json`, `npm/argus-darwin-x64/package.json`, `npm/argus-linux-arm64/package.json`, `npm/argus-linux-x64/package.json`
- Create: `scripts/build-dist.sh`, `scripts/set-versions.mjs`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `internal/version.version` ldflags path (Task 1); the platform-package naming contract (Task 2).
- Produces: `scripts/build-dist.sh <version>` → `dist/argus-<suffix>.tar.gz` + `dist/checksums.txt`, and each `npm/argus-<suffix>/bin/argus` populated. `scripts/set-versions.mjs <version>` → all five `package.json` versions (and the main package's optionalDependencies) set to `<version>`.

- [ ] **Step 1: Create the four platform templates.** Each `npm/argus-<suffix>/package.json` (substitute `<platform>`/`<cpu>`/`<suffix>` per the table):

```json
{
  "name": "@lucasngucii/argus-<suffix>",
  "version": "0.0.0",
  "description": "Argus prebuilt binary for <suffix>.",
  "os": ["<platform>"],
  "cpu": ["<cpu>"],
  "files": ["bin/"],
  "license": "MIT",
  "repository": { "type": "git", "url": "https://github.com/lucasngucii/Argus.git" }
}
```

| suffix | platform | cpu |
|---|---|---|
| darwin-arm64 | darwin | arm64 |
| darwin-x64 | darwin | x64 |
| linux-arm64 | linux | arm64 |
| linux-x64 | linux | x64 |

- [ ] **Step 2: Ignore built binaries.** Append to `.gitignore`:

```
/npm/argus-*/bin/
/dist/
```

- [ ] **Step 3: Write `scripts/set-versions.mjs`** (Node built-ins only):

```js
#!/usr/bin/env node
// Set the version across all five packages, and the main package's
// optionalDependencies, to the argument. Built-ins only.
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const version = process.argv[2];
if (!version) { console.error("usage: set-versions.mjs <version>"); process.exit(2); }

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
for (const s of suffixes) write(`npm/argus-${s}/package.json`, (j) => { j.version = version; });
console.log(`set version ${version} across ${suffixes.length + 1} packages`);
```

- [ ] **Step 4: Write `scripts/build-dist.sh`:**

```bash
#!/usr/bin/env bash
# Cross-compile the release matrix, archive + checksum each, and assemble the
# npm platform packages. Usage: scripts/build-dist.sh [version]
set -euo pipefail
VERSION="${1:-0.0.0-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
LDFLAGS="-s -w -X github.com/lucasngucii/argus/internal/version.version=${VERSION}"

rm -rf "$DIST"; mkdir -p "$DIST"

# "GOOS GOARCH node-suffix"
targets=(
  "darwin arm64 darwin-arm64"
  "darwin amd64 darwin-x64"
  "linux  arm64 linux-arm64"
  "linux  amd64 linux-x64"
)
for t in "${targets[@]}"; do
  read -r goos goarch suffix <<<"$t"
  bin="$DIST/argus-$suffix"
  echo "building $suffix ..."
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -ldflags "$LDFLAGS" -o "$bin" "$ROOT/cmd/argus"
  ( cd "$DIST" && tar -czf "argus-$suffix.tar.gz" "argus-$suffix" )
  pkgbin="$ROOT/npm/argus-$suffix/bin"
  mkdir -p "$pkgbin"; cp "$bin" "$pkgbin/argus"; chmod +x "$pkgbin/argus"
done
( cd "$DIST" && shasum -a 256 argus-*.tar.gz > checksums.txt )

node "$ROOT/scripts/set-versions.mjs" "$VERSION"
echo "built $VERSION -> $DIST (and assembled npm/ platform packages)"
```

- [ ] **Step 5: Smoke-test build-dist on the host.** Run:

```bash
chmod +x scripts/build-dist.sh
scripts/build-dist.sh 9.9.9
```
Expected: `dist/checksums.txt` lists four `.tar.gz`; each `npm/argus-<suffix>/bin/argus` exists; `npm/argus/package.json` and all four templates show `"version": "9.9.9"`; the main package's optionalDependencies are all `9.9.9`.

- [ ] **Step 6: Verify a cross-built binary is stamped.** Run (host binary is the one for your platform suffix):

```bash
./npm/argus-$(go env GOOS | sed s/amd64/x64/)-$(go env GOARCH | sed s/amd64/x64/)/bin/argus version 2>/dev/null || \
  ./dist/argus-$(go env GOOS)-$(go env GOARCH | sed s/amd64/x64/) version
```
Expected: prints `argus 9.9.9`. Then restore the templates' versions (build-dist mutated them): `git checkout npm/ && git clean -fd npm/ dist/`.

- [ ] **Step 7: Commit** (templates + scripts + gitignore; NOT the built binaries or mutated versions):

```bash
git add npm/argus-*/package.json scripts/build-dist.sh scripts/set-versions.mjs .gitignore
git commit -m "feat(dist): platform package templates + build-dist + set-versions"
```

---

### Task 4: CI workflow (vet + build + test)

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the Go module + `test/launcher.test.mjs`.
- Produces: a required status check on push/PR to `main`.

- [ ] **Step 1: Write the workflow.** Create `.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
env:
  CGO_ENABLED: "0"
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
      - run: go vet ./...
      - run: go build ./...
      - run: go test ./...
  launcher:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: node --test test/launcher.test.mjs
```

- [ ] **Step 2: Validate the YAML locally.** Run:

```bash
python3 -c "import sys,yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml valid')"
```
Expected: `ci.yml valid`. (If `actionlint` is installed, run it too.)

- [ ] **Step 3: Commit.**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: vet + build + test + launcher check on push/PR"
```

*(This workflow runs for real once the branch is pushed; that push is the driven verification.)*

---

### Task 5: Release workflow (tag → build → release → npm publish)

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `scripts/build-dist.sh` (Task 3); repo secret `NPM_TOKEN`.
- Produces: on a `v*` tag — a GitHub Release with archives + `checksums.txt`, and five published npm packages at the tag version.

- [ ] **Step 1: Write the workflow.** Create `.github/workflows/release.yml`:

```yaml
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          registry-url: "https://registry.npmjs.org"
      - name: Derive version
        id: v
        run: echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"
      - name: Build matrix + assemble packages
        run: scripts/build-dist.sh "${{ steps.v.outputs.version }}"
      - name: GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/argus-*.tar.gz
            dist/checksums.txt
      - name: Publish platform packages
        run: |
          for s in darwin-arm64 darwin-x64 linux-arm64 linux-x64; do
            npm publish "npm/argus-$s" --access public
          done
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
      - name: Publish main package
        run: npm publish npm/argus --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Note: platform packages publish BEFORE the main package, so the main package's `optionalDependencies` resolve on the registry immediately.

- [ ] **Step 2: Validate the YAML.** Run:

```bash
python3 -c "import sys,yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('release.yml valid')"
```
Expected: `release.yml valid`.

- [ ] **Step 3: Commit.**

```bash
git add .github/workflows/release.yml
git commit -m "ci: release workflow — tag v* builds, releases, and npm publishes"
```

---

### Task 6: Docs — npm install as the primary path

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the published package name + fallback behavior.
- Produces: accurate install docs.

- [ ] **Step 1: Rewrite the Install section.** Replace the `## Install` section body in `README.md` with:

```markdown
## Install

```bash
# prebuilt binary via npm (no Go toolchain needed)
npm install -g @lucasngucii/argus

# or download a release archive:
#   https://github.com/lucasngucii/Argus/releases
# or build from source (Go 1.26+):
go install github.com/lucasngucii/argus/cmd/argus@latest
```

Supported prebuilt platforms: macOS and Linux (arm64 + x64). On any other
platform, `npm` prints a pointer to the release archives / `go install`.
```

- [ ] **Step 2: Verify + commit.** Confirm the code fence renders and the package name matches `npm/argus/package.json`. Then:

```bash
git add README.md
git commit -m "docs: npm install as the primary path"
```

---

## Self-Review

**Spec coverage:** npm launcher + optionalDependencies (T2) · four `os`/`cpu`-gated platform packages (T3) · error-only fallback (T2 launcher) · version stamping via ldflags (T1) · `build-dist.sh` local packaging (T3) · `ci.yml` (T4) · tag-driven `release.yml` with GitHub Release + npm publish (T5) · zero-dep, no-toolchain launcher [Global + T2] · Node-vs-Go arch naming mapping [Global + T3] · docs (T6). Every spec section maps to a task.

**Placeholder scan:** no TBD/TODO; every code/config step carries full content; the platform template is parameterized by an explicit table, not "similar to".

**Type/name consistency:** the ldflags path `github.com/lucasngucii/argus/internal/version.version` is identical in T1, Makefile, and `build-dist.sh`. Package names `@lucasngucii/argus[-<suffix>]` and suffixes `darwin-arm64|darwin-x64|linux-arm64|linux-x64` are identical across launcher (T2), templates (T3), `set-versions.mjs` (T3), and `release.yml` (T5). The binary is at `bin/argus` in every platform package (launcher resolve, build-dist copy, template `files`).

**Ordering:** T1 (version) → T2 (launcher, tested against a host build) → T3 (templates + build-dist consume T1's ldflags + T2's naming) → T4/T5 (workflows consume T3) → T6 (docs). T4 and T5 are independent of each other.

**Verification honesty:** the Go change (T1) and launcher (T2) have real deterministic tests; `build-dist.sh` (T3) has a host smoke-test; the workflows (T4/T5) are YAML-validated locally and truly verified by the first push / first tag — noted as such, not claimed as unit-tested.

## Open items for the maintainer (from the spec)

1. Confirm `@lucasngucii/argus` is the intended npm identity and that an `NPM_TOKEN` secret with publish rights exists.
2. Confirm the `vX.Y.Z` tag convention (drives the release trigger + version strip).
