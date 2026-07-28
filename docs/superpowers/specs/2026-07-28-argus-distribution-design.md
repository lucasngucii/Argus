# Argus Distribution — Design (Plan 3 of 4)

> Turns the built binary into something a user installs in one line. Consumes
> Plans 1–2 (the `argus` binary and its commands) unchanged; adds no product
> behavior — only packaging, versioning, and release automation.

## Goal

A single command — `npm install -g @lucasngucii/argus` — lands a prebuilt
native `argus` binary on the user's PATH, with no Go toolchain required. In
parallel, every tagged version publishes cross-compiled archives + checksums to
GitHub Releases for users who prefer a direct download or `go install`.

Pure-Go (`CGO_ENABLED=0`) is the enabling constraint: one CI host cross-compiles
the whole matrix by setting `GOOS`/`GOARCH`, with no C cross-toolchains.

## Decisions (settled)

- **Package name:** `@lucasngucii/argus` (scoped — collision-free on npm; the
  unscoped `argus` is almost certainly taken). The executable is still `argus`.
- **Platform matrix (tier-1):** `darwin/arm64`, `darwin/amd64`, `linux/arm64`,
  `linux/amd64`. Windows is roadmap (its `init`/hook path needs separate
  validation and is not free to verify).
- **Fallback:** when npm installs no matching platform package, the launcher
  prints an actionable error (download from Releases, or `go install`) and exits
  non-zero. No network download in `postinstall` — deterministic installs, no
  supply-chain/reliability footgun.

## Architecture

The esbuild/turbo distribution pattern, kept minimal.

### npm packages (zero runtime deps, no build toolchain)

All packaging lives under `npm/` in the repo:

- **`npm/argus/` → `@lucasngucii/argus`** (the package users install):
  - `package.json`: `bin: { "argus": "bin/argus.js" }`, `optionalDependencies`
    naming all four platform packages at the exact same version, and no runtime
    dependencies.
  - `bin/argus.js`: a launcher using **only Node built-ins** (`child_process`,
    `path`). It computes `@lucasngucii/argus-<os>-<arch>` from `process.platform`
    + `process.arch`, `require.resolve`s that package's binary, and
    `execFileSync`s it with the original argv, inherited stdio, and the child's
    exit code propagated. On resolve failure it prints install guidance to
    stderr and exits 1.
- **`npm/argus-<os>-<arch>/` → `@lucasngucii/argus-<os>-<arch>`** (four of them):
  - `package.json` with `os` and `cpu` fields so npm installs only the one
    matching the host, `version` locked to the main package, and the binary file
    (`bin/argus`, or the platform's name) as the package's only real content.

This respects CLAUDE.md's "no JS build toolchain" rule: there is no bundler and
no dependency tree — the "build" is copying prebuilt Go binaries into package
folders. The launcher is dependency-free plain Node.

### Version stamping

`internal/version` currently hard-codes `0.1.0-dev`. Refactor to a package-level
`var version = "0.0.0-dev"` that `String()` returns, settable at link time:

```
-ldflags "-X github.com/lucasngucii/argus/internal/version.version=<tag>"
```

Source builds still report the `-dev` default; released binaries report the git
tag. The existing "looks like semver" test stays.

### Release pipeline (GitHub Actions)

- **`.github/workflows/ci.yml`** (on push + PR to `main`): `go vet ./...`,
  `go build ./...`, `go test ./...` with `CGO_ENABLED=0`. This fills the current
  no-CI gap and must be green before any release.
- **`.github/workflows/release.yml`** (on tag `v*`):
  1. Cross-compile the four targets (`GOOS`/`GOARCH`, `CGO_ENABLED=0`), stamping
     the version from the tag via ldflags.
  2. Produce `argus-<os>-<arch>.tar.gz` archives and a `checksums.txt` (sha256).
  3. Create a GitHub Release with the archives + checksums attached.
  4. Copy each binary into its platform package, set all five package versions to
     the tag (stripped of the leading `v`), and `npm publish` the main + four
     platform packages (`NPM_TOKEN`, `--access public`).
- **`scripts/build-dist.sh`**: cross-compiles and assembles the packages locally,
  so the release logic is testable without cutting a real release.

## Data flow

```
git tag vX.Y.Z ──▶ release.yml
   ├─ go build (×4, ldflags version=X.Y.Z) ─▶ argus-<os>-<arch>
   ├─ tar.gz + sha256 ─▶ GitHub Release assets
   └─ copy binaries ─▶ npm/argus-<os>-<arch>/ ─▶ npm publish (×5)

user: npm i -g @lucasngucii/argus
   └─ npm installs main + the ONE os/cpu-matching platform pkg
        └─ `argus …` ─▶ bin/argus.js ─▶ execFileSync(resolved binary, argv)
```

## Error handling

- **Unsupported platform / optional dep absent:** launcher exits 1 with a
  message naming the platform and pointing at Releases + `go install`.
- **Resolved binary not executable:** surfaced as the `execFileSync` error, exit
  non-zero — never a silent success.
- **Release publish partial failure:** `npm publish` is idempotent per
  version; a failed run is re-runnable on the same tag. Platform packages are
  published before (or alongside) the main package so the main package's
  optionalDependencies always resolve.

## Testing

Per CLAUDE.md ("shells: one integration test"; deterministic):

- **Launcher integration test:** place a real (locally cross-compiled) binary in
  the expected platform-package location and run `node bin/argus.js version`;
  assert it prints the version and propagates argv + exit code. One test.
- **Version stamping:** a CI/test step builds with a sample `-X` ldflag and
  asserts `argus version` reports it — proving the link-time override is wired.
- **Release dry-run:** `scripts/build-dist.sh` runs in CI (matrix build +
  package assembly) without publishing, so the packaging is exercised on every
  change that touches it.

## Non-goals (YAGNI)

Homebrew tap · Windows binaries · auto-update · `postinstall` network download ·
macOS signing/notarization · Linux distro packages (deb/rpm). Each is roadmap,
not v1 distribution.

## Open items for the maintainer

1. Confirm `@lucasngucii/argus` is the desired npm identity (vs. an unscoped
   name you own), and that an `NPM_TOKEN` with publish rights exists as a repo
   secret.
2. Confirm the tag convention is `vX.Y.Z` (drives the release trigger + version
   strip).
