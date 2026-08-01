# Changelog

## v0.1.12

Adds Codex as a second supported harness alongside Claude Code.

### Added

- **`argus init --harness=codex`** wires the PreToolUse hook for Codex.
  Codex requires two additional manual steps Argus cannot perform on your
  behalf: enabling the hooks feature flag in your Codex config, and trusting
  the hook interactively (`/hooks` in a Codex session). `init` prints both
  steps; `argus doctor` FAILs if the flag isn't on and WARNs that trust
  can't be confirmed from disk (an untrusted hook is silently inert — there's
  no on-disk signal to check).
- **`argus doctor` now probes every installed harness**, not just one: it
  checks Claude Code when a Claude Code install is present and Codex when a
  Codex install is present, reporting a PASS/FAIL/WARN line per harness.
- **`internal/adapter.Shape`**: a seam that translates an Argus verdict into
  the strongest verdict a given harness can actually honor, and is
  constrained to only ever translate *more* restrictive, never looser.
  Codex's hook contract is deny-only (no interactive ask), so `Shape`
  collapses an Argus `ask` to `deny` on Codex rather than risk it being
  ignored as an implicit allow.

### Codex coverage — read before relying on this

Codex's PreToolUse hook CAN fire for four tool classes: `shell` (Bash),
`unified_exec`, `apply_patch` (Codex ≥ 0.123), and MCP tool calls — but
Argus's Codex matcher in this release wires only `tool_name == "Bash"`. **Only
Bash commands are gated on Codex today**, on the full severity ladder, so a
Bash-mediated read (`cat ~/.ssh/id_rsa`) is still caught. **MCP tool calls,
`apply_patch`, and `unified_exec` are not yet wired and run completely
ungated on Codex** — this is a known gap, tracked for a follow-up that widens
the matcher once the exact `tool_name` each of those reports is confirmed
against a live `codex` CLI (see the verification note's PENDING items). Do
not treat MCP as gated on Codex, and do not read this as parity with Claude
Code's matcher (`Bash`/`Write`/`Edit`/`mcp__*`).

This adapter was verified against Codex's public documentation and issue
tracker, not yet against a live `codex` CLI — confirm the flag name, default
state, and trust behavior against your installed Codex version before
relying on it.

## v0.1.11

Re-release of v0.1.10 — that version published incompletely (the two macOS
`darwin` platform packages were missing, so `npm i -g @lucasngucii/argus` failed
on macOS). v0.1.11 republishes the full platform matrix.

### Fixed

- **The release job now fails closed on a partial publish.** The platform-package
  publish loop did not abort when a single `npm publish` failed, so the main
  package could ship on top of a missing platform binary — exactly what produced
  the broken v0.1.10 on macOS. Each publish now retries a transient error and,
  if it ultimately fails, aborts the whole release rather than shipping a partial
  matrix.

## v0.1.10

Trust-hardening release — no engine or classifier changes; the verdicts are
identical. This makes the supply chain verifiable and the trust model explicit.

### Supply chain

- **npm packages now ship with [provenance](https://docs.npmjs.com/generating-provenance-statements)**
  (SLSA build attestation): every published package links back to the exact
  commit and GitHub Actions run that built it, so the prebuilt binary can be
  traced to source rather than trusted blindly.

### Changes

- **Renamed the npm scope from `@agrus/argus` to `@lucasngucii/argus`.** The old
  scope did not match the `argus` binary or the `lucasngucii` author and read as
  a typosquat signal. **Install with `npm install -g @lucasngucii/argus`** — the
  `@agrus` scope is deprecated. The repository URL casing was normalized to
  match the Go module path.
- **Added [`SECURITY.md`](SECURITY.md)**: a plain-spoken threat model (what Argus
  does and does not protect against, including the blast radius of a compromised
  Argus binary), private vulnerability reporting, and a "verify what you
  installed" guide (provenance, checksums, build from source).

## v0.1.9

### Security fixes

- **Fixed a catastrophic fail-open**: a dangerous command wrapped in `if`/`for`/`while`/`case`, a
  function body, `time`, or `coproc` was invisible to the classifier — `if true; then rm -rf /; fi`
  classified `safe`. Every executed statement inside these constructs is now surfaced and
  inspected, including a command substitution in a loop/case header, an `(( ))`/`[[ ]]`/`let`
  expression, a redirect target, or a heredoc body.
- **Fixed an `opaque-exec` false positive**: the rule's `-c` detection was unanchored and
  case-insensitive, so any command containing `-c `/`-C ` (e.g. `git -C /repo show HEAD:file`,
  git's repo-dir flag) was wrongly flagged as an opaque shell subshell.
- **`disk-format` no longer floors a device backup**: `dd if=/dev/sda of=backup.img` (a pure read
  into a file) is no longer treated as a destructive disk operation; writing to a raw device or an
  erase still floors.
- **`docker-service` no longer asks on read-only subcommands**: `docker service ls/ps/inspect` and
  similar views no longer prompt; mutating operations (`create`, `prune`, `down`, …) still do.

### Changes

- **A pure metadata listing (`ls`/`stat`/`du`) of Argus's own config, the Claude Code hook wiring,
  or a credential directory is now allowed** instead of always denied — viewing filenames and
  metadata doesn't disarm Argus or leak a secret. Every write, delete, content read (`cat`, `grep`,
  …), and `git` invocation against these paths is still floored, Bash-only.

## v0.1.8

### Security fixes

- **Fixed a `tool_name` fail-open**: a missing or mis-cased tool name (e.g. `"bash"` instead of
  `"Bash"`) made a dangerous command's subject resolve empty, classifying it `safe` instead of
  inspecting it. `rm -rf /` is now correctly denied regardless of `tool_name` casing.
- **Fixed a case-insensitive-filesystem bypass** on every self-protect and credential rule
  (`self-protect-claude-settings`, `self-protect-argus`, `credential-system-write`,
  `mcp-read-sensitive-path`, `mcp-fileop-sensitive-path`, `rc-file-inject`): on macOS (APFS) and
  Windows, `~/.claude` and `~/.CLAUDE` name the same directory, but the rules were case-sensitive
  and a single case variation bypassed them entirely.
- **Fixed a false-positive**: writing to Claude Code's own memory/project files
  (`~/.claude/projects/*/memory/*.md`) was incorrectly floored as a self-protect violation. The
  self-protect rule now only fires on the hook-wiring file itself, the whole `.claude` directory
  (or an obfuscated/dot-alias reference to it), or the `projects/` directory as a whole — not on
  ordinary files inside it.
- MCP reads of `/etc/shadow` are now correctly flagged (`mcp-read-sensitive-path`); `/etc/passwd`
  remains deliberately unflagged (not a real secret, a common benign read).

### Internal

- Introduced a harness-adapter seam (`internal/adapter`) so the gate's payload parsing and
  verdict emission are no longer hardcoded to Claude Code — groundwork for future support of
  other agent harnesses (Codex, Gemini). No user-visible change yet: `argus gate` still defaults
  to the Claude Code adapter, and `init`/`doctor` behavior is unchanged for existing installs.
- `doctor` now validates that a hand-edited hook command names a harness Argus actually knows,
  parsed the same way the live gate parses it (shell-tokenized, not a regex guess) — catches a
  misconfigured install that would otherwise silently deny every tool call.

## v0.1.7 and earlier

See [GitHub Releases](https://github.com/lucasngucii/argus/releases).
