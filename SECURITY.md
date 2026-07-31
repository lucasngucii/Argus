# Security Policy

Argus is a security tool that sits in a maximally privileged position — in front
of every shell command, file write, and MCP tool call your AI coding agent
makes. It should be held to the skeptical standard you'd apply to anything with
that reach. This document states, plainly, what Argus does and does not protect
you from, and how to report a problem.

## Reporting a vulnerability

Please report privately — **do not** open a public issue for a security bug.

- Preferred: [GitHub private vulnerability reporting](https://github.com/lucasngucii/argus/security/advisories/new).
- Email: `lucasalehwork@gmail.com`.

Include the version (`argus version`), your OS/arch, and a minimal reproduction
(ideally an `argus explain "<command>"` transcript). A fail-open — any dangerous
command that classifies below `ask` — is the highest-severity class of bug here;
those are triaged first.

You'll get an acknowledgement within a few days. This is a single-maintainer
project, so please allow reasonable time for a fix before public disclosure.

## Supported versions

Argus is pre-1.0 and ships from a single `main` line. Only the **latest**
released version receives security fixes. Pin a version if you need stability,
but update promptly when a security release lands.

## Threat model — read this before you trust it

**Argus is a classification and audit layer, not a sandbox.** It raises the bar
and creates a decision trail. It does **not** replace your OS sandbox, your
agent harness's own permissions, or good judgment.

### What Argus is designed to do

- Classify each inline shell command, file write, and MCP tool call on a
  `safe / low / medium / high` ladder and return `allow / ask / deny` **before**
  it runs.
- Parse the real shell AST (via `mvdan/sh`), so obfuscation and flag variants
  are resolved to true `argv` rather than pattern-matched.
- **Fail closed.** Any parse error, policy error, or unknown state touching a
  dangerous verb escalates to `ask`/`deny` — never a silent allow. A `high`
  match is a floor no policy edit or allowlist can lower.
- Protect its own configuration, hook wiring, binary, and database, and
  credential paths (`~/.ssh`, `~/.aws`, `~/.argus`, `~/.claude`) from writes,
  deletes, and content reads.

### What Argus does NOT protect you from

- **A compromised or malicious Argus binary itself.** This is the inherent cost
  of its privileged position: code that sits in front of every agent action can,
  if subverted, see and control every agent action. Nothing in Argus's design
  mitigates a supply-chain compromise of Argus — only build provenance and
  reproducibility do (see below). Trust the binary the way you'd trust any tool
  with this reach: verify it.
- **What it cannot see.** Argus inspects only the inline command it is given. An
  interactive `psql` session's later `DROP`, a script's contents behind
  `bash script.sh`, or side effects inside an opaque MCP tool are not inspected —
  they escalate to `ask`, not deeper analysis.
- **Anything outside the agent's gated calls.** Argus is not an EDR, a firewall,
  or a kernel sandbox. It governs the agent's Bash/file/MCP surface, nothing
  wider.

### Trust-reducing properties (by design)

- **Local-first.** No network calls, no telemetry, no SaaS. Verdicts are
  computed locally and logged to a local SQLite store.
- **Fail-closed core.** A bug in classification tends toward *over-asking*, not
  silent-allow — the hot path escalates on error.
- **Auditable.** The engine is pure Go, MIT-licensed, and open source. The
  `classify(payload, policy) → Decision` core is pure (no I/O, clock, or
  globals), so it is replayable and testable.

## Verifying what you installed

The npm package ships a prebuilt binary. To trust it, verify rather than assume:

- **npm provenance.** Releases are published with
  [npm provenance](https://docs.npmjs.com/generating-provenance-statements)
  (SLSA build attestation), linking each published package back to the exact
  GitHub Actions run and commit that built it. Check the "Provenance" section on
  the package's npm page.
- **Checksums.** Every GitHub Release includes `checksums.txt` (SHA-256 of each
  release archive).
- **Build from source.** The most paranoid path needs no prebuilt binary at all:

  ```bash
  go install github.com/lucasngucii/argus/cmd/argus@latest
  ```

  Pure-Go, `CGO_ENABLED=0`, no cgo — the whole thing cross-compiles from source.
