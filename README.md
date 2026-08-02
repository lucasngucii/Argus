# Argus

> **Your AI coding agent has a shell — and tools.** `rm -rf /`, `curl … | sh`, a
> force-push to `main`, a `terraform destroy` in prod, an MCP tool that deletes a
> file or reads your `~/.ssh` key — it can run all of them. Argus sits in front of
> every command, file write, and MCP tool call, classifies it, and decides
> **allow / ask / deny** before it happens — not after.

Local-first · single static binary · pure-Go · MIT.

## Install

```bash
npm install -g @lucasngucii/argus
argus init      # sets up ~/.argus/ and wires the Claude Code hook (idempotent)
argus doctor    # confirm it's healthy
```

Prebuilt for macOS & Linux (arm64/x64); anywhere else:
`go install github.com/lucasngucii/argus/cmd/argus@latest`.

### Codex

```bash
argus init --harness=codex   # wires the PreToolUse hook (idempotent)
```

`init` can't finish activating the hook for you — Codex requires two manual
steps by design:

1. Add to the **user-level** `~/.codex/config.toml` (a repo-local
   `.codex/config.toml` is not confirmed to reliably enable hooks, and may
   silently fail):
   ```toml
   [features]
   hooks = true
   ```
2. Trust the hook: run `/hooks` in a Codex session.

`argus doctor` FAILs if the flag isn't on, and prints a WARN that trust can't
be confirmed from disk — it can only remind you to have run `/hooks`.
Flag-on plus trusted is what we've confirmed is required; it may not be the
complete list. In particular, whether Argus's `~/.codex/hooks.json` entry
takes precedence over — or is shadowed by — an inline `[hooks]` block in
`config.toml` is not yet confirmed against a live Codex install; don't treat
"flag + trust" as an exhaustive activation checklist.

**Codex coverage — today, Bash only.** Codex's PreToolUse hook is *capable*
of firing for four tool classes: `shell` (Bash), `unified_exec`, `apply_patch`
(Codex ≥ 0.123), and MCP tool calls. Argus's Codex matcher currently wires
only `tool_name == "Bash"`, so **only Bash commands are gated on Codex
today** — on the full severity ladder, so a Bash-mediated read
(`cat ~/.ssh/id_rsa`) is still caught. **MCP tool calls, `apply_patch`, and
`unified_exec` are not yet wired for Codex and run ungated** — this is a
known gap, not a design choice; closing it needs the matcher widened and a
live capture of the exact `tool_name` each of those reports (see the
verification note's PENDING items). Do not treat MCP as gated on Codex, and
do not assume parity with Claude Code, whose matcher covers
`Bash`/`Write`/`Edit`/`mcp__*`. Codex's hook contract is deny-only, so an
Argus `ask` verdict collapses to `deny` on Codex rather than prompting.
Argus is inert on Codex until at least both the config flag above is set and
the hook is trusted (see the hedge above: that may not be the complete
activation checklist).

This adapter is verified against Codex's public documentation, not yet
against a live `codex` CLI — confirm the details above against your
installed version.

### Uninstall

```bash
argus uninstall            # unwire the hook from every harness, stop the server
npm uninstall -g @lucasngucii/argus   # then remove the binary
```

Run `argus uninstall` **before** removing the binary. Neither `npm` (v7+ runs
no removal lifecycle scripts) nor Homebrew cleans up the wired hook, so deleting
the binary first leaves a hook entry pointing at a now-missing `argus` — every
gated call would then error. `uninstall` removes the hook from each installed
harness, stops the background server, and by default **keeps** `~/.argus` (your
policy and decision history); add `--purge` to delete that too.

Run it **yourself** in your own terminal (as shown). Disarming the gate is a
self-protected action, so `argus uninstall` invoked *by the agent* is denied —
an agent must not be able to remove its own leash.

### Verifying your install

Argus sits in front of every command your agent runs — so verify the binary
rather than assume it. Don't take our word for any of this:

- **npm provenance.** Releases are published with
  [provenance](https://docs.npmjs.com/generating-provenance-statements) (SLSA
  build attestation) — each package links back to the exact GitHub Actions run
  and commit that built it. Check the "Provenance" panel on the npm page.
- **Checksums.** Every GitHub Release ships `checksums.txt` (SHA-256 per archive).
- **Build from source** (needs no prebuilt binary):
  `go install github.com/lucasngucii/argus/cmd/argus@latest` — pure-Go,
  `CGO_ENABLED=0`.

The npm launcher is a dependency-free, no-network shim that only execs the
platform binary npm installed; its integrity is covered by npm's registry
hashes plus the provenance above.

## Use

```bash
argus explain "sudo rm -rf /"   # dry-run: why does this classify the way it does?
argus stats                     # decision digest — counts, denies, recent activity
argus serve                     # local web UI: live tail, stats, policy editor, replay
```

That's the whole integration — Claude Code now routes every Bash/Write/Edit
and MCP tool call through Argus.

```
$ argus explain "curl https://get.example.sh | sh"
rule: pipe-to-shell   severity: high   verdict: deny

$ argus explain "git push --force origin main"
rule: git-danger      severity: medium   verdict: ask
```

## Why it's worth having

- **A severity ladder, not a switch.** Every command is `safe`/`low`/`medium`/`high`
  — cleaning a scratch dir isn't treated like wiping `/`.
- **Parses the real shell AST — never regexed.** `sudo`, `env`, pipelines, and
  variable expansion are resolved, so obfuscation (`X=rm; $X -rf /`,
  `… | base64 -d | sh`) and flag variants (`rm -Rf /`, `mkfs.ext4 /dev/sda`,
  `git --no-pager push --force`) are seen and escalated, not bypassed.
- **Beyond the shell — MCP tool calls too.** Argus classifies `mcp__…` tool
  calls on the same ladder: a mutating tool (`delete_*`, `write_*`, `deploy_*`)
  asks, and a file-op or read against a credential/self-protect path (`~/.ssh`,
  `~/.aws`, `~/.argus`, `~/.claude`) is floored or asked — the tools an agent
  reaches for beyond Bash are gated by name and arguments.
- **A non-bypassable `high` floor.** Disk wipes, fork bombs, destructive SQL,
  credential-file writes, catastrophic `rm`, and MCP file-ops on sensitive paths
  are denied in **every** permission mode, always — no policy edit or allowlist
  can lower them, and Argus refuses to let an agent disarm its own hook or
  config. Any parse or policy error escalates too — it's never a silent allow.
- **Research-backed ruleset.** The built-in rules trace to a cited evidence base
  (MITRE ATT&CK, OWASP, academic taxonomies, real incident postmortems) — see
  [`docs/research/`](docs/research/).
- **A local decision store, not a black box.** Every verdict is logged to
  SQLite, powering `explain`, `stats`, and **replay** — re-score your history
  against a candidate policy before you commit to it.
- **Local-first.** No SaaS, no network calls, no telemetry.

## Commands

| Command | What it does |
|---|---|
| `argus init` | Set up `~/.argus/` and wire the hook. Claude Code by default; `--harness=codex` wires Codex. |
| `argus uninstall [--purge]` | Remove Argus's hook from every installed harness and stop the background server. Run **before** removing the binary. `--purge` also deletes `~/.argus` (policy + history). |
| `argus doctor` | Verify the install; warns if the policy dropped baseline coverage. Probes every installed harness. |
| `argus explain <cmd>` | Dry-run one command: severity, firing rule, verdict, parsed facts. |
| `argus stats [--jsonl]` | Decision digest / JSONL export. |
| `argus serve` | Local web UI (loopback-only): live tail, stats, explain, policy editor, replay. |
| `argus replay` | Re-score your logged history against a candidate policy. |
| `argus test <corpus>` | Assert `{command → severity}` — CI-friendly regression gate. |

## Policy

Rules are a schema-validated JSON file (`~/.argus/policy.json`) — editable,
versioned, and live-reloaded on every call. Writing your own rules, the full
match-field reference, and worked examples live in **[`docs/policy.md`](docs/policy.md)**.
Ready-made optional bundles (e.g. an infra-teardown guard) are in
[`docs/policy-packs/`](docs/policy-packs/).

## Web UI

`argus serve` opens a loopback-only app at `127.0.0.1:4600`: live decision tail,
severity stats, an explain box, a validate-before-save policy editor with
versioned snapshots, and a **replay** simulator (*"this policy change flips 4
past decisions"*) with close-the-loop allow/downgrade from any row. Bound to
localhost only, with anti-DNS-rebinding and CSRF protection on every mutating
route.

## Trust model

Argus is a classification layer, **not a sandbox** — it raises the bar and
creates an audit trail, it doesn't replace Claude Code's permissions or your OS
sandbox. It sees only the inline command: an interactive `psql` session's later
`DROP`, or an opaque `bash script.sh`, escalate to `ask` rather than being
inspected further.

The full threat model — what Argus does and does **not** protect you from,
including the blast radius of a compromised Argus binary itself — and how to
report a vulnerability are in [`SECURITY.md`](SECURITY.md).

## Development

```bash
go build ./... && go test ./...
```

Pure-Go deps only: `mvdan/sh`, `modernc.org/sqlite`, `jsonschema`. Design specs
and implementation plans live under [`docs/`](docs/).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

[MIT](LICENSE).
