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
| `argus init` | Set up `~/.argus/` and wire the hook. |
| `argus doctor` | Verify the install; warns if the policy dropped baseline coverage. |
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
