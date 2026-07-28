# Argus

**A local-first governance and observability gate for AI coding agents.**

Argus sits in front of every shell command and file write an AI coding agent
(Claude Code today) tries to run, classifies it by severity, and decides
**allow / ask / deny** — then records every decision to a local database so you
can see, explain, and tune what your agents are doing.

> Status: **v0.1 — alpha.** The classification engine, the Claude Code gate, and
> the CLI are implemented and verified end-to-end. The web control-plane
> (`serve` / replay UI) is on the [roadmap](#roadmap).

License: MIT · Go 1.26 · pure-Go (`CGO_ENABLED=0`), single static binary.

---

## Why

AI coding agents run real commands. The existing guardrails for them are
**stateless deny-lists**: they pattern-match a command, block or allow it, and
throw the decision away. That leaves three gaps:

- **They're catch-nets, not boundaries.** Regex over a raw command string loses
  to ordinary obfuscation — `X=rm; $X -rf /`, `rm$IFS-rf$IFS/`,
  `$(echo … | base64 -d) | sh`.
- **They fail open.** On any hiccup they tend to let the command through.
- **They have no memory.** You can't ask "what did the agent *try* to do?",
  "why was this blocked?", or "if I change this rule, what breaks?"

Argus is built the other way around.

## What makes it different

- **A severity model, not a binary.** Every command is `safe` / `low` /
  `medium` / `high` — so cleaning a scratch dir isn't treated like wiping `/`.
- **AST-based classification, not regex.** Commands are parsed with a real shell
  parser ([`mvdan/sh`](https://github.com/mvdan/sh)) so Argus sees the *true*
  `argv` after quotes, variables, wrappers (`sudo`, `env`, `timeout`), and
  pipelines are resolved. Obfuscation is treated as a signal and **escalated**.
- **Fail-closed.** On a parse/policy error, a command containing a dangerous
  verb escalates — it is never silently allowed. If Argus can't even emit its
  decision, it blocks (exit 2).
- **A non-bypassable `high` floor.** Catastrophic commands (disk wipe, fork
  bomb, pipe-to-shell, destructive SQL, recursive-rm of `/`/`~`/system dirs) are
  denied in **every** permission mode — including `--dangerously-skip-permissions`
  — and cannot be downgraded by policy or an allow-list entry.
- **Self-protection.** An agent can't disarm the gate: writes/deletes targeting
  Argus's own config, the hook wiring, or credential/system paths are `high`.
- **A local decision store.** Every decision goes to a local SQLite DB. This is
  the substrate for features stateless tools structurally can't offer —
  **replay** (re-score history against a candidate policy), **explain**, and
  history mining.
- **Local-first.** No SaaS, no network calls, no telemetry. One binary + one
  SQLite file under `~/.argus/`.

## How it works

Argus installs as a **PreToolUse hook** in Claude Code. Before a tool call runs,
Claude Code pipes it to `argus gate`, which classifies it and returns a verdict.
The gate is a short-lived, synchronous, fail-closed process (~0.1 ms/call);
a separate management layer (CLI today, web UI on the roadmap) reads the DB.

```
  hot path (fast, fail-closed)                 management (read-mostly)
  ────────────────────────────                 ────────────────────────
  Claude Code                                  argus stats / explain / test
     │ PreToolUse (JSON on stdin)                       │ reads
     ▼                                                  ▼
  argus gate ── classify(payload, policy) ──►  ~/.argus/argus.db  (SQLite, WAL)
     │  (pure: no I/O, no clock, no panic)              ▲
     ▼                                                  │ reads
  allow / ask / deny  ──►  Claude Code         ~/.argus/policy.json  (rules as data)
```

`classify()` is a **pure function** of `(payload, policy)` — deterministic,
testable, and replayable. Parsing, the DB write, and emitting the decision are
side-effects wrapped around it; a logging/DB failure can never change a verdict.

## Install

```bash
# prebuilt binary via npm (no Go toolchain needed)
npm install -g @agrus/argus

# or download a release archive:
#   https://github.com/lucasngucii/Argus/releases
# or build from source (Go 1.26+):
go install github.com/lucasngucii/argus/cmd/argus@latest
```

Supported prebuilt platforms: macOS and Linux (arm64 + x64). On any other
platform, `npm` prints a pointer to the release archives / `go install`.

## Quick start

```bash
argus init      # creates ~/.argus/, seeds policy.json, wires the Claude Code
                # PreToolUse hook into ~/.claude/settings.json (idempotent,
                # never clobbers your existing hooks), imports any legacy log
argus doctor    # verify the install is wired and healthy
```

That's it — Claude Code now routes tool calls through Argus. To inspect and tune:

```bash
argus explain "sudo rm -rf /"     # dry-run: severity, firing rule, verdict, AST facts
argus stats                       # decision digest (counts, denies, recent high/medium)
argus stats --jsonl               # stream all decisions as JSONL
argus test testdata/evasion.jsonl # run a rule corpus (command → expected severity)
```

### Commands

| Command | What it does |
|---|---|
| `argus gate` | The hook. Reads a PreToolUse payload on stdin, emits the verdict. |
| `argus init` | Set up `~/.argus/`, seed policy, wire the hook (idempotent). |
| `argus doctor` | Verify the install; warn if the policy dropped baseline rules. |
| `argus explain <cmd>` | Dry-run one command and show *why* it classifies as it does. |
| `argus stats [--jsonl]` | Decision aggregates / JSONL export. |
| `argus test <corpus…>` | Assert a `{command → expected severity}` corpus (CI-friendly). |
| `argus version` | Print the version. |
| `argus serve` / `argus replay` | **Roadmap** — web control-plane + policy replay. |

## Policy

Policy is **data**, not code — a JSON file (`~/.argus/policy.json`) validated
against a schema, so you can edit, version, and share it. Rules match against the
parsed command; a few procedural cases (like scoring an `rm` target) use named
built-in scorers.

```jsonc
{
  "version": 1,
  "rules": [
    { "id": "rm-recursive", "enabled": true, "tool": ["Bash"],
      "match": { "cmd": ["rm"], "flags": ["r"], "targetScorer": "rm_target" },
      "severity": "medium", "reason": "rm -r directory",
      "contextEscalation": [{ "when": { "cwdMatches": "prod" }, "to": "high" }] },

    { "id": "allow-my-deploy", "enabled": true, "allow": true, "tool": ["Bash"],
      "match": { "cmd": ["make"], "argMatches": "deploy" },
      "reason": "trusted deploy" }
  ]
}
```

- A rule's `severity` maps to a verdict: `safe`/`low` → allow, `medium` → ask
  (deny in non-interactive modes), `high` → deny.
- `allow: true` rules **down**-grade a match — but they can never downgrade a
  `high`/floor command.
- The always-high **floor** (catastrophes + self-protection) is enforced by the
  engine and survives even an empty or hand-edited policy.

## Trust model, honestly

Argus is a **classification layer** that complements Claude Code's own
permissions and your OS sandbox — it is **not** a sandbox and not an airtight
jail. It raises the bar and creates an audit trail. Known limits: it sees only
the inline command (a `psql` session's later `DROP`, or an opaque
`bash script.sh`, aren't inspectable — those escalate to `ask`), and command
classification, while AST-based, is not a formal proof of safety. Report gaps —
the evasion corpus exists exactly to close them.

## Roadmap

Argus is built in stages (design + plans live in [`docs/`](docs/)):

- **Plan 1 — engine + gate + CLI** ✅ *(this release)*
- **Plan 2 — web control-plane:** `argus serve` (localhost) with live decision
  tail, stats, an explain view, a policy editor, and the **replay simulator**
  (re-score your history against a candidate policy: *"this change flips 4
  decisions and newly catches 1"*).
- **Plan 3 — distribution:** `npm` install with prebuilt per-platform binaries.
- **Plan 4 — reach:** gate **MCP tool calls**, and multi-harness support beyond
  Claude Code (Codex, Gemini).

## Development

```bash
CGO_ENABLED=0 go build ./...
go test ./...              # unit + integration tests
go test -bench=. ./...     # hot-path budget
```

Dependencies are deliberately few and all pure-Go: `mvdan.cc/sh/v3`,
`modernc.org/sqlite`, `santhosh-tekuri/jsonschema/v6`. Design specs and
task-by-task implementation plans live under
[`docs/superpowers/`](docs/superpowers/).

## License

[MIT](LICENSE).
