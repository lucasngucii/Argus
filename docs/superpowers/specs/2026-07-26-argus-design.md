# Argus — Design Spec

> **Working name: “Argus”** (the hundred-eyed guardian — captures both *guarding* and *observing*). Name is provisional; see [Open Questions](#open-questions).
> Date: 2026-07-26 · Status: **Draft for review**

A **local-first governance and observability layer for AI coding agents.** Argus is the successor to the `agent-review` bash hook: it classifies every tool call an agent tries to make into a severity (`safe`/`low`/`medium`/`high`), decides `allow`/`ask`/`deny`, stores every decision in a local SQLite database, and ships a localhost web control-plane to observe decisions live, tune policy, and — uniquely — **replay policy changes against real history**.

---

## 0. Why this exists / positioning

Four OSS projects already occupy the Claude Code PreToolUse gating space (`kornysietsma/claude-code-permissions-hook`, `rulebricks/claude-code-guardrails`, `roboticforce/agent-guardrails`, `dwarvesf/claude-guardrails`). **All are stateless deny-lists** — they throw the decision away after blocking. None combine a **local decision store + web control-plane + a severity model**, and none treat **evasion resistance and fail-closed trust** as a first-class concern (dwarvesf openly documents that *“obfuscated bash can slip through”*).

Argus is **not a fifth deny-list.** Its wedge:

1. **Trust-first engine** — AST-based classification (not raw regex), fail-closed on the dangerous path, self-protecting. (§1, §2)
2. **A decision store** as the substrate for features stateless tools structurally cannot build — replay, explain, rule-testing, history mining. (§6)
3. **Local-first, offline, multi-harness** — no SaaS dependency (unlike rulebricks), and designed to gate not just Claude Code but any agent harness with a permission hook (Codex, Gemini). (§9 roadmap)

**Non-goals (v1):** cloud/SaaS backend; team/multi-user auth; replacing Claude Code’s native permissions or sandbox (Argus is an *additional* layer, honestly scoped — see §8).

---

## 1. Trust model (the core pillar)

A security gate is judged by its **false-negatives** — one risk that slips through is worse than ten annoying prompts. Five guarantees:

### 1.1 `high` is a hard floor — non-bypassable in every mode
Claude Code’s hook contract (verified against official docs) gives `permissionDecision: "deny"` precedence **even under `bypassPermissions` / `--dangerously-skip-permissions`**; hooks can *tighten* but not *loosen*. Argus leans on this: any command classified `high` returns `deny` and **cannot be reached by the auto-approve path in any permission mode.** The auto-approve path only ever touches `safe`/`low`. `medium`/`high` never pass silently.

A curated set of **always-high** patterns (disk wipe/format, forkbomb, pipe-to-shell, destructive SQL, self-tamper — §1.4) is enforced as an **engine-level invariant**: policy edits and allowlist entries can tune severities *below* this floor but **can never downgrade an always-high match.** Trust does not depend on the policy file being well-formed.

### 1.2 Evasion resistance — AST parsing, not regex
Regex on the raw command string is a catch-net, not a boundary. It loses to `X=rm; $X -rf /`, `rm$IFS-rf`, `$(echo cm0K | base64 -d) | sh`, `eval "…"`. Argus parses the command into a shell **AST** via `mvdan/sh`, giving real `argv` after quote/variable/pipeline resolution. On top:

- **Obfuscation is itself a signal.** Argus does not attempt perfect decoding. When it sees encoding/indirection wrapping a dangerous verb (`base64 -d | sh`, `eval`, `curl … | sh`, variable-indirected command names it cannot resolve), it **escalates severity** rather than passing through. Suspicion → escalate, never ignore.

### 1.3 Fail-CLOSED on the dangerous path (fixes the biggest hole in the current gate)
`gate.sh` today exits `0` on any error → silent pass-through → **fail-open**. Argus inverts this for risk:

| Failure | Command class | Action |
|---|---|---|
| Policy file unreadable/invalid | any | Fall back to **embedded always-high ruleset**; everything else → `ask`. Catastrophe protection never depends on the policy file. |
| AST parse fails | contains a dangerous token (raw scan) | escalate → `ask`/`deny` |
| AST parse fails | clearly benign | `allow` |
| DB write fails | any | **verdict unchanged** — logging is best-effort and never alters the security decision; error goes to stderr only |
| Binary missing/crash | any | Claude Code falls through to its **native** permission flow (still protected, just without Argus) |

Principle: **the security verdict is a pure function of (payload, policy); logging/DB are side-effects that can fail independently without weakening the verdict.**

### 1.4 Self-protection — the agent cannot disarm the gate
A compromised/confused agent could try to remove the hook or rewrite policy. Any **write, edit, move, delete, or chmod** targeting Argus’s own surface is **`high` (deny)**:
- `~/.claude/settings.json` / `settings.local.json` (hook wiring)
- the Argus hook entrypoint and binary
- `policy.json`
- the SQLite DB / its directory

Policy edits are only accepted through `argus` itself (CLI/web), which version-stamps them (§3.3) — not by an agent editing the file mid-session.

### 1.5 Verifiable = trustworthy
- **Deterministic & pure:** `classify(payload, policy) → {severity, ruleId, obfuscation, reasons}` has no randomness; same input + same `policy_version` ⇒ same verdict. This makes it **testable**.
- **Rule test harness:** `{command → expectedSeverity}` tables run in CI (§7). Includes an **evasion corpus** (obfuscated variants that MUST still be caught) as a permanent regression guard.
- **Immutable audit:** every decision is stored with the exact `rule_id` that fired and the `policy_version` in force — always answerable: *why did this pass / why was this blocked?*
- **Shadow mode:** `argus` can run log-only (classify + record, never block). Roll out by observing what gets classified `low` that shouldn’t, tune, *then* enforce. Trust built on real data.

---

## 2. Architecture — two layers, one binary

The gate is on Claude Code’s **synchronous hot path** (it blocks the tool call). A web server must **never** be in that path. Argus splits cleanly:

```
  ┌─ HOT PATH (must be fast, must not fail open) ──────────┐
  │  Claude Code ── PreToolUse (stdin JSON) ──►  argus gate │
  │                                               │ classify (pure) │
  │                            emit hookSpecificOutput ◄──┘ │
  │                                               │ write (best-effort) │
  └───────────────────────────────────────────────┼───────┘
                                                   ▼
                                            ~/.argus/argus.db  (SQLite, WAL)
                                                   ▲  reads
  ┌─ MANAGEMENT PLANE (may be slow / optional) ────┼───────┐
  │  argus serve  ──►  localhost web app           │        │
  │   • live tail (SSE)   • stats/heatmap                    │
  │   • policy editor     • REPLAY simulator  • EXPLAIN      │
  │        writes policy.json (+ version snapshot) ──────────┘
  └─────────────────────────────────────────────────────────┘
```

One Go binary, multiple subcommands:

| Command | Role |
|---|---|
| `argus gate` | **Hot-path hook.** Read stdin payload → classify against `policy.json` → write decision → emit `hookSpecificOutput`. Replaces `gate.sh`. |
| `argus serve` | Localhost web control-plane (live tail, stats, policy editor, replay, explain). |
| `argus init` | Wire the hook into `~/.claude/settings.json`, create default `policy.json`, init DB. |
| `argus doctor` | Verify wiring is intact & untampered; detect the gate’s own absence. |
| `argus stats` | Terminal digest (parity with the old `/agents-review`). |
| `argus test` | Run the rule test harness (`{command → expected severity}`). |
| `argus explain <cmd>` | Dry-run one command: show which rule fires and why. |
| `argus replay` | Re-score stored history against a candidate policy; print the diff. |

---

## 3. Components

### 3.1 Engine (`argus gate`)
Pure core + side-effecting shell.

**Input** (stdin JSON, per verified Claude Code contract): `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input` (`{command}` for Bash, `{file_path,…}` for Write/Edit), `tool_use_id`.

Contract nuances baked in:
- `permission_mode` ∈ `default | plan | acceptEdits | auto | dontAsk | bypassPermissions`. **UI “Manual” arrives as `"default"`** — match `default`, never `manual`.
- **Argus must assume it is not the only hook.** Multiple hooks combine most-restrictive-wins (`deny > ask > allow`); Argus’s `deny` will win but it must emit clean output and never depend on being sole.

**Pipeline:**
1. Parse payload. On failure → §1.3 fail-closed.
2. `classify(payload, policy)` (pure):
   a. Parse command to AST (`mvdan/sh`); detect obfuscation signals.
   b. Evaluate all enabled rules → collect matches.
   c. **Severity = max over matched rules** (a command matching a `low` and a `high` rule is `high`).
   d. Apply allowlist downgrades — **capped: never below an always-high match** (§1.1).
   e. Apply context escalation (e.g. `cwd` matches a prod path → bump).
3. Map severity → verdict: `safe`/`low`→`allow`; `medium`→`ask` (interactive) / `deny` (bypass); `high`→`deny`.
4. Write decision to SQLite (best-effort, never blocks verdict).
5. Emit `hookSpecificOutput` JSON (`allow`/`ask`/`deny` + reason). `safe` is not logged (noise reduction, as today).

**Output** (stdout): `{hookSpecificOutput:{hookEventName:"PreToolUse", permissionDecision, permissionDecisionReason}}`.

### 3.2 Policy (`policy.json`)
The heart — risk expressed as **data**, editable without touching code. JSON + published JSON Schema for validation and editor autocomplete.

```jsonc
{
  "version": 7,
  "meta": { "updatedAt": "2026-07-26T…Z", "updatedBy": "cli", "note": "…" },
  "defaults": { "onError": "escalate", "shadow": false },
  "rules": [
    {
      "id": "disk-format",
      "enabled": true,
      "alwaysHigh": true,           // engine invariant: cannot be downgraded
      "tool": ["Bash"],
      "match": { "cmd": ["dd","mkfs","fdisk"], "argMatches": "if=|erase" },
      "severity": "high",
      "reason": "disk/format/forkbomb"
    },
    {
      "id": "pipe-to-shell",
      "enabled": true, "alwaysHigh": true, "tool": ["Bash"],
      "match": { "pipesInto": ["sh","bash","zsh"] },
      "severity": "high", "reason": "pipe-to-shell"
    },
    {
      "id": "rm-recursive",
      "enabled": true, "tool": ["Bash"],
      "match": { "cmd": ["rm"], "flags": ["r"], "targetScorer": "rm_target" },
      "severity": "medium", "reason": "rm -r directory",
      "contextEscalation": [{ "when": { "cwdMatches": "prod" }, "to": "high" }]
    }
  ]
}
```

**Matcher fields** (all AST-derived, not raw-string):
- `cmd` — command name(s), resolved through simple variable indirection where possible.
- `flags`, `argMatches`, `argsContain`.
- `pipesInto` — pipeline sink is one of these commands.
- `redirectsTo` — output redirection path glob.
- `targetScorer` — named built-in procedural scorer for cases too rich for declarative fields (e.g. `rm_target`, which scores the destructiveness of `rm`’s targets — ported from the current `score_rm`).
- `obfuscation: true` — matches when obfuscation signals are present.
- `raw` — regex on the **canonicalized** string; documented escape hatch, discouraged.

Built-in scorers ship in the binary; policy references them by name. This keeps declarative rules simple while allowing the few procedural cases.

### 3.3 Storage (SQLite)
Pure-Go driver **`modernc.org/sqlite`** (no cgo) so the whole matrix cross-compiles from one CI machine (§5). Insert latency is sub-millisecond in-process; modernc’s modest overhead is irrelevant here.

```sql
CREATE TABLE decisions (
  id INTEGER PRIMARY KEY,
  ts TEXT, session TEXT, cwd TEXT,
  tool TEXT, command TEXT, file TEXT,
  severity TEXT, verdict TEXT, permission_mode TEXT,
  rule_id TEXT,            -- which rule fired (explain/audit)
  policy_version INTEGER,  -- policy in force (replay)
  harness TEXT,            -- 'claude-code' now; multi-harness later
  obfuscation INTEGER      -- bool
);
CREATE TABLE policy_versions (
  version INTEGER PRIMARY KEY,
  ts TEXT, author TEXT, note TEXT,
  policy_json TEXT,        -- full snapshot → enables replay & audit
  hash TEXT
);
```

**Concurrency (validated locally + against sqlite.org):** `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=3000` **on both writers and readers** (omitting it on the reader caused ~10% `SQLITE_BUSY` in local testing). Writers use **`BEGIN IMMEDIATE`** — a deferred read-txn that upgrades to a write fails *instantly* with `SQLITE_BUSY` regardless of `busy_timeout` (berthub.eu), so never take that path. WAL allows one writer + concurrent readers, which exactly fits many short-lived gate writers + one long-running `serve` reader. Local benchmark: 30 concurrent writers + reader with busy_timeout both sides = **0 failures**.

### 3.4 Web control-plane (`argus serve`)
Static SPA embedded into the Go binary via `//go:embed`; small JSON+SSE API. **Frontend: Svelte** (compiles to tiny dependency-free static assets — best fit for embedding; revisit if contributor familiarity argues for React). Localhost-only bind by default.

Screens:
- **Live tail** — SSE stream of decisions as they happen (`high` red, `medium` amber). Theme-aware.
- **Stats** — severity distribution, per-session, per-project heatmap, trend.
- **Policy editor** — edit rules against the JSON Schema; every save writes a new `policy_versions` snapshot.
- **Replay simulator** (§6) — the moat.
- **Explain** — paste a command, see the firing rule and severity.

---

## 4. Data flow

1. Agent issues a tool call → Claude Code runs `argus gate` (stdin payload).
2. Engine classifies (pure) → writes decision row (best-effort) → emits verdict.
3. `argus serve` tails new rows over SSE → UI updates live.
4. User spots a false-positive → edits policy in UI (or `allow`s from the row) → new `policy_versions` snapshot.
5. Before enforcing, user runs **Replay** against the last N days → sees exactly what the change flips → commits with confidence.

---

## 5. Distribution

Ship prebuilt Go binaries; make install one command.

- **Build matrix** (`CGO_ENABLED=0`, cross-compiled from one machine): `darwin/arm64`, `darwin/amd64`, `linux/amd64`, `linux/arm64`, `windows/amd64` (+ `windows/arm64`). Pure-Go SQLite keeps this trivial.
- **npm** (primary UX for the Claude Code audience): main package with a **JS bin shim**; per-platform binaries as **`optionalDependencies`** (`@argus/cli-darwin-arm64`, … each with `os`/`cpu` fields) so the package manager fetches only the matching one. **Postinstall download from GitHub Releases as fallback**, with checksum verification. Pitfalls to handle (from research): postinstall running as root → UID/GID errors; `--ignore-optional` disabling optionalDeps → the bin shim must degrade to the download path.
- **Also**: `go install`, Homebrew tap, raw release binaries.
- `argus init` wires the hook (`PreToolUse` matcher `Bash|Write|Edit` → `argus gate`) and is **idempotent & coexists** with the user’s other hooks.

---

## 6. The differentiators built on the decision store

Only possible because Argus keeps history + full policy snapshots:

- **★ Replay / policy simulator** — re-run stored commands through a candidate policy: *“this change flips 4 decisions ask→allow and newly catches 1 you previously allowed.”* No stateless tool can do this.
- **★ Explain / dry-run** — one command in, firing rule + severity out. Kills false-positive debugging.
- **★ Rule test harness** — `{command → expected severity}` as first-class, CI-enforced, with the evasion corpus.
- **Close-the-loop UI** — allowlist / downgrade directly from a decision row (capped by always-high floor).
- **(Roadmap) Rule suggestions from history** — mine clusters (*“you approved `git push` 6× in this repo → auto-allow rule?”*).

---

## 7. Testing strategy

- **Golden classification tables** — `{command → expectedSeverity}`; doubles as `argus test`.
- **Evasion corpus** — obfuscated variants (`X=rm;$X -rf /`, `base64|sh`, `$IFS`, `eval`) that MUST still be caught; permanent regression guard for §1.2.
- **Purity/determinism** — same input+policy ⇒ same verdict.
- **Fail-closed matrix** — inject policy/AST/DB failures, assert the §1.3 table.
- **Self-protection** — attempts to touch Argus’s own paths classify `high`.
- **Concurrency** — N writers + reader ⇒ 0 `SQLITE_BUSY` (harness already validated the approach locally).

---

## 8. Known limitations (documented honestly)

- **Inline visibility only.** The hook sees the command on the Bash line. `psql` opened interactively then `DROP` typed inside, or `bash opaque-script.sh`, are not inspectable → Argus **escalates opaque scripts/subshells to `ask` (`medium`)** rather than guessing safe. Escalation severity depends on visibility: when a dangerous verb is *visible* in the command string even if wrapped/encoded (e.g. `eval "rm -rf /"`, `sudo rm -rf /`), Argus classifies `high`; only when the danger is genuinely *opaque* (no dangerous token visible — a bare `psql`, an unknown `bash script.sh`) does it fall to `ask`.
- **Not a sandbox.** Argus is a *classification layer* complementing Claude Code’s permissions and OS sandbox, not a replacement. A determined adversary with full shell access has other avenues; Argus raises the bar and creates an audit trail, it is not an airtight jail.
- **Policy completeness is ongoing.** No off-the-shelf dangerous-command taxonomy exists (research-confirmed); the ruleset is authored in-house, seeded from the current `agent-review` rules and possibly the arXiv 2412.01655 taxonomy, and hardened via shadow mode + the evasion corpus + community packs over time.

---

## 9. Scope

**v1** (delivered across Plans 1–2)
- **Plan 1 — engine + gate CLI:** `mvdan/sh` AST classification, severity model, fail-closed, self-protection, always-high floor, allowlist/downgrade engine mechanism (capped by floor); `policy.json` + JSON Schema + version snapshots; SQLite store (WAL, busy_timeout, `_txlock=immediate`); CLI `gate`, `init`, `doctor`, `stats`, `test`, `explain`; migration from `agent-review` (§10).
- **Plan 2 — web control-plane:** `serve`, `replay` (CLI + simulator UI), live tail, stats, policy editor, explain view. `replay` and the close-the-loop allowlist **UI** ship here; the engine-level downgrade mechanism and `policy_versions` write path land in Plan 1 so the data model is correct from the start.
- **Plan 3 — distribution:** npm (optionalDeps + fallback) + GitHub Releases.

**Roadmap** (explicitly out of v1)
- Gate **MCP tool calls** (`mcp__*`) — new attack surface.
- **Multi-harness** (Codex, Gemini) governance.
- Rule suggestions from history; fleet / multi-machine aggregation; community policy packs; secret-content scanning on writes; `high`-block notifications (Slack/desktop).

---

## 10. Migration from `agent-review`

- Import existing `~/.claude/agent-review/decisions.jsonl` into `decisions`.
- Port the current `DESIGN.md` severity rules + `score_rm` into the seed `policy.json` / built-in scorers.
- `argus init` replaces the `gate.sh` hook wiring; keep a JSONL export for continuity with the old `/agents-review` habit.
- Run in **shadow mode** first to confirm parity before enforcing.

---

## Open Questions

1. **Name.** “Argus” is a working name; check npm/GitHub availability and collision with existing monitoring tools before publishing. Alternatives considered: `aegis`, `warden`, `aiguard`.
2. **Frontend framework** — Svelte (embedding size) vs React (contributor pool). Leaning Svelte; low-cost to revisit.
3. **arXiv 2412.01655** — evaluate whether its taxonomy is usable to seed policy, or author entirely in-house.
4. **License** — MIT assumed (matches the space); confirm.
