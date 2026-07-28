# Argus MCP Tool-Call Gating — Design (Spec)

> Phase 4, sub-project A. Closes the "MCP tool calls are a new attack surface"
> roadmap item (design doc §9). Multi-harness (Codex/Gemini) is a separate
> sub-project, out of scope here. Grounded in verified Claude Code hook behavior
> (see "Grounding" below) — not assumptions.
>
> **The authoritative, review-corrected design is the plan**
> [`docs/superpowers/plans/2026-07-28-mcp-gating.md`](../plans/2026-07-28-mcp-gating.md)
> **(rev 2).** Three adversarial reviews corrected this spec's first draft — see
> the Changelog at the end. Where this document and the rev-2 plan differ, the
> plan governs.

## The gap

Today Argus gates `Bash` (via `tool_input.command`) and `Write`/`Edit` (via
`tool_input.file_path`). `hook.Payload.Subject()` returns the command for Bash
and the file path otherwise. An **MCP tool call** (`mcp__<server>__<tool>`) has a
`tool_input` that is arbitrary server-defined JSON with **neither** `command` nor
`file_path` — so `Subject()` returns `""`, no rule matches, and the call
classifies **safe → allow**. Every MCP tool — a filesystem server that deletes
files, a database server that runs SQL, a shell-exec server — passes the gate
completely ungated. That is the attack surface to close.

## Goal

Gate MCP tool calls without over-blocking the many read-only MCP tools. Default
to allow, but (1) ask a human before an obviously-mutating MCP tool, and (2)
hard-deny an MCP tool whose arguments target Argus's own config, the hook wiring,
or credential/system paths. No change to the severity model, verdict map, or the
Bash/Write/Edit path.

## Grounding (verified Claude Code behavior)

- `tool_name` for an MCP tool is `mcp__<server>__<tool>` (double-underscore
  separators). Plugin-scoped tools are `mcp__plugin_<plugin>_<server>__<tool>`.
- `tool_input` is the **flat, arbitrary, server-defined arguments object** — no
  guaranteed fields. Example: `{"tool_name":"mcp__memory__create_entities",
  "tool_input":{"entity_type":"issue","name":"…","description":"…"}}`.
- Deny/ask/allow use the **same** `hookSpecificOutput`
  (`permissionDecision`, `permissionDecisionReason`) and exit-code contract as
  built-in tools — no MCP-specific difference.
- The PreToolUse `matcher` is regex; `mcp__.*` catches all MCP tools.
- `permission_mode` is sent for MCP calls, but whether `acceptEdits`/
  `bypassPermissions` alter MCP gating is **not documented** → design
  conservatively (treat MCP under the same `verdict.Map` mode logic; do not
  assume a mode silently exempts MCP).
- **No semantic parsing** is possible: unlike Bash (a real shell AST), an MCP
  tool's intent can only be judged from its server/tool name and a regex over its
  raw args JSON. This is the core constraint the design works within.

## Decisions (settled)

- **Default posture: allow.** An MCP tool with no matching rule stays `safe`
  (mirrors Bash — safe by default, rules catch the dangerous shapes). Rejected
  "ask on every MCP tool" (too noisy — most MCP tools are benign reads) and
  "keep allowing everything" (that's the gap).
- **Two baseline rules ship (see Rules).** One `medium` heuristic on mutating
  tool-name verbs, one set of `high` floor extensions for self-protection /
  credential access via MCP args.
- **Reuse subject-based Raw matching.** For an MCP call, `Subject()` returns the
  raw `tool_input` JSON, so existing subject-Raw floor rules (credential/system
  writes, self-protection) extend to MCP arguments **for free** once their `Tool`
  list includes MCP.
- **A `"mcp"` Tool token** means "any `mcp__*` tool", so a rule can target all
  MCP tools without enumerating server/tool names.

## Architecture / file changes

```
internal/hook/payload.go     # capture raw tool_input JSON; Subject() returns it for MCP; IsMCP()/MCPServer()/MCPTool() helpers
internal/classify/match.go   # "mcp" Tool token; new Match fields mcpServer/mcpTool; MCP-aware toolIn + fact gating
internal/policy/policy.go    # Match gains McpServer []string, McpTool string
internal/policy/schema.json  # allow mcpServer/mcpTool in the match schema
internal/policy/defaults.go  # +1 medium rule (mcp-mutating-tool); extend self-protect + credential floor rules' Tool lists to include "mcp"
internal/cli/init_hook.go    # matcher becomes "Bash|Write|Edit|mcp__.*"; doctor recognizes it
internal/cli/doctor.go       # (if it checks matcher) accept the mcp addition
internal/classify/*_test.go  # golden/evasion for MCP tool names + args
internal/cli/testdata/*.jsonl# corpus entries (needs an mcp tool_name; may require harness/corpus format to carry tool_input JSON — see Open Questions)
```

## Payload handling

`hook.Payload` keeps `ToolInput ToolInput{Command, FilePath}` (Bash/Write still
decode those). Add capture of the **raw** `tool_input` bytes via a custom
`Payload.UnmarshalJSON` (or a `ToolInputRaw json.RawMessage` populated during
decode). New helpers:

- `func (p Payload) IsMCP() bool` — `strings.HasPrefix(p.ToolName, "mcp__")`.
- `func (p Payload) MCPServer() string` / `MCPTool() string` — parse the
  `mcp__server__tool` form (server = the segment after `mcp__`; tool = the rest;
  treat plugin form `mcp__plugin_…` opaquely for v1 — the server segment simply
  carries the `plugin_<plugin>_<server>` string, still matchable).
- `Subject()` — unchanged for Bash/Write/Edit; for MCP returns the raw
  `tool_input` JSON string (so subject-Raw rules see the args).

## Classifier changes

- `toolIn(ruleTools, toolName)` accepts a `"mcp"` token that matches any
  `mcp__*` tool name (in addition to exact matches). So `Tool: ["mcp"]` = all MCP
  tools; `Tool: ["Bash","Write","Edit","mcp"]` = those built-ins plus all MCP.
- New `Match` fields:
  - `McpServer []string` — ANY-of exact match on the parsed server segment.
  - `McpTool string` — regex over the parsed tool segment (e.g.
    `(?i)(delete|drop|remove|write|exec)`).
- For an MCP call, the shell-AST facts (`f.Commands`, pipe sinks) are empty and
  meaningless; `usesShellFacts` rules must not fire on MCP (they already can't,
  since there are no resolved commands). Only `mcpServer`/`mcpTool`/`raw`
  (over the args JSON) apply.
- Fail-closed: an MCP payload whose `tool_input` fails to parse but whose
  `tool_name` matches the mutating-verb pattern escalates to at least `medium`
  (same spirit as opaque-exec).

## Rules (baseline, shipped in defaults.go)

1. **`mcp-mutating-tool`** — `Default().Rules`, `medium` (ask), downgradable:
   ```
   Tool: ["mcp"], McpTool: "(?i)\b(delete|drop|remove|destroy|truncate|write|create|update|put|patch|exec|run|kill)\b"
   Reason: "MCP tool with a mutating action — review before running"
   ```
   Ask a human before an MCP tool whose name announces a mutation. Read-style
   tools (`list`, `get`, `search`, `read`, `fetch`) don't match → stay allow.

2. **Extend the self-protection + credential floor to MCP** — add `"mcp"` to the
   `Tool` list of `self-protect-claude-settings`, `self-protect-argus`, and
   `credential-system-write` in `Floor()`. Their `Raw` patterns already match
   `.claude`/`.argus`/`.ssh/…`/`.aws/credentials`/`/etc` against the subject; with
   `Subject()` returning the MCP args JSON, an MCP tool whose arguments reference
   those paths becomes `high` (non-downgradable). Closes "a filesystem MCP deletes
   Argus's hook wiring".

No new floor rule is *invented* for MCP — the mutating-verb rule is `medium`
(a name heuristic, so it must stay downgradable), and the only `high` coverage is
the existing self-protect/credential floor extended to a new tool class.

## Init / matcher wiring

`init_hook.go`'s wired matcher changes from `"Bash|Write|Edit"` to
`"Bash|Write|Edit|mcp__.*"`. This stays idempotent (the existing
`hasGateHook` check keys off the `argus gate` command, not the matcher, so a
re-run won't duplicate). Existing installs keep their old matcher until they
re-run `init` or edit settings — documented, not auto-migrated (Argus never
rewrites a user's settings beyond the one append). `doctor` should note when the
wired matcher lacks `mcp__` (a non-fatal WARN, like the seed-rule WARN).

## Testing

Per CLAUDE.md (golden + evasion, deterministic):

- Unit: an MCP payload for a mutating tool (`mcp__fs__delete_file`) → medium; a
  read tool (`mcp__fs__read_file`) → safe; an MCP tool whose args reference
  `~/.ssh/id_rsa` or `.argus/` → high (floor, non-downgradable, prove an `allow`
  rule can't lower it).
- `IsMCP`/`MCPServer`/`MCPTool` parsing unit tests, including the plugin form.
- Init: matcher now contains `mcp__.*`; idempotent re-run doesn't duplicate.
- Schema: `Validate` accepts a rule using `mcpServer`/`mcpTool`.

## Non-goals

- Semantic understanding of any specific MCP server's schema (impossible
  generically — flagged in Grounding).
- Per-server rule packs (e.g. a "github MCP" pack) — a later policy-pack, not core.
- Multi-harness (Codex/Gemini) — Phase 4 sub-project B, separate.
- Retroactively gating MCP calls for existing installs without a re-`init`.

## Open questions (resolve during planning)

1. **Corpus format for MCP.** `internal/cli/testdata/*.jsonl` lines are
   `{"tool":"Bash","command":"…","expect":"…"}` — they carry a command string,
   not an arbitrary `tool_input` object. Gating MCP in the corpus harness needs
   the line format to optionally carry a `tool_name` + raw `tool_input`. Decide:
   extend the harness line schema, or cover MCP only in Go unit tests (the corpus
   stays Bash/file-focused). Leaning: unit tests for MCP, keep the corpus as-is,
   to avoid reshaping the harness for a handful of cases.
2. **Mutating-verb list breadth.** Start narrow (the list above) and widen only
   with a test proving a real miss. `create`/`update`/`put`/`patch` may be noisy
   for some servers — decide whether they're in v1 or deferred.
3. **`bypassPermissions` + MCP.** Since the mode's effect on MCP is undocumented,
   `verdict.Map` treats MCP identically to Bash (medium→deny in non-interactive
   modes). Confirm that's the intended conservative default, or special-case.
4. **Plugin-form server parsing.** v1 treats `mcp__plugin_<plugin>_<server>__…`
   with the whole `plugin_<plugin>_<server>` as the "server" string. Good enough
   for name matching; a finer split can come later if a rule needs it.

## Changelog (draft → rev 2, from three adversarial reviews)

**BLOCKING fixed:**
- The mutating-verb regex used `\b`, which does not split snake_case (`delete_file`
  → no match), so the rule would ship inert and its own test would fail. Fixed to
  `(^|_)verb(_|$)` [plan T5].
- The `ToolInput.UnmarshalJSON` draft swallowed decode errors, fail-**open**ing a
  mistyped Bash `command`. Moved to `Payload.UnmarshalJSON`; only MCP tolerates a
  non-string command/file_path, Bash/Write stay fail-closed [plan T1].
- The "extend the credential/self-protect floor to MCP args for free" idea was
  wrong twice over: (a) a bare path substring in **freeform** args (a docs-search
  query mentioning `~/.ssh`) would be a non-recoverable floor FP; (b) adding
  `McpTool` to a shared rule disables it for Bash. Replaced with ONE dedicated MCP
  floor rule `mcp-fileop-sensitive-path` that AND-gates a **file-op tool name**
  against the sensitive-path match [plan T4].

**Should-fixed:**
- Destructive-SQL-in-args demoted from floor to `medium` (freeform keyword
  heuristic; consistent with the Bash `db-write` rule) [plan T5].
- Verb list widened with the high-impact, name-guessable
  `send|publish|revoke|deploy|merge|apply|grant|transfer` (each was silently
  `allow`) [plan T5].
- **Store/replay data hole:** MCP decisions were logged with empty command/file →
  blank in the Live tail and re-scored as `safe` by replay forever. The MCP
  subject is now persisted in the `Command` column and reconstructed into
  `ToolInput.Raw` on replay [plan T6].
- **Doctor remedy no-op:** the WARN said "re-run argus init" but `wireHook`
  short-circuited without updating a stale matcher. `wireHook` now self-heals the
  matcher; a `gateMatcherOf` helper backs the WARN [plan T7].
- **Explain gap:** MCP rules were undryrunnable. `explain` (web + CLI) now accepts
  an MCP tool name + args JSON [plan T8]. The corpus harness's Bash/file-only
  boundary is made explicit rather than silently mis-routing an `mcp__*` line.

**Now stated honestly (was overclaimed):** extending protection to MCP is NOT
"free" — the floor is deliberately AND-gated to avoid non-recoverable FPs on
freeform args, and a mutating tool with an innocuous name is `allow` unless a
per-server rule is added (an "ask-once-per-new-(server,tool)" resolved in the
dirty shell is noted as a future option).
