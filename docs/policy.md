# Argus Policy Guide

Policy is **data, not code** — a schema-validated JSON file at `~/.argus/policy.json`.
The gate reloads it on every call, so an edit takes effect on the very next tool
call. This guide covers writing your own rules; for the built-in ruleset's
evidence base, see [`docs/research/`](research/); for ready-made optional rule
bundles, see [`docs/policy-packs/`](policy-packs/).

## Anatomy of a rule

```json
{
  "id": "terraform-destroy",
  "enabled": true,
  "tool": ["Bash"],
  "severity": "medium",
  "reason": "irreversible infrastructure teardown",
  "match": { "cmd": ["terraform"], "argsContain": ["destroy"] },
  "contextEscalation": [{ "when": { "cwdMatches": "prod" }, "to": "high" }]
}
```

| Field | Meaning |
|---|---|
| `id` | Unique name for the rule. |
| `enabled` | Set `false` to keep a rule around but inactive. |
| `tool` | Which tool calls it applies to: `Bash`, `Write`, `Edit`. |
| `severity` | `safe` \| `low` \| `medium` \| `high` — what this rule assigns when it matches. |
| `alwaysHigh` | `true` pins the match to `high` and makes it **non-downgradable** — no `allow` rule or policy edit can lower it. Reserve this for genuine catastrophes. |
| `allow` | `true` turns the rule into a whitelist entry (downgrades a match to `safe`). Can never override an `alwaysHigh` floor rule. |
| `reason` | Shown in `explain` output and the web UI. |
| `contextEscalation` | Raise severity further when a condition holds — currently `cwdMatches` (the working directory contains that path segment). |

### `match` fields (all present fields must hold — logical AND)

| Field | Matches |
|---|---|
| `cmd` | Command name(s), resolved through wrappers (`sudo rm` → `rm`). |
| `flags` | Single-letter flags that must **all** be present, e.g. `["r","f"]`. |
| `argsContain` | **Any** of these appears as an exact resolved argument. |
| `argMatches` | Regex over the joined, resolved arguments. |
| `pipesInto` | The command's output is piped into one of these (e.g. `["sh","bash"]`). |
| `redirectsTo` | An exact redirect target. |
| `raw` | Regex over the entire raw command string — the escape hatch for shapes the other fields can't express (redirects, multi-command pipelines). |
| `mcpServer` | MCP server segment(s), exact ANY-of (e.g. `["github"]`). |
| `mcpTool` | Regex over the MCP tool segment (e.g. `(?i)(^|_)delete(_|$)`). |

Commands are parsed with a real shell AST, not matched as raw text: `sudo`,
`env`, `timeout`, etc. are unwrapped so the rule sees the actual command being
run, and pipelines are resolved into named sinks.

## How severities combine

- Every enabled rule that matches contributes its severity; the **highest wins**.
- An `alwaysHigh` match is a **floor** — computed independently of the rest of
  the policy and immune to any `allow` rule. This is enforced by the engine, not
  by policy content, so it survives an empty or heavily edited `policy.json`.
- `contextEscalation` only ever raises a rule's own severity, never lowers it.

## More examples

**A hard stop, no override possible** (reserve for things that are always a mistake):

```json
{ "id": "wipe-any-disk", "enabled": true, "alwaysHigh": true,
  "tool": ["Bash"], "severity": "high", "reason": "disk-level destructive op",
  "match": { "cmd": ["dd"], "argMatches": "of=/dev/" } }
```

**Escalate by working directory** (routine in dev, blocked in prod):

```json
{ "id": "kubectl-delete", "enabled": true, "tool": ["Bash"], "severity": "medium",
  "reason": "removes live workloads",
  "match": { "cmd": ["kubectl"], "argsContain": ["delete"] },
  "contextEscalation": [{ "when": { "cwdMatches": "prod" }, "to": "high" }] }
```

**Whitelist one command you trust** (never overrides a floor hit):

```json
{ "id": "allow-my-deploy", "enabled": true, "allow": true, "tool": ["Bash"],
  "match": { "raw": "^make deploy-staging$" }, "reason": "trusted deploy script" }
```

## Editing your policy

- **By hand:** edit `~/.argus/policy.json` directly; `argus doctor` checks it
  loads and validates, and warns if you've dropped a baseline rule.
- **Web editor:** `argus serve` → **Policy** tab — validate-before-save (a bad
  edit is rejected, the file is left untouched), every save is versioned with a
  snapshot you can browse, and the **Replay** tab shows what a candidate policy
  would have changed across your logged history before you commit to it.
- **Dry-run a single command:** `argus explain "<command>"` shows the firing
  rule, severity, verdict, and the parsed AST facts — the fastest way to check
  a new rule does what you intended.

## Policy packs

[`docs/policy-packs/`](policy-packs/) ships optional rule bundles you can merge
in for setups the default policy doesn't cover out of the box (e.g. an
infra-teardown guard for `terraform`/`kubectl`/cloud CLIs). Each pack states
plainly whether its severities are backed by a cited incident or are principled
inference — see the pack's own README for specifics.

## Gating MCP tools

MCP tools (`mcp__server__tool`) are gated once the hook matcher includes
`mcp__.*` (a fresh `argus init` wires it; `argus doctor` WARNs and a re-init
self-heals an old install).

**Default allow.** Rules judge the tool NAME and the args JSON (there is no
shell AST for MCP — no semantic parsing).

Built-in coverage:
- `mcp-mutating-tool` (medium/ask — a mutating verb in the tool name)
- `mcp-destructive-sql-args` (medium — destructive SQL in args)
- `mcp-fileop-sensitive-path` (high — a file-op-named tool whose args target a
  credential/system/self-protect path; **non-downgradable** floor rule)

Target a specific server with `mcpServer`/`mcpTool`, e.g.:

```json
{ "id": "github-mcp-write", "enabled": true, "alwaysHigh": true, "tool": ["mcp"],
  "severity": "high",
  "match": { "mcpServer": ["github"], "mcpTool": "(?i)(^|_)(create|delete|merge|push)" },
  "reason": "github write op" }
```

**Honest limit:** a mutating tool with an innocuous name and benign-looking args
is `allow` unless you add a per-server rule — the floor is deliberately AND-gated
(tool-name + path) to avoid non-recoverable false positives on freeform args, so
a docs-search merely mentioning a credential path is not blocked.

## Editing your policy

- **By hand:** edit `~/.argus/policy.json` directly; `argus doctor` checks it
  loads and validates, and warns if you've dropped a baseline rule.
- **Web editor:** `argus serve` → **Policy** tab — validate-before-save (a bad
  edit is rejected, the file is left untouched), every save is versioned with a
  snapshot you can browse, and the **Replay** tab shows what a candidate policy
  would have changed across your logged history before you commit to it.
- **Dry-run a single command:** `argus explain "<command>"` shows the firing
  rule, severity, verdict, and the parsed AST facts — the fastest way to check
  a new rule does what you intended.
