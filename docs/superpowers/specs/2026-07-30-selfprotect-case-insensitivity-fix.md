# Self-protect/credential rules: close the case-insensitive-filesystem bypass

**Date:** 2026-07-30
**Status:** approved

## Problem

Found during round-3 adversarial re-verification of the `.claude` self-protect narrowing fix
(spec `2026-07-30-self-protect-claude-scope-fix.md`). All `Match.Raw` regexes in the
self-protect/credential ruleset are case-sensitive, but the default filesystem on macOS (APFS)
and on Windows is **case-insensitive** — `~/.claude`, `~/.Claude`, `~/.CLAUDE` all name the exact
same directory on disk. A single case variation bypasses the floor entirely:

```
cat ~/.claude/Settings.json     → currently NOT floored (should be identical to settings.json)
rm -rf ~/.CLAUDE                → currently NOT floored
cp -r ~/.claude/PROJECTS /tmp   → currently NOT floored
cat ~/.SSH/id_rsa               → currently NOT floored (credential-system-write)
```

This is a distinct class of bug from the boundary-width work in the prior two specs (that was
about how much of a *path* counts as "the same entity"; this is about case-folding of the
*literal words* in the pattern) and has a much wider blast radius: it affects every rule built
on `leadBoundary`/`trailBoundary`/`bareDirBoundary` with a literal path fragment, not just
`self-protect-claude-settings`.

## Scope — 5 rules, `Raw` field only

| Rule | File location |
|---|---|
| `self-protect-claude-settings` | `SelfProtectRules()` |
| `self-protect-argus` | `SelfProtectRules()` |
| `credential-system-write` | `Floor()` |
| `mcp-read-sensitive-path` | `Baseline()` |
| `mcp-fileop-sensitive-path` | `Floor()` |

The last two (`mcp-read-sensitive-path`, `mcp-fileop-sensitive-path`) already have `(?i)` on
their **`McpTool`** field (the verb pattern) — that is unrelated and untouched. Only their `Raw`
field (the path pattern) is missing case-insensitivity and needs it.

## Fix

Prepend `(?i)` to the `Raw` string of all five rules above. `regexp.Compile(mt.Raw)`
(`internal/classify/match.go`) compiles the string as-is with no wrapping, so a leading `(?i)`
is a standard Go/RE2 inline flag applying case-insensitivity to the entire pattern. No change to
`leadBoundary`, `trailBoundary`, or `bareDirBoundary` themselves — they contain no letters, so
they're unaffected by the flag either way. `\b` word-boundary behavior is unaffected by case
folding (it depends on word-char class, not case). Character classes like `[A-Za-z0-9_]+`
already cover both cases and remain correct (now redundantly so, harmless).

This is deliberately the **over-matching / fail-safe direction**: on a case-sensitive filesystem
(Linux) a literal-case-only path is what actually exists, so `(?i)` only ever adds coverage for
casings that don't correspond to a real distinct file there — never removes a real match.

## Testing

For each of the 5 rules, one golden case with an alternate-case variant of its most
security-critical literal, asserting `high` (floor rules) or `medium` (the two `medium`
MCP-read rule) as appropriate — mirroring the existing golden case for the canonical-case form:
- `self-protect-claude-settings`: `~/.CLAUDE` (bare dir, uppercase) → high.
- `self-protect-argus`: `~/.ARGUS` → high.
- `credential-system-write`: `~/.SSH/id_rsa` → high.
- `mcp-read-sensitive-path`: a read-verb MCP tool targeting `~/.AWS/credentials` → medium.
- `mcp-fileop-sensitive-path`: a write-verb MCP tool targeting `~/.claude/Settings.json` → high.

Plus a regression check that the existing canonical-case golden tests for all 5 rules still
pass unchanged, and that the full suite has no new failures.

## Amendment — `rc-file-inject` (found during round-4 adversarial re-verification)

Same bug class, different rule: `rc-file-inject`'s `Raw: ">>?\s*\S*\.(bash|zsh)rc\b"` doesn't use
`leadBoundary`/`trailBoundary` (so it was outside the original 5-rule scope) but has the
identical case-sensitivity gap — `>> ~/.bashrc` is caught, `>> ~/.BASHRC` / `>> ~/.Zshrc` are not.
Lower severity than the other 5 (medium/ask persistence heuristic, not a floor), but the same
one-line fix applies: prepend `(?i)`.

## Out of scope

The `../claude/settings.json` sibling-fabrication path-traversal residual (documented in the
prior spec) remains out of scope — case-folding does not touch that.
