# self-protect-claude-settings — narrow the bare-`.claude` false-positive

**Date:** 2026-07-30
**Status:** approved

## Problem

`self-protect-claude-settings`'s bare-`.claude` alternative used the shared `trailBoundary`
(`(/|[\s;&|)"']|$)`), whose first branch (`/`) only checks that the character immediately after
`.claude` is a slash — it does not look further. So it matched `.claude` followed by ANY
subpath, not just a whole-directory reference. This floored every write/read/command touching
anything under `~/.claude/` — including the auto-memory system's own files
(`~/.claude/projects/*/memory/*.md`), a completely legitimate, everyday operation unrelated to
hook-wiring self-protection.

## Design (three findings surfaced during brainstorming, all folded in)

1. **The false positive itself:** narrow the bare-dir alternative to a real "whole directory or
   an alias of itself" boundary — not "starts with a slash".
2. **The narrowing itself has edge cases** (found by tracing `.claude//`, `.claude/.`,
   `.claude/..`): a naive `/?` (at most one trailing slash) boundary would let
   `rm -rf ~/.claude//` (double slash), `rm -rf ~/.claude/.` (dot-alias for itself), and
   `cp -r ~/.claude/.. /tmp/x` (parent-traversal exfil) slip through undetected. Fixed by
   treating ANY run of only `.`/`/` characters after the directory name as "still the same
   entity", not a distinct subpath.
3. **The narrowing reopens an obfuscation bypass on nhánh 1** (found by tracing
   `.claude/./././settings.json`): the OLD overly-broad nhánh 2 accidentally caught this as a
   side effect (any subpath matched). Once narrowed, this specific obfuscation of the
   settings.json path slips through both nhánh 1 (exact-match, no tolerance for `./` noise) and
   the now-narrower nhánh 2. Fixed by hardening nhánh 1 to tolerate `./` noise directly.
4. **Scope decision (user-approved):** after narrowing, `cp -r ~/.claude/projects /tmp/exfil` —
   bulk-copying every project's transcripts/memory — would no longer be self-protect-floored
   (it's a genuinely named subpath, not a dot-alias). The user chose to explicitly protect
   `.claude/projects` as its own whole-directory reference (same reasoning as `.claude` itself),
   while leaving an individual project's subfolder (`.claude/projects/<id>`) out of scope — that
   narrower action is left to the general `rm-recursive`/`rm-catastrophic` scoring, not
   self-protection specifically.

## The fix

```go
// bareDirBoundary closes a whole-directory-or-alias-of-itself reference: any
// run of only "." and "/" characters (a trailing slash, "/." or "/.." self/
// parent aliases, or repeated slashes) still refers to the SAME entity, not a
// genuinely distinct file/dir inside it — so it must still be caught. A named
// segment after the slash (an actual deeper path) is a distinct target and is
// NOT covered by this boundary; unlike trailBoundary, "/" alone is not enough.
const bareDirBoundary = `[./]*([\s;&|)"']|$)`
```

`self-protect-claude-settings`'s `Match.Raw` becomes:

```go
Match: Match{Raw: leadBoundary + `\.claude/(\./)*settings(\.local)?\.json\b` +
    `|` + leadBoundary + `\.claude` + bareDirBoundary +
    `|` + leadBoundary + `\.claude/projects` + bareDirBoundary},
```

- Nhánh 1 (settings.json): added `(\./)*` tolerance for `./`-noise between `.claude/` and
  `settings`.
- Nhánh 2 (bare `.claude`): `trailBoundary` → `bareDirBoundary`.
- Nhánh 3 (new): `.claude/projects` as its own whole-directory reference, same `bareDirBoundary`.

`self-protect-argus` is **unchanged** — no observed false positive there (`~/.argus` holds only
flat files created by the binary itself, no subdirectory an agent would legitimately write to).

## Verification table (all traced by hand before implementation; pin as tests)

| Input | Alternative | Verdict |
|---|---|---|
| `~/.claude/settings.json` | 1 | deny |
| `~/.claude/./././settings.json` (obfuscation) | 1 | deny (closes the reopened gap) |
| `rm -rf ~/.claude` | 2 | deny |
| `rm -rf ~/.claude//` (double slash) | 2 | deny |
| `rm -rf ~/.claude/.` (dot-alias) | 2 | deny |
| `cp -r ~/.claude/.. /tmp/x` (parent traversal) | 2 | deny |
| `rm -rf ~/.claude/projects` | 3 | deny |
| `cp -r ~/.claude/projects /tmp/exfil` | 3 | deny |
| `cat ~/.claude/projects/x/memory/foo.md` | none | **allow** (the reported bug, fixed) |
| `rm -rf ~/.claude/projects/x` (one project) | none (via this rule) | allow via self-protect; still scored by the general `rm-recursive`/`rm-catastrophic` rules independently |

## Known residual (explicitly out of scope, flagged for a future follow-up)

Regex matching on `Write`/`Edit`'s raw `file_path` (and Bash argument text) cannot defend
against every path-normalization trick (e.g. `.claude/../claude/settings.json` with a
fabricated sibling directory). This is a pre-existing, architecture-level limitation shared by
several other path-matching rules (`credential-system-write`, `mcp-fileop-sensitive-path`, …),
not specific to this rule. Solving it properly (e.g. normalizing paths via `filepath.Clean`
before matching, applied consistently across the ruleset) is a separate, larger piece of work
and is not attempted here.
