# Read-only view exemption for self-protect / credential rules

**Date:** 2026-07-30
**Status:** approved (design v2 — hardened after 5-agent review)
**Author:** brainstormed with the user

## Problem

Argus's self-protect and credential rules fire on *any* tool invocation whose
subject text contains a protected path, with no awareness of whether the
operation reads or writes. A pure view of Argus's own config wiring is floored
`high`/`deny` exactly like a destructive write:

```
cat ~/.claude/projects/x/memory.md → high/deny   (just reading a note)
ls ~/.argus                        → high/deny   (just listing a directory)
grep foo ~/.claude/x               → high/deny
git -C ~/.claude show HEAD:x       → high/deny
ls ~/.ssh                          → high/deny   (listing filenames, not key content)
```

None of these can disarm Argus or leak a secret. `.claude`/`.argus` hold hook
wiring and Argus's own state; a `~/.ssh` *directory listing* reveals filenames,
not key material. Yet all are treated as the maximal-severity floor.

The user's framing: **view operations should generally be allowed, except views
of genuinely sensitive information** — the *content* of a credential file, a
credential-bearing settings file, a system secret.

This is the same defect class as the just-fixed `opaque-exec` false positive
(`git -C … show` flagged as an opaque subshell): a rule matching coarse text
without the context that distinguishes benign from dangerous.

## Design history — v1 was unsound

A first design (v1) trusted the **command name** to decide read-vs-write. A
5-agent adversarial review proved that unsound and it was rejected. Confirmed
against the real binary:

- `find` (`-delete`, `-exec`) is a delete/exec primitive, yet is a "metadata"
  verb — `find ~/.claude -delete` disarms Argus; `find ~/.ssh -exec cat {} \;`
  reads key content. The `-delete`/`-exec` payloads are `find`'s arguments, not
  separate parsed commands, so the "every command is a read verb" check is blind
  to them.
- `sort -o FILE` / `uniq IN OUT` write via a flag/positional, not a shell
  redirect, so the redirect check misses them: `sort -o ~/.claude/settings.json`
  overwrites the hook wiring.
- An empty command list (`X=$(rm -rf ~/.claude)` parses to zero resolved
  commands, `Obfuscated=false`) makes the universal-quantifier conditions
  **vacuously true** — the floor is exempted while bash still executes the
  substitution.
- `git reflog expire`/`delete` mutate, yet `reflog` was a read subcommand.

v2 (this document) closes all four by (a) pruning the verb sets to commands with
**no argument-reachable write/exec mode**, (b) requiring a non-empty command
list, (c) adding a `-o`/`--output` guard and dropping `reflog` from git,
and (d) a metadata/content tier split plus a settings-file carve-out so
credential-bearing files never get a content exemption.

## Invariant change — CLAUDE.md §4 / §5 (deliberate, user-approved)

This design deliberately narrows two stated invariants. The user explicitly
approved the change during brainstorming; it is recorded here and the CLAUDE.md
edits are part of the implementation.

- **§4 (high is a floor).** Unchanged in spirit: once a floor rule *fires*, no
  policy or allowlist can downgrade it. Clarified: a **pure read** of a
  self-protect path (not a secret) **does not fire** the floor in the first
  place — a narrowed match condition, **not** a downgrade code path. No code
  path lowers an `AlwaysHigh` match that has already matched.
- **§5 (self-protection stays high).** Narrowed: self-protection floors
  **writes/deletes** to Argus's own paths, **and any read of secret content**
  (credential files, credential-bearing settings files). A pure read of the
  hook wiring / non-secret config is outside self-protection's scope.

Security rationale: §5 exists so an agent cannot **disarm** Argus. Disarming
means writing/deleting the hook wiring, binary, db, or config. Reading a
non-secret note does not disarm anything; at worst it is reconnaissance, which
the audit trail still records. Reading a **secret** (a key, a token in
`settings.local.json`) is the one read that stays floored.

### Exact CLAUDE.md wording (part of the implementation)

Append to §4:

> An `alwaysHigh` rule that **matches** pins the floor; nothing may downgrade it.
> A rule may decline to **match** (a narrowed match condition) only when the
> narrowing is itself fail-closed — any parse failure, obfuscation, redirect,
> pipe-to-writer, mixed chain, empty command list, **or write-capable
> argument** yields no exemption. A "read verb" with a write mode
> (`find -delete`, `sort -o`, `git … --output`) is a write, not a read.

Replace §5 with:

> **Self-protection stays high.** Self-protection floors **writes/deletes** to
> Argus's own paths **and any read of secret content** (credential files,
> credential-bearing settings files). Only a pure read of the non-secret hook
> wiring / config is exempt, Bash-only, via `internal/classify/readonly.go`;
> MCP is never exempt. The exemption is keyed to specific built-in rule IDs
> whose regexes must never be broadened to cover secret content.

## Mechanism — non-match, not downgrade

Chosen approach (of three considered — a local helper, a new `policy.Match`
field, a `shellast.Facts` flag): a **pure predicate in a dedicated file
`internal/classify/readonly.go`**, keyed to specific rule IDs, matching the
existing `effectiveTool` precedent. No change to `policy.Match`, its JSON
schema, or `shellast`. YAGNI: only three rules need this today; generalising
to a public schema field is deferred until a third real consumer exists.
(`classify.go` is already ~209 lines; the verb vocabulary + predicate is a
distinct responsibility and gets its own file.)

The predicate makes the rule **not fire** on a read-only chain (like the
`opaque-exec` narrowing), rather than letting it fire and then downgrading — so
no "downgrade an already-matched floor" code path is ever created. Verified in
review: the `continue` runs before `floorHit`/severity is set, so floor
integrity and the `applyAllowlist` guard are untouched.

### `isReadOnlyChain(f shellast.Facts, verbs map[string]bool) bool`

Returns `true` only when **every** condition holds (fail-closed — any doubt
returns `false`):

1. `f.ParseOK == true` — a parse failure is never treated as a read.
2. `f.Obfuscated == false` — any evasion signal (eval, unresolved expansion,
   command/process substitution, decoder-into-shell) disqualifies.
3. `len(f.Commands) > 0` — an empty command list is never a read (closes the
   `X=$(rm -rf …)` vacuous-quantifier hole).
4. `len(f.Redirects) == 0` — any redirect disqualifies. (`parse.go` records
   every redirect, input and output. Output `>`/`>>` are writes; input `<`
   reads are over-blocked here — a deliberate fail-safe, accepted: `grep foo <
   x` stays floored rather than risk a mis-parse.)
5. **Every** `Cmd` in `f.Commands` has `Resolved == true` **and** is a read verb
   under `verbs` (for `git`, see below).
6. **Every** entry in `f.PipeSinks` is a read verb under `verbs`. (Belt-and-
   suspenders: every pipe RHS also surfaces as a `Cmd`, so condition 5 already
   covers it; kept as cheap fail-closed defense-in-depth, annotated as such.)

The **universal quantifier over commands (5) plus the non-empty guard (3)** is
the security core: `cat ~/.claude/x && rm -rf ~/.claude` is not read-only (`rm`
fails 5); `X=$(rm …)` is not read-only (fails 3).

### Verb sets — only commands with NO write/exec mode

Every listed command is read-only in **all** its argument forms (no output
flag, no in-place edit, no delete/exec). Commands with any write mode
(`find`, `sort`, `uniq`, `tree`, `awk`, `sed`, `yq`) are **deliberately
excluded** — losing them means a rare view stays floored, which is the safe
direction.

```go
// touch only names/metadata, never file content
metadataVerbs = {ls, stat, file, du, realpath, basename, dirname, readlink}

// reveal file content, but cannot write/exec
contentVerbs  = {cat, head, tail, less, more, wc, nl, grep, egrep, fgrep,
                 rg, ag, diff, cmp, cut, jq, xxd, od, hexdump, strings,
                 comm, tac, column}
```

`readVerbs` = `metadataVerbs ∪ contentVerbs`, plus `git` handled specially:

`git` is a read verb only when `verbs` includes it (i.e. only the content tier —
`git show`/`git grep` reveal content, so `git` is **never** a metadata-tier
read verb and never exempts a credential read) **and** all of:
- `gitSubcommand(cmd.Args)` (existing `internal/classify/scorers.go:196`,
  skips global options `-C`/`-c`/`--no-pager`/`--git-dir=…`) is in
  `{show, diff, log, status, blame, cat-file, ls-files, ls-tree, rev-parse,
  describe, shortlog, grep}` — note **`reflog` is excluded** (it has
  `expire`/`delete` mutating forms);
- none of the args after the subcommand is `-o`, `--output`, or `--output=…`
  (`git diff --output=FILE` writes).

The lists are **closed and final**, not illustrative — an implementer uses
exactly these.

### Wiring in `classify.Classify`

Path nature determines the tier; a settings-file subject is carved out because
those files can hold MCP tokens/secrets.

| Rule | Paths | Metadata read | Content read |
|---|---|---|---|
| `self-protect-claude-settings` | `.claude/**` | exempt (`safe`) | exempt **unless** subject is a `settings(.local).json` path |
| `self-protect-argus` | `.argus`, `bin/argus` | exempt | exempt |
| `credential-system-write` | `~/.ssh/*`, `~/.aws/credentials`, `/etc/*` | exempt | **floored** (secret content) |

Inside `Classify`'s rule loop, after a rule matches and before its severity is
applied:

```go
switch r.ID {
case "self-protect-claude-settings":
    // metadata read of anything under .claude is safe (even settings.json —
    // ls/stat reveal no content); content read is safe EXCEPT of a settings
    // file, which may hold secrets and stays floored.
    if isReadOnlyChain(f, metadataVerbs) ||
        (!matchesClaudeSettingsFile(subject) && isReadOnlyChain(f, readVerbs)) {
        continue
    }
case "self-protect-argus":
    if isReadOnlyChain(f, readVerbs) {
        continue
    }
case "credential-system-write":
    // only metadata listing is exempt; content read of a secret stays floored.
    if isReadOnlyChain(f, metadataVerbs) {
        continue
    }
}
```

- `matchesClaudeSettingsFile(subject)` reuses the settings-file sub-pattern the
  rule already carries: `(?i)` + `leadBoundary` + `\.claude/[./]*settings(\.local)?\.json\b`.
  Defined once, adjacent to the rule, referenced by both.
- Keyed on rule ID (localised, like `effectiveTool`), not a schema field.
- The `continue` skips the rule before its severity is accumulated — no
  downgrade of an already-matched floor.
- Independent of `applyAllowlist`: a read-only chain produces no self-protect
  match for the allowlist to act on.

### Load-bearing invariant — rule-ID ↔ path-nature coupling

The tiers are keyed on rule ID in `readonly.go`/`classify.go`, but the paths
each rule matches live in `defaults.go` and can drift independently. If a
`self-protect-*` regex were later broadened to a genuinely secret file, that
file would silently inherit the content exemption. This is guarded by:

- A doc comment on each of `self-protect-claude-settings`, `self-protect-argus`,
  and `credential-system-write` stating whether its paths are secret-bearing and
  which read tier the exemption grants, cross-referencing the wiring.
- A matching comment at the `switch r.ID` site pointing back to those rules.

Not enforced by the type system (YAGNI — three rules), but documented on both
ends so an edit on either side surfaces the constraint.

### MCP is unchanged

MCP payloads have no shell AST (`f` is empty), so `isReadOnlyChain` returns
`false` (fails condition 3) for every MCP call. `mcp-read-sensitive-path` and
`mcp-fileop-sensitive-path` keep their current behavior. The exemption is
Bash-only.

### Net behavior change

Bash-only, three rules:
- `self-protect-claude-settings`: metadata read → `safe`; content read → `safe`
  except of a settings file (still floored).
- `self-protect-argus`: any pure read → `safe`.
- `credential-system-write`: pure metadata read → `safe`; content read
  unchanged (floored).

## Group B — independent over-broad matches

Two unrelated rules match too coarsely (not a read/write question), fixed the
way `opaque-exec` was. Landed as **separate commits** from the read exemption
(different risk: one edits a floor + invariants, these are pattern narrowings).

### Fix: `disk-format` — drop the bare `if=` alternative

Current `ArgMatches: if=|of=/dev/|erase` floors `dd if=/dev/sda of=backup.img`
(reading a device into a file — a backup) as `high`/`deny`. `dd`'s destructive
signal is always its **output** (`of=/dev/…`) or `erase`, never its input.
Drop `if=`; keep `of=/dev/` and `erase`. New: `ArgMatches: of=/dev/|erase`.

- `dd if=/dev/sda of=backup.img` → no longer fires (backup allowed).
- `dd if=/dev/zero of=/dev/sda`, `dd of=/dev/sda` → still high (via `of=/dev/`).
- `diskutil eraseDisk …` → still high (via `erase`); dropping `if=` doesn't
  touch it.
- Update the rule's doc comment (`defaults.go:150-152`) in lockstep — it
  currently says "reading or writing a raw device (if=…, of=/dev/…)"; the `if=`
  read is no longer floored.
- Known residual (pre-existing, unchanged): `dd of=/dev/null`/`of=/dev/stdout`
  still floor `high` — benign but rare, accepted as-is.

### Fix: `docker-service` — noun → mutating verb

Current `ArgsContain: [service, stack, swarm, prune, down]` fires on the noun
regardless of verb, so `docker service ls`/`stack ps`/`service inspect` (views)
ask like `create`/`prune`/`down`. It is `medium`/ask (not a floor), so the cost
is a spurious prompt. Switch from `ArgsContain` to an `ArgMatches` regex
requiring a mutating verb (matched against joined args; `Cmd: [docker,
docker-compose]` still gates that only docker invocations are considered):

```
(?i)\b(service|stack|swarm)\s+(create|rm|remove|scale|update|deploy|leave|init|rollback)\b|\bsystem\s+prune\b|\bcompose\s+down\b|\bprune\b|\bdown\b
```

- `docker service ls/ps/inspect/logs` → no longer fires.
- `docker service create/rm/scale`, `docker stack deploy`, `docker swarm leave`,
  `docker system prune`, `docker compose down`, `docker-compose down` → still
  `medium`.
- Residual (accepted, `medium`/ask only): the bare `\bdown\b`/`\bprune\b`
  alternatives match those tokens anywhere in args (e.g. a container literally
  named `down`). Cost is a spurious prompt, not a block. `downstream` does
  **not** match (`\b`).

### Left as-is (reviewed, intentional)

- **`sudo`** — asking on *every* `sudo` is a deliberate "privilege escalation
  always asks" posture. The wrapped command still surfaces separately (`sudo rm
  -rf` → `rm-catastrophic` high). Narrowing would weaken a sound default.
- **`mcp-mutating-tool`** (`run`/`exec` verbs) — genuinely ambiguous
  (`run_query` reads, `run_deploy` mutates, indistinguishable by name); `medium`
  /ask, narrowing risks missing real mutations.

## Testing (TDD, table-driven, golden)

**Read exemption — positive (now `safe`):**
`cat ~/.claude/projects/x/memory.md`, `ls ~/.argus`, `grep foo ~/.claude/x`,
`head bin/argus`, `git -C ~/.claude show HEAD:x`, `ls ~/.ssh`, `stat ~/.aws`,
`cat ~/.argus/policy.json`.

**Read exemption — floor MUST still fire (the critical regressions):**
- writes/deletes: `rm -rf ~/.claude`, `rm -rf ~/.argus`,
  `echo x > ~/.claude/settings.json`, `cat a > ~/.argus/db` (redirect)
- write-capable "read" verbs (the v1 holes — corpus entries, must stay caught):
  `find ~/.claude -delete`, `find ~/.ssh -type f -exec cat {} \;`,
  `sort -o ~/.claude/settings.json in`, `uniq in ~/.argus/db`,
  `git -C ~/.claude diff --output=~/.claude/settings.json HEAD`,
  `git -C ~/.claude reflog expire --all`
- structural: `cat ~/.claude/x && rm -rf ~/.argus` (mixed chain),
  `X=$(rm -rf ~/.claude)` (empty commands), `cat $(evil) ~/.claude`
  (obfuscated / unresolved), `cat ~/.claude/x | tee /other` (pipe to writer),
  `bash -c "cat ~/.claude/settings.json"` (bash not a read verb)
- settings carve-out: `cat ~/.claude/settings.json`,
  `cat ~/.claude/settings.local.json`, `grep token ~/.claude/settings.local.json`
  → **still high** (content of a secret-bearing file); but
  `stat ~/.claude/settings.json`, `ls ~/.claude` → `safe`
- credential content: `cat ~/.ssh/id_rsa`, `grep key ~/.aws/credentials`
  → **still high**
- Write/Edit **tool** floor (not Bash): a `Write`-tool payload to
  `~/.claude/settings.json` and to `~/.ssh/id_rsa` → **still high** (empty facts
  → `isReadOnlyChain` false; pins the Bash-only boundary)

**`isReadOnlyChain` unit tests — one negative per condition:**
`ParseOK=false` (unterminated quote), `Obfuscated=true`, empty `Commands`,
a redirect present, an unresolved command name (`Resolved=false`), a pipe sink
that is a non-read verb, and a resolved-but-non-read command.

**MCP unchanged:** an MCP read tool targeting `.claude` → still `medium`
(regression guard that the exemption didn't leak into MCP).

**Group B:**
`dd if=/dev/sda of=backup.img` → safe; `dd if=/dev/zero of=/dev/sda`,
`dd of=/dev/sda` → high. `docker service ls/ps/inspect` → safe; `docker service
create`, `docker system prune`, `docker compose down` → medium.

**Determinism / purity:** `isReadOnlyChain` is a pure function of `Facts` and a
membership map (never iterated for logic/output, so map order can't leak into a
verdict); exhaustive unit tests, no clock/IO/globals (CLAUDE.md §1).

## Out of scope

- **`/etc/shadow` (and `/etc/passwd`) *read* coverage on Bash.** Discovered
  during review: `cat /etc/shadow` is **not** floored today (`credential-system-
  write` covers only `>\s*/etc/` writes and `/etc/sudoers`). A pre-existing gap,
  unrelated to this change; left as-is. (MCP reads of `/etc/shadow` *are*
  covered by `mcp-read-sensitive-path`.)
- Extending the read exemption to MCP (no shell AST to reason about).
- Narrowing `sudo` or `mcp-mutating-tool` (reviewed, intentionally kept).
- Re-including `find`/`sort`/`uniq`/`awk`/`sed` with per-command write-flag
  guards (a view via these stays floored — the safe direction).
- Generalising read-awareness into a public `policy.Match` field (deferred to a
  third consumer).
- The `../claude/settings.json` sibling-fabrication path-traversal residual
  (tracked in a prior spec, unrelated to reads).
