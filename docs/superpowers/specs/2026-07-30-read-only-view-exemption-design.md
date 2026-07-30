# Metadata-read view exemption for self-protect / credential rules

**Date:** 2026-07-30
**Status:** approved (design v3 — simplified to metadata-only after two review rounds)
**Author:** brainstormed with the user

## Problem

Argus's self-protect and credential rules fire on *any* tool invocation whose
subject text contains a protected path, with no awareness of whether the
operation reads or writes. A pure directory listing is floored `high`/`deny`
exactly like a destructive write. Confirmed against the current binary:

```
ls ~/.argus              → high/deny   (listing a directory)
ls ~/.claude             → high/deny
ls ~/.ssh                → high/deny   (filenames, not key content)
stat ~/.aws              → high/deny   (size/perms, not content)
stat ~/.claude/settings.json → high/deny   (metadata, reveals nothing)
```

None of these can disarm Argus or leak a secret — a listing reveals filenames
and metadata (size, perms, mtime), never file content. Yet all are floored at
maximal severity. The user's framing: **views should generally be allowed,
except views of genuinely sensitive information.**

This is the same defect class as the just-fixed `opaque-exec` false positive
(`git -C … show` flagged as an opaque subshell): a rule matching coarse text
without the context that distinguishes benign from dangerous.

## Design history — why metadata-only

Two earlier designs were rejected during adversarial review:

- **v1** trusted the command *name* to decide read-vs-write. Review proved
  unsound: `find -delete`, `sort -o`, `uniq OUT`, `git reflog`, and an
  empty-command vacuous quantifier (`X=$(rm -rf …)`) all let a write masquerade
  as a read and suppress the floor.
- **v2** pruned the verb set and added a content tier plus a settings-file
  carve-out. A second review (running the real tools) proved *that* unsound too:
  `xxd -r`, `rg --pre`, `less -o`/`LESSOPEN`, `git -c diff.external`, `git grep
  -O`, and repo-local `.git/config diff.external` are all write/exec vectors
  reachable through "read" verbs — several invisible in argv. It also found the
  content tier was nearly **vacuous**: a prior scope fix already made deep paths
  under `.claude` non-matching, so the content tier exempted essentially nothing
  useful (settings files are secret-bearing and must stay floored; bare
  directories are only sensibly *listed*, not `cat`-ed).

The conclusion both rounds converged on: **content reading and `git` cannot be
safely classified read-only from a command's arguments**, and the content tier
bought no real benefit. v3 keeps only what is provably safe and useful — a
**single metadata-listing tier** (`ls`/`stat`/`du`/…). Content reads and `git`
against a protected path stay floored (the safe direction). This is both the
leaner and the sounder design.

## Invariant change — CLAUDE.md §4 / §5 (deliberate, user-approved)

This design deliberately narrows two stated invariants. The user explicitly
approved the change during brainstorming.

- **§4 (high is a floor).** Unchanged in spirit: once a floor rule *fires*,
  nothing downgrades it. Clarified: a **pure metadata listing** of a protected
  path **does not fire** the floor — a narrowed match condition, **not** a
  downgrade code path. No code path lowers an `AlwaysHigh` match that already
  matched.
- **§5 (self-protection stays high).** Narrowed: self-protection floors
  **writes/deletes and all content reads** of Argus's own paths and credential
  paths. Only a pure metadata listing (`ls`/`stat`/`du` — names, sizes, perms,
  never content) is exempt.

Security rationale: §5 exists so an agent cannot **disarm** Argus (write/delete
its wiring/binary/db/config) or **exfiltrate** a secret (read a key's content).
A directory listing does neither; it reveals only names and metadata, and the
audit trail still records it.

### Exact CLAUDE.md wording (part of the implementation)

Append to §4:

> An `alwaysHigh` rule that **matches** pins the floor; nothing may downgrade it.
> A rule may decline to **match** (a narrowed match condition) only when the
> narrowing is fail-closed — any parse failure, obfuscation, redirect, pipe,
> mixed chain, empty command list, non-listing command, or write/exec-capable
> argument yields no exemption. Only a pure metadata-listing chain
> (`ls`/`stat`/`du`, Bash-only) is ever exempt.

Replace §5's line with:

> **Self-protection stays high.** Self-protection floors **writes, deletes, and
> all content reads** of Argus's own paths and credential paths. Only a pure
> metadata listing (`ls`/`stat`/`du` — names and metadata, never content) is
> exempt, Bash-only, via `internal/classify/readonly.go`; MCP and content reads
> are never exempt. The exemption is keyed to specific built-in floor rule IDs.

## Mechanism — non-match, not downgrade

A **pure predicate in a dedicated file `internal/classify/readonly.go`**, keyed
to specific built-in rule IDs, matching the existing `effectiveTool` precedent.
No change to `policy.Match`, its JSON schema, or `shellast`. YAGNI: only three
rules need this; generalising to a public schema field is deferred until a
third real consumer exists. (`classify.go` is already ~209 lines; the listing
vocabulary + predicate is a distinct responsibility.)

The predicate makes the rule **not fire** on a listing chain (like the
`opaque-exec` narrowing), rather than firing then downgrading — so no
"downgrade an already-matched floor" path exists. The `continue` runs before
`floorHit`/severity is set for that rule, so floor integrity and the
`applyAllowlist` guard are untouched (verified against `classify.go`).

### `isReadOnlyChain(f shellast.Facts) bool`

"Read-only" here means a **pure metadata-listing chain**: every command lists
names/metadata and none reads content, writes, or executes. Returns `true` only
when **all** hold (fail-closed — any doubt returns `false`):

1. `f.ParseOK == true` — a parse failure is never a listing.
2. `f.Obfuscated == false` — any evasion signal (eval, unresolved expansion,
   command/process substitution, decoder-into-shell) disqualifies.
3. `len(f.Commands) > 0` — an empty command list is never a listing (closes the
   `X=$(rm -rf …)` vacuous-quantifier hole).
4. `len(f.Redirects) == 0` — any redirect disqualifies. (`parse.go` records
   every redirect. Output `>`/`>>` are writes; input `<` is over-blocked here —
   a deliberate fail-safe.)
5. **Every** `Cmd` in `f.Commands` has `Resolved == true` **and** `Name ∈
   listingVerbs`.
6. **Every** entry in `f.PipeSinks` is in `listingVerbs`. (Belt-and-suspenders:
   every pipe RHS also surfaces as a `Cmd`, so condition 5 already covers it;
   kept as cheap fail-closed defense-in-depth.)

The universal quantifier over commands (5) plus the non-empty guard (3) is the
security core: `ls ~/.claude && rm -rf ~/.claude` fails 5 (`rm`); `X=$(rm …)`
fails 3.

### `listingVerbs` — only pure name/metadata commands

```go
listingVerbs = {ls, stat, du, realpath, basename, dirname, readlink}
```

Every entry reveals only names, sizes, permissions, or a symlink target — never
file content — and has **no** output flag, in-place edit, delete, or exec mode
in any argument form (audited command-by-command, GNU and BSD/macOS variants,
in the second review round). Deliberately **excluded** and why:

- content readers (`cat`, `head`, `grep`, `wc`, `cut`, …) — reveal content;
  a credential/settings read must stay floored.
- `file` — `file -C -m X` writes `X.mgc`; also borderline content (magic bytes).
- `find` — `-delete`/`-exec`; `sort`/`uniq`/`tree` — output flag/positional;
  `xxd`/`rg`/`less`/`more` — write or exec (`xxd -r`, `rg --pre`, `less -o`,
  `LESSOPEN`); `awk`/`sed`/`yq` — write/in-place.
- `git` — repo-local `.git/config` `diff.external`/textconv makes even `git
  show`/`log`/`diff` execute arbitrary commands **with no argv signal**, so git
  cannot be classified read-only from arguments. Any `git … <protected path>`
  stays floored.

The list is **closed and final** — an implementer uses exactly these.

### Wiring in `classify.Classify`

The exemption is Bash-only and applies only to the three built-in floor rules.
Both constraints are enforced explicitly (not left to incidental behavior):

```go
// consider gains an isBuiltinFloor bool so a user rule that happens to reuse a
// built-in ID cannot claim the exemption against its own regex.
consider := func(rules []policy.Rule, isBuiltinFloor bool) {
    for _, r := range rules {
        ...
        if !ok { continue }
        if isBuiltinFloor && tool == "Bash" && isSelfProtectOrCredential(r.ID) &&
            isReadOnlyChain(f) {
            continue // pure metadata listing of a protected path — not a violation
        }
        ...
    }
}
consider(policy.Floor(), true)
consider(pol.Rules, false)
```

- `tool` is `effectiveTool(p)` (already in `Classify` scope). For a `Write`/
  `Edit` payload `tool` is `"Write"`/`"Edit"` (no `Command`), so the exemption
  never applies — the Bash-only boundary is **real**, not incidental. A `Write`
  to `~/.claude/settings.json` or `~/.ssh/id_rsa` stays floored.
- `isSelfProtectOrCredential(r.ID)` matches exactly
  `{self-protect-claude-settings, self-protect-argus, credential-system-write}`.
- `isBuiltinFloor` is true only for the `policy.Floor()` pass, so a user policy
  rule reusing one of those IDs gets no exemption.
- The `continue` skips only this rule; other floors (`rm-catastrophic`,
  `disk-format`, `pipe-to-shell`, …) are separate iterations and still fire.
- MCP payloads have empty facts and non-Bash tools, so the exemption never
  reaches them; `mcp-read-sensitive-path`/`mcp-fileop-sensitive-path` unchanged.

### Load-bearing invariant — rule-ID coupling

The exemption is keyed on rule ID, but the paths each rule matches live in
`defaults.go`. A doc comment on each of the three rules and at the wiring site
records the constraint: **these rules' regexes must never be broadened such that
a metadata listing could leak secret content** (metadata verbs reveal no
content, so this holds as long as the set stays metadata-only). Not
type-enforced (YAGNI — three rules), documented on both ends.

### Net behavior change

Bash-only, three rules — a pure metadata-listing chain (`ls`/`stat`/`du`/
`realpath`/`basename`/`dirname`/`readlink`) over a protected path is now `safe`
instead of `high`. Everything else (content reads, `git`, writes, deletes,
mixed chains, obfuscation) is unchanged — still floored.

## Group B — independent over-broad matches

Two unrelated rules match too coarsely (not a read/write question), fixed the
way `opaque-exec` was. Landed as **separate commits** from the exemption.

### Fix: `disk-format` — drop the bare `if=` alternative

`ArgMatches: if=|of=/dev/|erase` floors `dd if=/dev/sda of=backup.img` (a
device backup — pure read) as `high`/`deny`. `dd`'s destructive signal is always
its **output** (`of=/dev/…`) or `erase`, never its input. Drop `if=`; keep
`of=/dev/` and `erase`. New: `ArgMatches: of=/dev/|erase`.

- `dd if=/dev/sda of=backup.img` → no longer fires.
- `dd if=/dev/zero of=/dev/sda`, `dd of=/dev/sda` → still high (via `of=/dev/`).
- `diskutil eraseDisk …` → still high (via `erase`).
- Update the rule's doc comment (`defaults.go:150-152`) in lockstep.
- Known residual (pre-existing): `dd of=/dev/null`/`of=/dev/stdout` still floor
  `high` — benign but rare, accepted.

### Fix: `docker-service` — noun → mutating verb

`ArgsContain: [service, stack, swarm, prune, down]` fires on the noun regardless
of verb, so `docker service ls`/`stack ps`/`service inspect` (views) ask like
`create`/`prune`/`down`. It is `medium`/ask (not a floor). Switch to an
`ArgMatches` regex requiring a mutating verb (matched on joined args; `Cmd:
[docker, docker-compose]` still gates that only docker invocations count):

```
(?i)\b(service|stack|swarm)\s+(create|rm|remove|scale|update|deploy|leave|init|rollback)\b|\bsystem\s+prune\b|\bcompose\s+down\b|\bprune\b|\bdown\b
```

- `docker service ls/ps/inspect/logs` → no longer fires.
- `docker service create/rm/scale`, `docker stack deploy`, `docker swarm leave`,
  `docker system prune`, `docker compose down`, `docker-compose down` → still
  `medium`.
- Residual (accepted, `medium`/ask only): the bare `\bdown\b`/`\bprune\b`
  alternatives match those tokens anywhere in args (e.g. a container named
  `down`). Cost is a spurious prompt, not a block. `downstream` does not match.

### Left as-is (reviewed, intentional)

- **`sudo`** — asking on *every* `sudo` is a deliberate "privilege escalation
  always asks" posture. The wrapped command still surfaces separately (`sudo rm
  -rf` → `rm-catastrophic` high).
- **`mcp-mutating-tool`** (`run`/`exec`) — genuinely ambiguous (`run_query`
  reads, `run_deploy` mutates); `medium`/ask, narrowing risks missing mutations.

## Testing (TDD, table-driven, golden)

**Exemption — positive (now `safe`):**
`ls ~/.argus`, `ls ~/.claude`, `ls ~/.ssh`, `stat ~/.aws`,
`stat ~/.claude/settings.json` (metadata reveals nothing), `du ~/.claude/projects`,
and `ls ~/.argus && stat ~/.claude` (multi-command listing). Each is confirmed
to match its rule today (so the test is non-vacuous): `~/.argus`/`~/.ssh` via
`trailBoundary`, `~/.claude` via `bareDirBoundary`, `settings.json` via alt-1.

**Exemption — floor MUST still fire (corpus entries, must stay caught):**
- writes/deletes: `rm -rf ~/.claude`, `rm -rf ~/.argus`,
  `echo x > ~/.claude/settings.json`, `cat a > ~/.argus/db`
- content reads (now the main line held): `cat ~/.claude/settings.json`,
  `cat ~/.claude/settings.local.json`, `grep token ~/.claude/settings.local.json`,
  `cat ~/.ssh/id_rsa`, `grep key ~/.aws/credentials`, `cat ~/.argus/policy.json`
- disguised writes/exec via non-listing verbs: `find ~/.claude -delete`,
  `find ~/.ssh -type f -exec cat {} \;`, `sort -o ~/.claude/settings.json in`,
  `uniq in ~/.argus/db`, `xxd -r p ~/.claude/settings.json`,
  `rg --pre=/tmp/x . ~/.argus`, `less -o ~/.argus/db x`
- git (all forms floored): `git -C ~/.claude show HEAD:settings.local.json`,
  `git -C ~/.claude grep token`, `git -C ~/.ssh log`,
  `git -c diff.external=x -C ~/.claude diff HEAD`
- structural: `cat ~/.claude/x && rm -rf ~/.argus` (mixed chain),
  `X=$(rm -rf ~/.claude)` (empty commands), `ls $(evil) ~/.claude` (obfuscated),
  `ls ~/.claude | tee /other` (pipe to writer),
  `bash -c "ls ~/.claude"` (bash not a listing verb)
- Write/Edit **tool** floor (not Bash): `Write` payload to
  `~/.claude/settings.json` and `~/.ssh/id_rsa` → **still high** (tool≠Bash)

**`isReadOnlyChain` unit tests — one negative per condition:**
`ParseOK=false` (unterminated quote), `Obfuscated=true`, empty `Commands`,
a redirect present, an unresolved command name, a pipe sink that is a non-listing
verb, and a resolved-but-non-listing command (`cat`).

**MCP unchanged:** an MCP read tool targeting `.claude` → still `medium`.

**Group B:** `dd if=/dev/sda of=backup.img` → safe; `dd if=/dev/zero of=/dev/sda`,
`dd of=/dev/sda` → high. `docker service ls/ps/inspect` → safe; `docker service
create`, `docker system prune`, `docker compose down` → medium.

**Determinism / purity:** `isReadOnlyChain` is a pure function of `Facts`;
`listingVerbs` is used only for membership (never iterated for logic/output);
exhaustive unit tests, no clock/IO/globals (CLAUDE.md §1).

## Commits / tasks

Three logical changes, three commits:
1. Metadata-read exemption (`readonly.go` + wiring + CLAUDE.md §4/§5 + per-rule
   doc comments) — the CLAUDE.md edit lands with the code it describes.
2. `disk-format` narrowing.
3. `docker-service` narrowing.

## Out of scope

- **`/etc/shadow`/`/etc/passwd` *read* coverage on Bash.** Discovered in review:
  `cat /etc/shadow` is **not** floored today (`credential-system-write` covers
  only `>\s*/etc/` writes and `/etc/sudoers`). A pre-existing gap, left as-is.
- Content reads and `git` of protected paths (kept floored — the safe direction).
- Extending the exemption to MCP (no shell AST).
- Narrowing `sudo` or `mcp-mutating-tool` (reviewed, intentionally kept).
- Generalising read-awareness into a public `policy.Match` field.
- The `../claude/settings.json` sibling-traversal residual (prior spec).
