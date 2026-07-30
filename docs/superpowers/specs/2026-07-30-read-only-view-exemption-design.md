# Read-only view exemption for self-protect / credential rules

**Date:** 2026-07-30
**Status:** approved (design)
**Author:** brainstormed with the user

## Problem

Argus's self-protect and credential rules fire on *any* tool invocation whose
subject text contains a protected path, with no awareness of whether the
operation reads or writes. A pure view of Argus's own config wiring is floored
`high`/`deny` exactly like a destructive write:

```
cat ~/.claude/settings.json     → high/deny   (just reading hook config)
ls ~/.argus                     → high/deny   (just listing a directory)
grep foo ~/.claude/x            → high/deny
git -C ~/.claude show HEAD:x    → high/deny
ls ~/.ssh                       → high/deny   (listing filenames, not key content)
```

None of these can disarm Argus or leak a secret. `.claude`/`.argus` hold hook
wiring and Argus's own state — not secrets. A `~/.ssh` *directory listing*
reveals filenames, not key material. Yet all are treated as the maximal-severity
floor.

The user's framing: **view operations should generally be allowed, except views
of genuinely sensitive information** (the *content* of a credential file, a
system secret like `/etc/shadow`).

This is the same class of defect as the just-fixed `opaque-exec` false positive
(`git -C … show` flagged as an opaque subshell): a rule matching on coarse text
without the context that distinguishes benign from dangerous.

## Invariant change — CLAUDE.md §4 / §5 (deliberate, user-approved)

This design deliberately narrows two stated invariants. The user explicitly
approved the change during brainstorming; it is recorded here and the CLAUDE.md
edits are part of the implementation.

- **§4 (high is a floor).** Unchanged in spirit: once a floor rule *fires*, no
  policy or allowlist can downgrade it. Clarified: a **pure read** of a
  self-protect path (not a secret) **does not fire** the floor in the first
  place — this is a narrowed match condition, **not** a downgrade code path.
  No code path lowers an `AlwaysHigh` match that has already matched.
- **§5 (self-protection stays high).** Narrowed: self-protection floors
  **writes/deletes** to Argus's own paths. A pure read of the hook-wiring /
  config is outside self-protection's scope. Genuinely secret content
  (credential *files*, `/etc/shadow`) still floors every verb except pure
  metadata listing.

The security rationale: §5 exists so an agent cannot **disarm** Argus.
Disarming means writing/deleting the hook wiring, binary, db, or config.
Reading `settings.json` does not disarm anything — at worst it is reconnaissance,
which the audit trail still records.

## Mechanism — non-match, not downgrade

Chosen approach (of three considered — a local helper, a new `policy.Match`
field, a `shellast.Facts` flag): a **pure helper in `classify.go`**, keyed to
the specific rule IDs, matching the existing `effectiveTool` precedent. No
change to `policy.Match`, its JSON schema, or `shellast`. YAGNI: only five
rules need this today; generalising to a public schema field is deferred until
a third real consumer exists.

The helper makes the rule **not fire** on a read-only chain (like the
`opaque-exec` narrowing), rather than letting it fire and then downgrading —
so no "downgrade an already-matched floor" code path is ever created.

### `isReadOnlyChain(f shellast.Facts, verbs map[string]bool) bool`

Returns `true` only when **every** condition holds (fail-closed — any doubt
returns `false`):

1. `f.ParseOK == true` — a parse failure is never treated as a read.
2. `f.Obfuscated == false` — any evasion signal (eval, unresolved expansion,
   decoder-into-shell) disqualifies.
3. `len(f.Redirects) == 0` — any `>`/`>>` is a write, even behind a read verb
   (`cat x > ~/.claude/settings.json`).
4. **Every** `Cmd` in `f.Commands` has `Resolved == true` **and** its `Name` is
   in `verbs` (for `git`, see below).
5. **Every** entry in `f.PipeSinks` is in `verbs` — blocks `… | tee file`,
   `… | curl` (a read piped to a writer/network sink is not a read).

The **universal quantifier is the security core**: a mixed chain such as
`cat ~/.claude/x && rm -rf ~/.claude` is NOT read-only (the `rm` command fails
condition 4), so the floor still fires.

### Two verb tiers

```go
// touch only names/metadata, never file content
metadataVerbs = {ls, stat, file, find, du, tree, realpath, basename, dirname}

// reveal file content
contentVerbs  = {cat, head, tail, less, more, wc, nl, grep, egrep, fgrep,
                 rg, ag, diff, cmp, sort, uniq, cut}
```

`git` is handled specially inside the helper: treated as a read verb only when
its subcommand — located after skipping global options (`-C dir`, `-c k=v`,
`--no-pager`, `--git-dir=…`), reusing the same skip logic the `git_danger`
scorer already applies — is in:

```
{show, diff, log, status, blame, cat-file, ls-files, ls-tree,
 rev-parse, describe, shortlog, reflog, grep}
```

Any other `git` subcommand (or an unresolvable one) makes the chain non-read.

### Wiring in `classify.Classify`

Path-nature determines which tier applies:

| Rules | Paths | Nature | Exempt verbs |
|---|---|---|---|
| `self-protect-claude-settings`, `self-protect-argus` | `.claude`, `.argus`, `bin/argus` | config wiring — **not secret** | metadata **+** content → read is `safe` |
| `credential-system-write` | `~/.ssh/*`, `~/.aws/credentials`, `/etc/*` | **secret content** | metadata **only** → content read stays floored |

Inside `Classify`'s rule loop, after a rule matches and before its severity is
applied:

```go
if isSelfProtectPathRule(r.ID) && isReadOnlyChain(f, readVerbs) {
    continue // rule does not fire — pure view of non-secret config
}
if r.ID == "credential-system-write" && isReadOnlyChain(f, metadataVerbs) {
    continue // only metadata listing is exempt; content read stays floored
}
```

where `readVerbs` is the union of `metadataVerbs` and `contentVerbs`, and
`isSelfProtectPathRule` matches the two self-protect rule IDs.

- Keyed on rule ID (localised, like `effectiveTool`), not a schema field.
- The `continue` skips the rule before its severity is accumulated — no
  downgrade of an already-matched floor.
- Independent of `applyAllowlist`: a read-only chain simply produces no
  self-protect match for the allowlist to act on.

### MCP is unchanged

MCP payloads have no shell AST (`f` is empty), so `isReadOnlyChain` returns
`false` for every MCP call. `mcp-read-sensitive-path` and
`mcp-fileop-sensitive-path` keep their current behavior. The read exemption is
Bash-only. (MCP reads of `.claude`/`.argus` remain `medium`/ask via
`mcp-read-sensitive-path`, out of scope here.)

### Net behavior change

Only three rules change behavior, all Bash-only:
- `self-protect-claude-settings`: pure read (metadata or content) → `safe`.
- `self-protect-argus`: pure read (metadata or content) → `safe`.
- `credential-system-write`: pure **metadata** read → `safe`; content read
  unchanged (floored).

## Group B — independent over-broad matches

Two unrelated rules match too coarsely (not a read/write question). Fixed the
same way `opaque-exec` was — narrow the pattern. Two others were reviewed and
deliberately left as-is.

### Fix: `disk-format` — drop the bare `if=` alternative

Current `ArgMatches: if=|of=/dev/|erase` floors `dd if=/dev/sda of=backup.img`
(reading a device into a file — a **backup**) as `high`/`deny`. `dd`'s
destructive signal is always its **output** (`of=/dev/…`) or `erase`, never its
input. Drop `if=`; keep `of=/dev/` and `erase`.

- `dd if=/dev/sda of=backup.img` → no longer fires (backup allowed).
- `dd if=/dev/zero of=/dev/sda` → still high (via `of=/dev/`).
- `dd of=/dev/sda` → still high.

New: `ArgMatches: of=/dev/|erase`.

### Fix: `docker-service` — noun → mutating verb

Current `ArgsContain: [service, stack, swarm, prune, down]` fires on the noun
regardless of verb, so `docker service ls`, `docker stack ps`,
`docker service inspect` (all views) ask exactly like `create`/`prune`/`down`.
It is `medium`/ask (not a floor), so the cost is a spurious prompt, not a block.

Switch from `ArgsContain` to an `ArgMatches` regex that requires a **mutating**
verb:

```
(?i)\b(service|stack|swarm)\s+(create|rm|remove|scale|update|deploy|leave|init|rollback)\b|\bsystem\s+prune\b|\bcompose\s+down\b|\bprune\b|\bdown\b
```

- `docker service ls/ps/inspect/logs` → no longer fires.
- `docker service create/rm/scale`, `docker stack deploy`, `docker swarm leave`,
  `docker system prune`, `docker compose down` → still `medium`.

(The bare `\bprune\b`/`\bdown\b` alternatives keep `docker system prune` and
`docker compose down` caught even though the noun differs; `Cmd: [docker,
docker-compose]` still gates that only docker invocations are considered.)

### Left as-is (reviewed, intentional)

- **`sudo`** — asking on *every* `sudo`, including `sudo cat`, is a deliberate
  "privilege escalation always asks" posture, not a bug. The wrapped command
  still surfaces separately (`sudo rm -rf` → `rm-catastrophic` high). Narrowing
  would weaken a sound default.
- **`mcp-mutating-tool`** (`run`/`exec` verbs) — genuinely ambiguous:
  `run_query` reads but `run_deploy`/`exec_migration` mutate, indistinguishable
  by name. It is `medium`/ask; narrowing risks missing real mutations.
  Fail-safe toward asking.

## Testing (TDD, table-driven, golden)

**Read-only exemption — positive (now `safe`):**
`cat ~/.claude/settings.json`, `ls ~/.argus`, `grep foo ~/.claude/x`,
`head bin/argus`, `git -C ~/.claude show HEAD:x`.

**Read-only exemption — floor MUST still fire (the critical regressions):**
- `rm -rf ~/.claude`, `rm -rf ~/.argus` → high
- `echo x > ~/.claude/settings.json`, `cat a > ~/.argus/db` → high (redirect)
- `cat ~/.claude/x && rm -rf ~/.argus` → high (mixed chain)
- `cat $(evil) ~/.claude` → high (obfuscated / unresolved)
- `cat ~/.claude/x | tee /other` → high (pipe sink is a writer)
- `bash -c "cat ~/.claude/settings.json"` → not read-only (bash is not a read
  verb; the `-c` string is opaque) → floor still applies

**Credential two-tier:**
- `ls ~/.ssh` → `safe`; `stat ~/.aws` → `safe`
- `cat ~/.ssh/id_rsa` → **still high**; `grep key ~/.aws/credentials` → **still high**
- `cat /etc/shadow` → **still high** (system secret)

**MCP unchanged:**
- an MCP read tool targeting `.claude` → still `medium` (regression guard that
  the exemption did not leak into MCP).

**Group B:**
- `dd if=/dev/sda of=backup.img` → safe; `dd if=/dev/zero of=/dev/sda` → high;
  `dd of=/dev/sda` → high.
- `docker service ls/ps/inspect` → safe; `docker service create`,
  `docker system prune`, `docker compose down` → medium.

**Determinism / purity:** `isReadOnlyChain` is a pure function of `Facts`;
exhaustive unit tests, no clock/IO/globals (CLAUDE.md §1).

## CLAUDE.md edits (part of implementation)

- §4: add that a floor is non-downgradable **once fired**, and that a pure read
  of a self-protect path does not fire it (narrowed match, not a downgrade).
- §5: scope "self-protection stays high" to **writes/deletes**; pure reads of
  the hook wiring / config are out of scope; secret *content* still floors every
  verb except metadata listing.

## Out of scope

- Extending the read exemption to MCP (no shell AST to reason about).
- Narrowing `sudo` or `mcp-mutating-tool` (reviewed, intentionally kept).
- Generalising read-awareness into a public `policy.Match` field (deferred to a
  third consumer).
- The `../claude/settings.json` sibling-fabrication path-traversal residual
  (tracked in a prior spec, unrelated to reads).
