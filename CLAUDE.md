# Argus — Engineering Rules

Binding rules for this codebase. **Violating the letter violates the spirit.** When a rule blocks you, stop and ask — don't route around it. For design judgment (when to abstract, add a dep, split a file), invoke the **argus-architect** skill.

## Stack & build
- Go **1.26**. **`CGO_ENABLED=0` always** — pure-Go deps only (this is why `modernc.org/sqlite`, not `mattn/go-sqlite3`).
- Dependencies are a liability. Pre-approved: `mvdan.cc/sh/v3`, `modernc.org/sqlite`, `santhosh-tekuri/jsonschema/v6`. Any new dep needs a one-line justification and a "why not stdlib" answer.
- **stdlib first:** `log/slog` (logs), `flag` (args), `net/http`+SSE (serve), `encoding/json`, `//go:embed` (assets). No web / DI / config framework.

## Architecture invariants — never break these
1. **Pure core, dirty shell.** `classify(payload, policy) → Decision` is pure: no I/O, no clock, no globals, no randomness. Parsing, DB, and hook emission wrap it. This is what makes the engine testable and replayable.
2. **The hot path never fails open.** On any error touching a command with a dangerous verb → escalate (`ask`/`deny`). Never silent-allow.
3. **Logging/DB failures never change the verdict.** The verdict is computed before, and independently of, any write.
4. **`high` is a floor.** An `alwaysHigh` match that *fires* cannot be downgraded by policy or allowlist — never add a code path that can. A rule may only *decline to match* (a narrowed match condition) when the narrowing is fail-closed: any parse failure, obfuscation, redirect, pipe, mixed chain, empty command list, or non-listing/write/exec command yields no exemption. Only a pure metadata-listing chain (`ls`/`stat`/`du`, Bash-only) is ever exempt.
5. **Self-protection stays high.** Self-protection floors writes, deletes, and all content reads of Argus's own config / binary / hook / db paths and credential paths. Only a pure metadata listing (`ls`/`stat`/`du` — names and metadata, never content) is exempt, Bash-only, via `internal/classify/readonly.go`; MCP and content reads are never exempt.

## Code style
- **One file, one responsibility.** If a file passes ~200 lines or you can't name its single job, split it.
- **Functions over interfaces.** Add an interface only when a second real implementation exists today. No generics for one type. No factories for one product.
- **No premature abstraction.** Duplication is cheaper than the wrong abstraction — inline it twice before extracting.
- **Errors:** wrap with context and `%w` (`fmt.Errorf("load policy: %w", err)`). Never `panic` outside `main`. Never swallow an error except at a documented best-effort write (comment it).
- Names carry intent. Exported symbols get a doc comment saying **why**, not what.
- No dead code, no speculative params, no commented-out blocks.

## Testing
- **TDD:** failing test first, then minimal code. Table-driven is the default.
- Every classifier rule and scorer has **golden cases**; every evasion technique has a **corpus entry that must stay caught**.
- Pure functions: exhaustive unit tests. Shells: one integration test.
- A non-deterministic test is a bug.

## Commits
- Identity **`lucasngucii <lucasalehwork@gmail.com>`**. **Never** add a `Co-Authored-By: Claude` trailer.
- Conventional commits (`feat: fix: test: docs: chore:`). One logical change per commit. Commit at each green.

## Default posture
Choose the boring, readable option. Optimize for the next person reading this at 2am. Measure before optimizing — the hot-path budget (~5ms) is guarded by a benchmark, not a guess.
