# Argus Core Engine + Gate — Implementation Plan (Plan 1 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. REQUIRED: read `CLAUDE.md` and invoke the **argus-architect** skill before each task.
>
> **Rev 2** — hardened after two independent adversarial reviews. Changelog vs rev 1 at the end.

**Goal:** Replace the `agent-review` bash hook with a trust-first, compiled Go engine that classifies each Claude Code tool call into a severity, emits an allow/ask/deny verdict on the synchronous hot path, and records every decision to local SQLite.

**Architecture:** One Go binary with subcommands. The security verdict is a **pure function** `Classify(payload, policy) → Decision` — no I/O, no clock, no globals, no panics. Parsing, DB writes, and hook emission are side-effecting shells around it. Shell commands are understood via a real **AST parser (`mvdan/sh`)**, not regex. The dangerous path **fails closed**.

**Tech Stack:** Go 1.26 · `mvdan.cc/sh/v3` · `modernc.org/sqlite` (pure-Go) · `github.com/santhosh-tekuri/jsonschema/v6` · stdlib `encoding/json`, `flag`, `regexp`, `embed`.

## Global Constraints

- **Module:** `github.com/lucasngucii/argus`. Go **1.26**. **`CGO_ENABLED=0` always** (mandates `modernc.org/sqlite`).
- **`Classify` is pure and never panics:** no `os.*`, no time, no globals; policy-supplied regex compiled with `regexp.Compile` (never `MustCompile`) — a bad regex fails **closed** (escalate), never crashes. `Gate` wraps everything in a `recover` that fail-closes.
- **Fail-closed, scoped to danger:** on any internal error (payload/AST/policy/regex), escalate **only when a dangerous verb/token is visible**; a provably-benign command still `allow`s (matches spec §1.3). Never silent-allow a dangerous command.
- **`safe` is never logged**; `low`/`medium`/`high` are.
- **`high` is a non-bypassable floor:** an `AlwaysHigh` match (built-in floor **or** a policy rule with `alwaysHigh:true`) can never be downgraded by the allowlist. The engine keys non-downgradability off `Rule.AlwaysHigh`, not off which slice a rule came from.
- **Interactive vs non-interactive modes:** only `default` and `plan` prompt the user. `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions` do **not** reliably prompt → for them `medium → deny` (never `ask`), so `medium`/`high` never pass silently. Empty/unknown mode ⇒ treat as `default`.
- **Commit identity:** author & committer `lucasngucii <lucasalehwork@gmail.com>`; **never** a `Co-Authored-By: Claude` trailer.
- **Paths:** `~/.argus/` (`argus.db`, `policy.json`); hook wires into `~/.claude/settings.json`.

## File Structure

```
argus/
  go.mod
  Makefile
  cmd/argus/main.go                 # subcommand dispatch
  internal/hook/payload.go          # PreToolUse payload types + parse
  internal/shellast/parse.go        # mvdan/sh → argv, prefix-unwrap, pipes, redirects, obfuscation
  internal/policy/policy.go         # types (named, json-tagged), load, validate
  internal/policy/defaults.go       # embedded default policy + always-high floor + self-protect
  internal/policy/schema.json       # JSON Schema (embedded), enumerates severity
  internal/classify/match.go        # single-rule matcher over AST facts (regexp.Compile)
  internal/classify/scorers.go      # built-in scorers (rm_target, git_danger)
  internal/classify/classify.go     # pure Classify — floor, escalation, allowlist, fail-closed
  internal/verdict/verdict.go       # severity→verdict (mode-aware) + hookSpecificOutput
  internal/store/store.go           # SQLite: schema, WAL+_txlock=immediate, insert, versions, aggregates
  internal/cli/{gate,init,doctor,test,explain,stats}.go
  testdata/golden.jsonl             # {command,tool,cwd,mode → expected severity}
  testdata/evasion.jsonl            # obfuscation variants that MUST stay caught
```

---

### Task 1: Project scaffold

**Files:** Create `go.mod`, `Makefile`, `cmd/argus/main.go`, `internal/version/version.go`, `internal/version/version_test.go`
**Interfaces — Produces:** `version.String() string`; `main` dispatching `os.Args[1]`.

- [ ] **Step 1: Failing test**
```go
// internal/version/version_test.go
package version
import "testing"
func TestStringIsSemver(t *testing.T) {
	if g := String(); g == "" || g[0] < '0' || g[0] > '9' {
		t.Fatalf("version %q not semver-looking", g)
	}
}
```
- [ ] **Step 2: Run → FAIL** (`go test ./internal/version/` — no module).
- [ ] **Step 3: Implement**
```go
// go.mod
module github.com/lucasngucii/argus

go 1.26
```
```go
// internal/version/version.go
package version
func String() string { return "0.1.0-dev" }
```
```go
// cmd/argus/main.go
package main

import (
	"fmt"
	"os"

	"github.com/lucasngucii/argus/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	// gate|init|doctor|test|explain|stats wired in later tasks
	case "version", "--version", "-v":
		fmt.Println("argus", version.String())
	default:
		usage()
		os.Exit(2)
	}
}
func usage() { fmt.Fprintln(os.Stderr, "usage: argus <gate|init|doctor|test|explain|stats|version>") }
```
```makefile
export CGO_ENABLED=0
build: ; go build -o bin/argus ./cmd/argus
test: ; go test ./...
bench: ; go test -run=x -bench=. ./...
```
- [ ] **Step 4: Run → PASS**; `go vet ./...` clean.
- [ ] **Step 5: Commit** `chore: scaffold argus Go module and subcommand dispatch`.

---

### Task 2: PreToolUse payload parsing

**Files:** Create `internal/hook/payload.go`, `internal/hook/payload_test.go`
**Interfaces — Produces:**
- `type ToolInput struct { Command, FilePath string }` (json `command`,`file_path`)
- `type Payload struct { SessionID, TranscriptPath, CWD, PermissionMode, HookEventName, ToolName, ToolUseID string; ToolInput ToolInput }`
- `func Parse(r io.Reader) (Payload, error)`
- `func (p Payload) Subject() string` — `Command` for Bash, else `FilePath`.

- [ ] **Step 1: Failing tests**
```go
// internal/hook/payload_test.go
package hook
import ("strings"; "testing")
func TestParseBash(t *testing.T) {
	p, err := Parse(strings.NewReader(`{"tool_name":"Bash","permission_mode":"default","cwd":"/tmp","tool_input":{"command":"sudo rm -rf /"}}`))
	if err != nil { t.Fatal(err) }
	if p.ToolName != "Bash" || p.Subject() != "sudo rm -rf /" { t.Fatalf("%+v", p) }
}
func TestParseWriteSubjectIsPath(t *testing.T) {
	p, _ := Parse(strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":"/etc/hosts"}}`))
	if p.Subject() != "/etc/hosts" { t.Fatalf("subject=%q", p.Subject()) }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the two structs with json tags, `Parse` via `json.NewDecoder`, `Subject()` as specified.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(hook): parse PreToolUse stdin payload`.

---

### Task 3: Shell AST facts — prefix-unwrap, obfuscation, unresolved-arg flagging

**Files:** Create `internal/shellast/parse.go`, `internal/shellast/parse_test.go`
**Interfaces — Produces:**
- `type Cmd struct { Name string; Args []string; Resolved bool }`
- `type Facts struct { Commands []Cmd; PipeSinks []string; Redirects []string; RawTokens []string; Obfuscated bool; ParseOK bool }`
- `func Extract(command string) Facts` — never errors. Behaviors (each is a fix for a review finding):
  1. **Prefix-unwrap** — a command whose name is a known wrapper (`sudo env doas nohup nice time timeout xargs`) is unwrapped so the wrapped command surfaces as its **own** `Cmd` (append both the wrapper and the inner command). *(fixes `sudo rm -rf /` → medium.)*
  2. **Mixed-part word ⇒ obfuscated** — a word combining `*syntax.Lit` with `*syntax.ParamExp`/`*syntax.CmdSubst`/quoted parts (e.g. `rm$IFS-rf$IFS/`) is unresolvable: set `Obfuscated=true`, mark that `Cmd.Resolved=false`. Never silently concatenate only the literals.
  3. **Unresolved `$VAR` in any position** (name or arg) ⇒ `Resolved=false` + `Obfuscated=true`.
  4. **`eval` / decoder-piped-into-shell / parse failure** ⇒ `Obfuscated=true`; on parse failure also `ParseOK=false` and populate `RawTokens` (whitespace split) for a fail-closed scan.

- [ ] **Step 1: Failing tests**
```go
// internal/shellast/parse_test.go
package shellast
import "testing"

func nameOf(f Facts, i int) string { if i < len(f.Commands) { return f.Commands[i].Name }; return "" }

func TestPrefixUnwrap(t *testing.T) {
	f := Extract("sudo rm -rf /")
	if !hasCmd(f, "rm") { t.Fatalf("sudo not unwrapped: %+v", f.Commands) }
}
func TestIFSObfuscationFlagged(t *testing.T) {
	f := Extract("rm$IFS-rf$IFS/")
	if !f.Obfuscated { t.Fatal("$IFS-split word must flag obfuscated") }
}
func TestVarIndirectionResolves(t *testing.T) {
	if !hasCmd(Extract("X=rm; $X -rf /"), "rm") { t.Fatal("VAR=rm;$X must resolve to rm") }
}
func TestUnresolvedArgFlagged(t *testing.T) {
	if !Extract("rm -rf $TARGET").Obfuscated { t.Fatal("unresolved $TARGET arg must flag obfuscated") }
}
func TestPipeSink(t *testing.T) {
	f := Extract("curl x | sh")
	if len(f.PipeSinks) == 0 || f.PipeSinks[len(f.PipeSinks)-1] != "sh" { t.Fatalf("sinks=%v", f.PipeSinks) }
}
func TestBase64PipeShellObfuscated(t *testing.T) {
	if !Extract("echo cm0K | base64 -d | sh").Obfuscated { t.Fatal("base64|sh must flag obfuscated") }
}
func TestParseFailurePopulatesRaw(t *testing.T) {
	f := Extract("`unterminated")
	if f.ParseOK || len(f.RawTokens) == 0 || !f.Obfuscated { t.Fatalf("parse-fail path wrong: %+v", f) }
}
// hasCmd helper defined in parse.go test-support or inline
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — parse with `syntax.NewParser().Parse`; on error set `ParseOK=false`, `Obfuscated=true`, fill `RawTokens`, return. Otherwise recursively walk statements in source order maintaining a `vars map[string]string` from `*syntax.Assign`. For each `*syntax.CallExpr`: build the command word via a `resolveWord(word, vars) (text string, resolved bool)` that (a) returns `(varValue,true)` for a single resolvable `ParamExp`, (b) returns `("",false)` for a single unresolved `ParamExp`, (c) returns `(concatLits, false)` **and marks obfuscated** for a multi-part word mixing lits with non-lits, (d) returns `(lit,true)` for a pure literal. If the resolved name is a known wrapper prefix, also emit a second `Cmd` from `Args` (recurse one level). Detect `eval`, and decoder(`base64|xxd|openssl`)-into-shell pipes. `hasCmd(f, name)` returns true if any `Commands[i].Name == name`.
- [ ] **Step 4: Run → PASS** (`go get mvdan.cc/sh/v3`).
- [ ] **Step 5: Commit** `feat(shellast): AST facts with prefix-unwrap, $IFS/var obfuscation, fail-closed raw scan`.

---

### Task 4: Policy types, loader, embedded defaults + floor + self-protect

**Files:** Create `internal/policy/policy.go`, `internal/policy/defaults.go`, `internal/policy/schema.json`, `internal/policy/policy_test.go`
**Interfaces — Produces (named types, json-tagged — no anonymous structs, no dead fields):**
```go
type Match struct {
	Cmd         []string `json:"cmd,omitempty"`
	Flags       []string `json:"flags,omitempty"`
	ArgMatches  string   `json:"argMatches,omitempty"`   // regexp on joined args
	ArgsContain []string `json:"argsContain,omitempty"`  // ANY-of, against resolved args
	PipesInto   []string `json:"pipesInto,omitempty"`
	RedirectsTo string   `json:"redirectsTo,omitempty"`
	TargetScorer string  `json:"targetScorer,omitempty"`
	Raw         string   `json:"raw,omitempty"`          // regexp on subject (escape hatch)
}
type Condition struct { CWDMatches string `json:"cwdMatches,omitempty"` }
type Escalation struct { When Condition `json:"when"`; To string `json:"to"` }
type Rule struct {
	ID string `json:"id"`; Enabled bool `json:"enabled"`
	AlwaysHigh bool `json:"alwaysHigh,omitempty"`
	Allow bool `json:"allow,omitempty"`           // allowlist/downgrade entry (Task 7)
	Tool []string `json:"tool"`
	Match Match `json:"match"`
	Severity string `json:"severity,omitempty"`   // safe|low|medium|high (schema-enumerated)
	Reason string `json:"reason"`
	ContextEscalation []Escalation `json:"contextEscalation,omitempty"`
}
type Defaults struct { Shadow bool `json:"shadow,omitempty"` }   // OnError removed: escalation is invariant, not a knob
type Policy struct { Version int `json:"version"`; Meta map[string]string `json:"meta,omitempty"`; Defaults Defaults `json:"defaults,omitempty"`; Rules []Rule `json:"rules"` }
```
- `func Load(path string) (Policy, error)` / `func loadBytes(b []byte) (Policy, error)` — schema-validate then unmarshal.
- `func Default() Policy` — seed rules. **Does NOT embed `Floor()`** (the classifier owns the floor pass; avoids double-eval).
- `func Floor() []Rule` — built-in always-high rules **plus** `SelfProtectRules()`. Home-independent.

- [ ] **Step 1: Failing tests**
```go
// internal/policy/policy_test.go
package policy
import "testing"
func TestFloorAllHigh(t *testing.T) {
	if len(Floor()) == 0 { t.Fatal("empty floor") }
	for _, r := range Floor() { if !r.AlwaysHigh || r.Severity != "high" { t.Fatalf("floor not always-high: %+v", r) } }
}
func TestDefaultDoesNotEmbedFloor(t *testing.T) {
	for _, r := range Default().Rules { if r.AlwaysHigh { t.Fatal("Default() must not embed floor rules (classifier owns them)") } }
}
func TestSchemaRejectsBadSeverity(t *testing.T) {
	if _, err := loadBytes([]byte(`{"version":1,"rules":[{"id":"x","enabled":true,"tool":["Bash"],"severity":"hgih","reason":"typo"}]}`)); err == nil {
		t.Fatal("schema must reject severity typo")
	}
}
func TestSchemaRejectsNonIntVersion(t *testing.T) {
	if _, err := loadBytes([]byte(`{"version":"nope","rules":[]}`)); err == nil { t.Fatal("version must be int") }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement.** `schema.json` (draft 2020-12): `version` integer required; `rules` array; `severity` `enum:["safe","low","medium","high"]`; `tool` array of string. `Floor()` returns the catastrophe rules (all `AlwaysHigh:true, Severity:"high"`):
```go
// internal/policy/defaults.go (Floor excerpt)
func Floor() []Rule {
	f := []Rule{
		{ID: "disk-format", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{Cmd: []string{"dd", "mkfs", "fdisk", "diskutil"}, ArgMatches: `if=|erase`}, Reason: "disk/format"},
		{ID: "forkbomb", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{Raw: `:\(\)\s*\{`}, Reason: "forkbomb"},
		{ID: "pipe-to-shell", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{PipesInto: []string{"sh", "bash", "zsh"}}, Reason: "pipe-to-shell"},
		{ID: "db-destructive", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{ArgMatches: `(?i)\b(drop|truncate)\s+(table|database)\b|\bdelete\s+from\b|\.drop\(\)|deletemany`}, Reason: "DB destructive"},
	}
	return append(f, SelfProtectRules()...)
}
```
`Default()` seed rules (note the **precise** git rule and the opaque-escalation rule — fixes false-positive + §8 gaps):
```go
func Default() Policy {
	p := Policy{Version: 1, Meta: map[string]string{"seed": "agent-review v2"}}
	p.Rules = []Rule{
		{ID: "rm-recursive", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "rm -r directory",
			Match: Match{Cmd: []string{"rm"}, Flags: []string{"r"}, TargetScorer: "rm_target"},
			ContextEscalation: []Escalation{{When: Condition{CWDMatches: "prod"}, To: "high"}}},
		{ID: "git-danger", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "git force/hard-reset/clean",
			Match: Match{Cmd: []string{"git"}, TargetScorer: "git_danger"}},   // precise: only --force/reset --hard/clean -f
		{ID: "sudo", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "sudo",
			Match: Match{Cmd: []string{"sudo"}}},
		{ID: "docker-service", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "docker service/prod op",
			Match: Match{Cmd: []string{"docker"}, ArgsContain: []string{"service", "stack", "swarm", "prune", "down"}}},
		{ID: "db-write", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "DB client write",
			Match: Match{Cmd: []string{"psql", "mongosh", "mongo", "clickhouse-client"},
				ArgMatches: `(?i)\b(insert\s+into|update\s|create\s+(table|database)|alter\s|grant\s)\b`}},
		{ID: "opaque-exec", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "opaque script/subshell — cannot inspect",
			Match: Match{ArgMatches: `(?i)\b(bash|sh|zsh)\s+[^-|;&]+\.sh\b|-c\s`}},
	}
	return p
}
```
- [ ] **Step 4: Run → PASS** (`go get github.com/santhosh-tekuri/jsonschema/v6`).
- [ ] **Step 5: Commit** `feat(policy): named json-tagged types, schema-enum severity, floor+self-protect, precise defaults`.

---

### Task 5: Single-rule matcher (regexp.Compile, fail-closed)

**Files:** Create `internal/classify/match.go`, `internal/classify/match_test.go`
**Interfaces — Produces:**
- `func Matches(tool, subject string, f shellast.Facts, r policy.Rule) (matched bool, regexErr bool)` — regexErr=true when a policy regex fails to compile (caller escalates, per fail-closed).
- Field semantics (AND across populated fields): `Cmd` any-of against every `Facts.Commands[i].Name` (so prefix-unwrapped inner commands count); `Flags` require a short-flag cluster containing the letter (parse `-rf` as `{r,f}`, ignore long `--force`); `ArgsContain` **ANY-of** against resolved args of matched commands; `ArgMatches`/`Raw` via `regexp.Compile` (bad regex → `regexErr=true`); `PipesInto`/`RedirectsTo` against `Facts.PipeSinks`/`Facts.Redirects`.

- [ ] **Step 1: Failing tests**
```go
// internal/classify/match_test.go
package classify
import ("testing"; "github.com/lucasngucii/argus/internal/policy"; "github.com/lucasngucii/argus/internal/shellast")
func m(tool, subj string, mt policy.Match) bool {
	ok, _ := Matches(tool, subj, shellast.Extract(subj), policy.Rule{Tool: []string{tool}, Match: mt}); return ok
}
func TestMatchCmdIncludesUnwrapped(t *testing.T) {
	if !m("Bash", "sudo rm -rf /", policy.Match{Cmd: []string{"rm"}, Flags: []string{"r"}}) { t.Fatal("must see rm inside sudo") }
}
func TestFlagIgnoresLongOptions(t *testing.T) {
	if m("Bash", "curl --retry x", policy.Match{Cmd: []string{"curl"}, Flags: []string{"r"}}) { t.Fatal("--retry must not satisfy flag r") }
}
func TestArgsContainAnyOf(t *testing.T) {
	if !m("Bash", "docker service ls", policy.Match{Cmd: []string{"docker"}, ArgsContain: []string{"service", "down"}}) { t.Fatal("any-of") }
}
func TestBadRegexReportsError(t *testing.T) {
	_, rerr := Matches("Bash", "x", shellast.Extract("x"), policy.Rule{Tool: []string{"Bash"}, Match: policy.Match{ArgMatches: "("}})
	if !rerr { t.Fatal("invalid regex must report regexErr, not panic") }
}
func TestToolScoping(t *testing.T) {
	if m("Write", "rm", policy.Match{Cmd: []string{"rm"}}) { t.Fatal("Bash-only must not match Write") }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** as specified. Never `MustCompile`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(classify): AST matcher — unwrapped cmds, short-flag parse, any-of args, regexp.Compile fail-closed`.

---

### Task 6: Built-in scorers (`rm_target`, `git_danger`)

**Files:** Create `internal/classify/scorers.go`, `internal/classify/scorers_test.go`
**Interfaces — Produces:**
- `func ScoreRmTarget(f shellast.Facts) string` — `high|medium|low`. **An unresolved/empty target ⇒ `high`** (can't prove safe).
- `func ScoreGitDanger(f shellast.Facts) string` — `medium` only for `push --force`/`push -f`/`push --force-with-lease`, `reset --hard`, `clean -*f*`; else `safe`.
- `var Scorers = map[string]func(shellast.Facts) string{"rm_target": ScoreRmTarget, "git_danger": ScoreGitDanger}`

- [ ] **Step 1: Failing tests**
```go
// internal/classify/scorers_test.go
package classify
import ("testing"; "github.com/lucasngucii/argus/internal/shellast")
func TestRmTarget(t *testing.T) {
	for cmd, want := range map[string]string{
		"rm -rf /": "high", "rm -rf ~": "high", "rm -rf /etc/x": "high", "rm -rf ..": "high",
		"rm -rf ./build": "low", "rm -rf /tmp/scratch": "low", "rm -rf node_modules": "low",
		"rm -rf src/components": "medium",
	} { if g := ScoreRmTarget(shellast.Extract(cmd)); g != want { t.Errorf("%s: %s!=%s", cmd, g, want) } }
}
func TestRmUnresolvedTargetHigh(t *testing.T) {
	if ScoreRmTarget(shellast.Extract("rm -rf $TARGET")) != "high" { t.Fatal("unresolved target must be high") }
}
func TestGitDanger(t *testing.T) {
	for cmd, want := range map[string]string{
		"git push --force": "medium", "git reset --hard HEAD~1": "medium", "git clean -fd": "medium",
		"git push origin main": "safe", "git reset HEAD file": "safe", "git clean -n": "safe",
	} { if g := ScoreGitDanger(shellast.Extract(cmd)); g != want { t.Errorf("%s: %s!=%s", cmd, g, want) } }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement.** `rm_target`: iterate non-flag args of any `rm` command; if a command is `Resolved=false` or a target is empty ⇒ `high`. Targets `/`,`~`,`$HOME`, bare `/Users/<x>`/`/home/<x>`, system dirs, or containing `..` ⇒ `high`; scratch/tmp/`./…`/`node_modules|build|dist|coverage` ⇒ `low`; else `medium`. `git_danger`: inspect the `git` command's args for the qualified-destructive combos only.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(classify): rm_target (unresolved→high) and precise git_danger scorers`.

---

### Task 7: Pure classifier — floor by AlwaysHigh, obfuscation→high, allowlist downgrade

**Files:** Create `internal/classify/classify.go`, `internal/classify/classify_test.go`
**Interfaces — Produces:**
- `type Decision struct { Severity, RuleID, Reason string; Obfuscated bool }`
- `func Classify(p hook.Payload, pol policy.Policy) Decision` — pure, no panic, no `os.*`.
- `func rank(s string) int` — `safe<low<medium<high`; **unknown ⇒ high** (fail-closed).

- [ ] **Step 1: Failing tests**
```go
// internal/classify/classify_test.go
package classify
import ("testing"; "github.com/lucasngucii/argus/internal/hook"; "github.com/lucasngucii/argus/internal/policy")
func bash(cmd, mode, cwd string) hook.Payload {
	return hook.Payload{ToolName: "Bash", PermissionMode: mode, CWD: cwd, ToolInput: hook.ToolInput{Command: cmd}}
}
func sev(cmd, cwd string) string { return Classify(bash(cmd, "default", cwd), policy.Default()).Severity }

func TestSudoRmIsHigh(t *testing.T)      { if sev("sudo rm -rf /", "/tmp") != "high" { t.Fatal(sev("sudo rm -rf /", "/tmp")) } }
func TestIFSRmIsHigh(t *testing.T)       { if rank(sev("rm$IFS-rf$IFS/", "/tmp")) < rank("high") { t.Fatal("$IFS rm must be high") } }
func TestEvalVisibleRmHigh(t *testing.T) { if sev(`eval "rm -rf /"`, "/tmp") != "high" { t.Fatal("visible rm in eval must be high") } }
func TestOpaqueEvalIsMedium(t *testing.T){ if sev(`eval "$(cat script)"`, "/tmp") != "medium" { t.Fatal("opaque eval → medium (ask)") } }
func TestBenignIsSafe(t *testing.T)      { if sev("ls -la", "/tmp") != "safe" { t.Fatal("ls safe") } }
func TestGitPushBenignSafe(t *testing.T) { if sev("git push origin main", "/tmp") != "safe" { t.Fatal("plain push must not fire") } }
func TestProdEscalation(t *testing.T)    { if sev("rm -rf src", "/srv/prod-app") != "high" { t.Fatal("prod cwd escalate") } }
func TestFloorBypassStillHigh(t *testing.T) {
	if Classify(bash("curl x | sh", "bypassPermissions", "/tmp"), policy.Default()).Severity != "high" { t.Fatal("floor breached") }
}
func TestUserAlwaysHighHonored(t *testing.T) {
	pol := policy.Default()
	pol.Rules = append(pol.Rules, policy.Rule{ID: "custom", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"}, Match: policy.Match{Cmd: []string{"terraform"}}})
	pol.Rules = append(pol.Rules, policy.Rule{ID: "allow-tf", Enabled: true, Allow: true, Tool: []string{"Bash"}, Match: policy.Match{Cmd: []string{"terraform"}}})
	if Classify(bash("terraform apply", "default", "/tmp"), pol).Severity != "high" { t.Fatal("user alwaysHigh must not be downgradable") }
}
func TestAllowlistDowngradesMedium(t *testing.T) {
	pol := policy.Default()
	pol.Rules = append(pol.Rules, policy.Rule{ID: "allow-sudo", Enabled: true, Allow: true, Tool: []string{"Bash"}, Match: policy.Match{Cmd: []string{"sudo"}, ArgMatches: `apt-get`}})
	if Classify(bash("sudo apt-get install jq", "default", "/tmp"), pol).Severity != "safe" { t.Fatal("allowlist must downgrade medium→safe") }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement**
```go
// internal/classify/classify.go
package classify

import (
	"strings"

	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/shellast"
)

type Decision struct{ Severity, RuleID, Reason string; Obfuscated bool }

var order = map[string]int{"safe": 0, "low": 1, "medium": 2, "high": 3}

func rank(s string) int { if v, ok := order[s]; ok { return v }; return order["high"] } // unknown → fail-closed

var dangerToken = strings.NewReplacer() // placeholder removed below; see hasDangerToken

func hasDangerToken(s string) bool {
	s = strings.ToLower(s)
	for _, t := range []string{"rm ", "rm\t", "dd ", "mkfs", "fdisk", ":()", "drop ", "delete from", "> /", "chmod", "chown", "mkfs", "shutdown", "reboot"} {
		if strings.Contains(s, t) { return true }
	}
	return false
}

func Classify(p hook.Payload, pol policy.Policy) Decision {
	f := shellast.Extract(p.Subject())
	best := Decision{Severity: "safe", Reason: "safe"}
	floorHit := false
	regexBroke := false

	consider := func(rules []policy.Rule) {
		for _, r := range rules {
			if !r.Enabled || r.Allow { continue }
			ok, rerr := Matches(p.ToolName, p.Subject(), f, r)
			if rerr { regexBroke = true }
			if !ok { continue }
			s := r.Severity
			if r.Match.TargetScorer != "" {
				if sc, has := Scorers[r.Match.TargetScorer]; has { s = sc(f) }
			}
			s = applyContext(s, r, p.CWD)
			if r.AlwaysHigh { s = "high"; floorHit = true }
			if rank(s) > rank(best.Severity) {
				best = Decision{Severity: s, RuleID: r.ID, Reason: r.Reason, Obfuscated: f.Obfuscated}
			}
		}
	}
	consider(policy.Floor()) // built-in floor (owns its pass; Default() does not embed it)
	consider(pol.Rules)      // user/default rules (may carry AlwaysHigh too)

	// Obfuscation / parse-failure escalation, scoped to visible danger.
	if f.Obfuscated || !f.ParseOK {
		visibleDanger := hasDangerToken(p.Subject())
		for _, tok := range f.RawTokens { if hasDangerToken(tok + " ") { visibleDanger = true } }
		bump := "medium"
		if visibleDanger || floorHit || rank(best.Severity) >= rank("medium") { bump = "high" }
		if rank(bump) > rank(best.Severity) {
			best.Severity, best.Obfuscated = bump, true
			if best.Reason == "safe" { best.Reason = "obfuscated/unparseable" }
		}
	}

	// A broken policy regex must not silently drop a rule → escalate a visible-danger command.
	if regexBroke && hasDangerToken(p.Subject()) && rank(best.Severity) < rank("medium") {
		best = Decision{Severity: "medium", Reason: "policy regex error (fail-closed)"}
	}

	// Allowlist downgrade — never below a floor hit.
	if !floorHit {
		best = applyAllowlist(best, p, f, pol)
	}
	return best
}

func applyContext(s string, r policy.Rule, cwd string) string {
	for _, e := range r.ContextEscalation {
		if e.When.CWDMatches != "" && pathHasSegment(cwd, e.When.CWDMatches) && rank(e.To) > rank(s) {
			s = e.To
		}
	}
	return s
}
// pathHasSegment matches a whole path segment (so "prod" does not match "/reproduce/").
func pathHasSegment(path, needle string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == needle || strings.HasPrefix(seg, needle+"-") || strings.HasSuffix(seg, "-"+needle) { return true }
	}
	return false
}

func applyAllowlist(best Decision, p hook.Payload, f shellast.Facts, pol policy.Policy) Decision {
	for _, r := range pol.Rules {
		if !r.Enabled || !r.Allow { continue }
		if ok, _ := Matches(p.ToolName, p.Subject(), f, r); ok {
			return Decision{Severity: "safe", RuleID: r.ID, Reason: "allowlisted: " + r.Reason}
		}
	}
	return best
}
```
*(Delete the `dangerToken` placeholder line; it is shown only to flag that no such global is needed — `hasDangerToken` is the real helper.)* Fix `pathHasSegment` so `TestProdEscalation` (`/srv/prod-app`) matches via the `prefix"-"` arm.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(classify): pure classifier — AlwaysHigh floor, scoped obfuscation→high, allowlist downgrade, fail-closed rank`.

---

### Task 8: Self-protection rules (home-independent)

**Files:** Modify `internal/policy/defaults.go` (add `SelfProtectRules`); Create `internal/classify/selfprotect_test.go`
**Interfaces — Produces:** `func SelfProtectRules() []policy.Rule` — **no args**, home-independent suffix regex; every rule `AlwaysHigh:true, Severity:"high"`.

- [ ] **Step 1: Failing test**
```go
// internal/classify/selfprotect_test.go
package classify
import ("testing"; "github.com/lucasngucii/argus/internal/hook"; "github.com/lucasngucii/argus/internal/policy")
func TestCannotDisarm(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/Users/x/.claude/settings.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -f /home/y/.argus/policy.json"}},
		{ToolName: "Edit", ToolInput: hook.ToolInput{FilePath: "/root/.argus/argus.db"}},
	}
	for _, p := range cases {
		if Classify(p, pol).Severity != "high" { t.Fatalf("self-protection breach: %+v", p.ToolInput) }
	}
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — rules matching `Raw`/`RedirectsTo` regex `\.claude/settings(\.local)?\.json$`, `\.argus/(policy\.json|argus\.db)`, and the hook/binary path, for tools `Bash|Write|Edit`. No `os.UserHomeDir()` anywhere.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(policy): home-independent self-protection rules (always-high)`.

---

### Task 9: Severity → verdict (mode-aware) + hookSpecificOutput

**Files:** Create `internal/verdict/verdict.go`, `internal/verdict/verdict_test.go`
**Interfaces — Produces:**
- `func Map(severity, permissionMode string) string` — returns `allow|ask|deny`.
- `func Emit(w io.Writer, verdict, reason string) error`.
- Rule: `safe|low`→allow; `high`→deny; `medium`→ `ask` **only** when mode ∈ {`default`,`plan`,``}, else **deny** (`acceptEdits`,`auto`,`dontAsk`,`bypassPermissions`).

- [ ] **Step 1: Failing tests**
```go
// internal/verdict/verdict_test.go
package verdict
import ("bytes"; "strings"; "testing")
func TestMap(t *testing.T) {
	for _, c := range []struct{ sev, mode, want string }{
		{"low", "default", "allow"}, {"medium", "default", "ask"}, {"medium", "plan", "ask"},
		{"medium", "acceptEdits", "deny"}, {"medium", "dontAsk", "deny"}, {"medium", "auto", "deny"},
		{"medium", "bypassPermissions", "deny"}, {"high", "default", "deny"},
	} { if g := Map(c.sev, c.mode); g != c.want { t.Errorf("%s/%s: %s!=%s", c.sev, c.mode, g, c.want) } }
}
func TestEmit(t *testing.T) {
	var b bytes.Buffer; _ = Emit(&b, "deny", "pipe-to-shell")
	if !strings.Contains(b.String(), `"permissionDecision":"deny"`) || !strings.Contains(b.String(), `"hookEventName":"PreToolUse"`) {
		t.Fatalf("bad emit: %s", b.String())
	}
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** as specified; `Emit` marshals `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":V,"permissionDecisionReason":"argus: "+reason}}` (+`"suppressOutput":true` for allow).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(verdict): mode-aware medium→deny in non-interactive modes + hookSpecificOutput`.

---

### Task 10: SQLite store (WAL + `_txlock=immediate`, versions, aggregates, process-level concurrency test)

**Files:** Create `internal/store/store.go`, `internal/store/store_test.go`
**Interfaces — Produces:**
- `type Row struct { TS, Session, CWD, Tool, Command, File, Severity, Verdict, PermissionMode, RuleID, Harness string; PolicyVersion int; Obfuscation bool }`
- `func Open(path string) (*Store, error)` — DSN `file:PATH?_pragma=busy_timeout(3000)&_pragma=journal_mode(WAL)&_txlock=immediate`.
- `func (s *Store) Insert(r Row) error` (uses `BeginTx` → immediate write lock).
- `func (s *Store) Recent(limit int) ([]Row, error)`
- `func (s *Store) Counts() (map[string]int, error)` — `SELECT severity, COUNT(*) … GROUP BY severity` over full history (fixes partial-aggregate nit).
- `func (s *Store) InsertPolicyVersion(version int, author, note, policyJSON, hash string) error`

- [ ] **Step 1: Failing tests**
```go
// internal/store/store_test.go
package store
import ("os/exec"; "path/filepath"; "sync"; "testing")
func TestInsertRecentCounts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "a.db")); if err != nil { t.Fatal(err) }
	_ = s.Insert(Row{TS: "t", Severity: "high", Verdict: "deny"})
	_ = s.Insert(Row{TS: "t", Severity: "low", Verdict: "allow"})
	c, _ := s.Counts(); if c["high"] != 1 || c["low"] != 1 { t.Fatalf("counts=%v", c) }
}
// Real deployment model: many SEPARATE connections writing + a concurrent reader.
func TestProcessLevelConcurrencyNoBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	seed, _ := Open(path); _ = seed.Insert(Row{TS: "t", Severity: "low"})
	var wg sync.WaitGroup
	errc := make(chan error, 40)
	// 30 independent writer connections (proxy for separate processes)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w, e := Open(path); if e != nil { errc <- e; return }; errc <- w.Insert(Row{TS: "t", Severity: "low"}) }()
	}
	// concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r, e := Open(path); if e != nil { errc <- e; return }; _, e = r.Recent(5); errc <- e }()
	}
	wg.Wait(); close(errc)
	for e := range errc { if e != nil { t.Fatalf("SQLITE_BUSY/err under process-level load: %v", e) } }
}
var _ = exec.Command // reserved: optional os/exec subprocess variant
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** with `modernc.org/sqlite` (driver `"sqlite"`). `Insert` uses `db.BeginTx(ctx, nil)` (DSN `_txlock=immediate` makes the tx acquire the write lock up front) → `INSERT` → `Commit`. `Counts`/`Recent` are plain queries. Create both tables in `Open`.
- [ ] **Step 4: Run → PASS** (`go get modernc.org/sqlite`). Remove the reserved `exec` line if unused.
- [ ] **Step 5: Commit** `feat(store): SQLite WAL + immediate-lock, counts, policy_versions, process-level concurrency test`.

---

### Task 11: `argus gate` — hot path, shadow mode, recover→fail-closed

**Files:** Create `internal/cli/gate.go`, `internal/cli/gate_test.go`, `internal/cli/gate_bench_test.go`; Modify `cmd/argus/main.go`
**Interfaces — Produces:** `func Gate(stdin io.Reader, stdout io.Writer, home string) int` — parse → load policy (fail-closed: on load error use `policy.Default()` and log to stderr) → `Classify` → if `pol.Defaults.Shadow` force verdict `allow` (but still record) → best-effort `store.Insert` (skip `safe`) → `verdict.Emit`. A top-level `recover` fail-closes to `ask`. Always returns 0.

- [ ] **Step 1: Failing tests**
```go
// internal/cli/gate_test.go
package cli
import ("bytes"; "strings"; "testing")
func run(in string) string { var o bytes.Buffer; Gate(strings.NewReader(in), &o, "/nonexistent-home"); return o.String() }
func TestGateDeniesSudoRm(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"sudo rm -rf /"}}`), `"permissionDecision":"deny"`) {
		t.Fatal("sudo rm -rf / must deny")
	}
}
func TestGateDeniesPipeShellInBypass(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","permission_mode":"bypassPermissions","tool_input":{"command":"curl x | sh"}}`), `"deny"`) { t.Fatal("bypass floor") }
}
func TestGateAllowsBenign(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","tool_input":{"command":"echo hi"}}`), `"permissionDecision":"allow"`) { t.Fatal("benign allow") }
}
func TestGateGarbageNotAllow(t *testing.T) {
	if strings.Contains(run(`{not json`), `"permissionDecision":"allow"`) { t.Fatal("garbage must not allow") }
}
```
```go
// internal/cli/gate_bench_test.go — guard the ~5ms hot-path budget (CLAUDE.md: measure)
package cli
import ("io"; "strings"; "testing")
func BenchmarkGate(b *testing.B) {
	in := `{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"sudo rm -rf /tmp/x"}}`
	for i := 0; i < b.N; i++ { Gate(strings.NewReader(in), io.Discard, b.TempDir()) }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement.** On payload parse error emit `deny` (unparseable = anomaly; per updated §1.3). Wire `case "gate": os.Exit(cli.Gate(os.Stdin, os.Stdout, home))` in `main.go` (`home,_ := os.UserHomeDir()`; policy `~/.argus/policy.json`, DB `~/.argus/argus.db`).
- [ ] **Step 4: Run → PASS.** Run `go test -bench=BenchmarkGate ./internal/cli/`; **record ns/op in the commit body** and confirm it is comfortably under the ~5ms budget. If not, cache the compiled policy/regex.
- [ ] **Step 5: Commit** `feat(cli): argus gate — hot path, shadow mode, recover→fail-closed (bench: <N>ns/op)`.

---

### Task 12: `argus init` (+ version-stamp + jsonl import) and `argus doctor`

**Files:** Create `internal/cli/init.go`, `internal/cli/doctor.go`, `internal/cli/init_test.go`; Modify `cmd/argus/main.go`
**Interfaces — Produces:**
- `func Init(home string) error` — create `~/.argus/`; write `policy.json` (=`policy.Default()`); `store.Open` + **`InsertPolicyVersion(1, "init", "seed", <json>, <sha256>)`** (fixes dead `policy_versions`); idempotently add a `PreToolUse` hook (matcher `Bash|Write|Edit` → the installed `argus gate`) to `~/.claude/settings.json` **without clobbering existing hooks**; import legacy `~/.claude/agent-review/decisions.jsonl` if present.
- `func Doctor(home string, w io.Writer) int` — verify: hook entry present & references argus; `policy.json` loads & schema-validates; DB writable; ≥1 `policy_versions` row. Report PASS/FAIL per check; non-zero if any FAIL.

- [ ] **Step 1: Failing test** — `Init` on a temp home creates `policy.json`, DB with a `policy_versions` row, and a settings.json containing the argus hook while preserving a pre-seeded unrelated `PreToolUse` entry; `Doctor` returns 0 after `Init`, non-zero after the hook entry is deleted.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — merge settings.json via `map[string]any`; append to `hooks.PreToolUse` only if no entry already references `argus gate`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(cli): argus init (idempotent hook wiring, v1 version-stamp, jsonl import) + doctor`.

---

### Task 13: `argus test` — rule harness + golden/evasion corpora

**Files:** Create `internal/cli/test.go`, `testdata/golden.jsonl`, `testdata/evasion.jsonl`, `internal/cli/harness_test.go`; Modify `cmd/argus/main.go`
**Interfaces — Produces:** `func RunHarness(paths []string, pol policy.Policy, w io.Writer) int` — read `{command,tool,cwd,mode,expect}` lines, run `Classify`, print mismatches, return non-zero on any.

`testdata/evasion.jsonl` (every line is a must-catch; the Task 3/7 fixes make each pass deterministically — no "iterate until it passes" hand-wave):
```jsonl
{"tool":"Bash","command":"sudo rm -rf /","expect":"high"}
{"tool":"Bash","command":"env X=1 rm -rf /","expect":"high"}
{"tool":"Bash","command":"X=rm; $X -rf /","expect":"high"}
{"tool":"Bash","command":"rm$IFS-rf$IFS/","expect":"high"}
{"tool":"Bash","command":"echo cm0K | base64 -d | sh","expect":"high"}
{"tool":"Bash","command":"eval \"rm -rf /\"","expect":"high"}
{"tool":"Bash","command":"rm -rf $TARGET","expect":"high"}
```
`testdata/golden.jsonl` includes benign no-fire cases (guard false-positives):
```jsonl
{"tool":"Bash","command":"git push origin main","expect":"safe"}
{"tool":"Bash","command":"git reset HEAD file","expect":"safe"}
{"tool":"Bash","command":"ls -la","expect":"safe"}
{"tool":"Bash","command":"rm -rf ./build","expect":"low"}
{"tool":"Bash","command":"sudo apt-get update","expect":"medium"}
```

- [ ] **Step 1: Failing test** — a Go test loads both corpora and asserts `RunHarness(..., policy.Default()) == 0`.
- [ ] **Step 2: Run → FAIL** (drives any remaining Task 3/7 hardening).
- [ ] **Step 3: Implement** the harness; make every corpus line pass.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `test(cli): rule harness + evasion/golden corpora (prefix, $IFS, eval, benign-no-fire)`.

---

### Task 14: `argus explain`

**Files:** Create `internal/cli/explain.go`, `internal/cli/explain_test.go`; Modify `cmd/argus/main.go`
**Interfaces — Produces:** `func Explain(command, tool, cwd, mode string, pol policy.Policy, w io.Writer) int` — print AST facts (commands, pipes, obfuscated), firing `RuleID`, severity, and the mapped verdict.

- [ ] **Step 1: Failing test** — `Explain("sudo rm -rf /","Bash","/tmp","default",Default(),buf)` output contains `severity: high`, non-empty `rule:`, and `verdict: deny`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** via `Classify` + `verdict.Map` + facts dump.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(cli): argus explain — dry-run one command`.

---

### Task 15: `argus stats` (full-history aggregates + jsonl export)

**Files:** Create `internal/cli/stats.go`, `internal/cli/stats_test.go`; Modify `cmd/argus/main.go`
**Interfaces — Produces:** `func Stats(s *store.Store, w io.Writer, jsonl bool) int` — full-history severity counts (via `store.Counts`), deny count, distinct sessions, and recent `high`/`medium` rows; with `jsonl=true`, stream every decision as JSONL (spec §10 continuity export).

- [ ] **Step 1: Failing test** — insert 1 high + 2 low, assert output contains `high: 1` and `low: 2`; with `jsonl=true`, output has 3 JSON lines.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** via `store.Counts` + `store.Recent`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(cli): argus stats — full-history aggregates + --jsonl export`.

---

## Self-Review

**Spec coverage:** §1.1 floor (T4/T7/T9) · §1.2 evasion/AST (T3/T13) · §1.3 fail-closed incl. payload-parse→deny & benign-parse-fail→allow (T7/T11) · §1.4 self-protection + version-stamp (T8/T12) · §1.5 pure/testable/audit/shadow (T7/T10/T11/T13) · §3.2 DSL incl. `Allow`,`ArgsContain`,scorers (T4/T5/T6) · §3.3 store WAL/immediate/versions (T10) · §8 opaque→ask vs visible-danger→high (T4/T7) · §10 migration import + jsonl export (T12/T15). Deferred to later plans (disclosed, not gaps): `serve`, `replay` UI, npm distribution, MCP/multi-harness.

**Placeholder scan:** the two `var _ =` reserved lines (T7 `dangerToken`, T10 `exec`) are explicitly called out to be deleted in their steps; no "TBD/handle edge cases" remain; the former "iterate until it passes" (T13) is replaced by concrete Task 3/7 algorithms.

**Type consistency:** `hook.Payload`/`ToolInput`, `shellast.Facts`/`Cmd`(+`RawTokens`), `policy.{Match,Condition,Escalation,Rule(+Allow,AlwaysHigh),Defaults(Shadow only),Policy}`, `classify.{Decision,Classify,Matches(→bool,bool),Scorers}`, `verdict.{Map,Emit}`, `store.{Row,Insert,Recent,Counts,InsertPolicyVersion}` are used identically across producing/consuming tasks. `Floor()` is no-arg everywhere; `SelfProtectRules()` is no-arg.

**Ordering:** T1→T11 sequential; T12–T15 independent after T11.

---

## Changelog (rev 1 → rev 2), from two adversarial reviews

**Blocking fixed:** (B-sudo) prefix-unwrap so `sudo/env/… rm -rf /`→high [T3/T5]; (B-IFS) mixed Lit+ParamExp word flagged obfuscated so `rm$IFS-rf$IFS/`→high [T3]; (B-eval) obfuscation escalates to **high** when a dangerous token is visible, else medium [T7]; (B-allowlist) real `Allow` field + `applyAllowlist` downgrade, floor keyed off `AlwaysHigh` not slice identity [T4/T7]; (B-concurrency) test now uses separate connections + concurrent readers [T10].
**Should-fixed:** mode-aware `medium→deny` for all non-interactive modes [T9]; `regexp.Compile` (no panic) + `recover` [T5/T11]; home-independent `SelfProtectRules()` (purity) [T8]; DSN `_txlock=immediate` + `BeginTx` [T10]; `rank(unknown)→high` + schema severity enum [T4/T7]; unresolved-arg→high in `rm_target` [T6]; shadow mode implemented, `OnError` removed [T4/T11]; `ArgsContain` specified [T5]; precise `git_danger` scorer [T6]; parse-fail escalates only on visible danger [T7]; `policy_versions` written at init [T12]; segment-based cwd match [T7].
**Nits fixed:** removed dead `regexp` import [T7]; named+json-tagged structs [T4]; floor not double-evaluated [T4/T7]; short-flag vs long-option parsing [T5]; removed `Match.Obfuscation` [T4]; opaque-exec + bare-DB escalation rule [T4]; full-history `Counts` for stats [T10/T15]; jsonl export [T15]; hot-path benchmark added [T11]. `Scorers` map + `harness` column kept as conscious, spec-endorsed extension points.
