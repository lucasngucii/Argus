# Harness Adapter Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carve Argus's Claude-Code-specific edges (payload parse, verdict emit, hook wiring, doctor probe) into a per-harness seam without changing the pure classifier, so a later phase adds Codex/Gemini by filling in adapters.

**Architecture:** A new leaf package `internal/adapter` holds the hot-path seam (`Canonical`, `Parse`, `Emit`, `Outcome`) — it imports only `hook` + `verdict`, so no import cycle. The non-hot-path `Wire`/`Probe` dispatch switches live in package `cli` (next to the `wireHook`/`checkHook` helpers they call, which cannot move without a `cli → adapter → cli` cycle). A `--harness` flag selects the harness; absent/empty resolves to `claude-code` so existing installs keep working. `classify(payload, policy)` is untouched.

**Tech Stack:** Go 1.26, stdlib `flag`/`encoding/json`/`io`, existing `internal/{hook,verdict,policy,store,classify,cli}`.

**Spec:** `docs/superpowers/specs/2026-07-29-harness-adapter-seam-design.md` (read it; this plan implements it verbatim).

## Global Constraints

- Go **1.26**, **`CGO_ENABLED=0` always**. No new dependencies.
- `internal/classify` **must NOT change**. The five CLAUDE.md invariants hold (pure core; hot path never fails open; verdict independent of writes; `high` is a floor; self-protection stays high).
- The `adapter` package imports **only** `hook` and `verdict` (never `cli`/`policy`/`store`), keeping it a cycle-free leaf.
- Dispatch `switch name` matches **canonical** names only (`"claude-code"`); `""`/unknown fall to a fail-closed `default`. Never add `case ""` — `Canonical` is the single name authority.
- Conventional commits; identity **`lucasngucii <lucasalehwork@gmail.com>`**; **NO** `Co-Authored-By: Claude` trailer. One logical change per commit.
- TDD: failing test first, table-driven default, deterministic. The existing golden + evasion corpus must stay green after every task.

---

### Task 1: `adapter` package — `Canonical` + `Outcome`

**Files:**
- Create: `internal/adapter/adapter.go`
- Test: `internal/adapter/adapter_test.go`

**Interfaces:**
- Consumes: nothing (leaf).
- Produces: `adapter.Canonical(name string) (string, error)`; `adapter.Outcome{Verdict, Reason string}`. Both are used by Tasks 3–6.

- [ ] **Step 1: Write the failing test**

```go
package adapter

import "testing"

func TestCanonical(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "claude-code", false},          // bare `argus gate`, old install
		{"claude-code", "claude-code", false},
		{"codex", "", true},                 // not yet a known harness
		{"CLAUDE-CODE", "", true},           // case-sensitive; unknown
		{"claude", "", true},
	}
	for _, tt := range tests {
		got, err := Canonical(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("Canonical(%q) err=%v wantErr=%v", tt.in, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("Canonical(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/adapter/ -run TestCanonical`
Expected: FAIL (package/undefined `Canonical`, `Outcome`).

- [ ] **Step 3: Write minimal implementation**

```go
// Package adapter is the per-harness seam for the parts of the gate that are
// specific to the agent harness Argus is gating: parsing the hook payload and
// emitting the verdict. The pure classifier is harness-independent and lives
// elsewhere; only JSON-in and JSON-out belong here. It imports only hook and
// verdict so it stays a cycle-free leaf.
package adapter

import "fmt"

// Outcome is what an adapter serializes: the verdict Gate decided to emit
// (post-shadow — shadow mode sets Verdict to "allow") and its reason. It
// deliberately carries no payload, so an adapter cannot re-derive or override
// the verdict it was handed (keeps the `high` floor enforced in the pure core).
type Outcome struct {
	Verdict string // "allow" | "ask" | "deny"
	Reason  string
}

// Canonical resolves a --harness flag value to its stored/dispatched identity.
// "" (an old install's bare `argus gate`) and "claude-code" both map to
// "claude-code"; any other value is an unknown harness and errors. Callers use
// the returned string for BOTH dispatch and the store row, so a raw flag string
// is never persisted (a mislabelled row would be filtered out of replay/close-loop).
func Canonical(name string) (string, error) {
	switch name {
	case "", "claude-code":
		return "claude-code", nil
	default:
		return "", fmt.Errorf("unknown harness %q", name)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/adapter/`
Expected: PASS. Then `CGO_ENABLED=0 go build ./...`.

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/adapter.go internal/adapter/adapter_test.go
git commit -m "feat(adapter): Canonical name authority + Outcome type"
```

---

### Task 2: `adapter.Parse` — harness-dispatched payload parse

**Files:**
- Create: `internal/adapter/claudecode.go`
- Test: `internal/adapter/parse_test.go`

**Interfaces:**
- Consumes: `hook.Parse(io.Reader) (hook.Payload, error)`, `Canonical` (Task 1).
- Produces: `adapter.Parse(name string, r io.Reader) (hook.Payload, error)` — used by Gate (Task 4).

- [ ] **Step 1: Write the failing test**

```go
package adapter

import (
	"strings"
	"testing"
)

func TestParseDispatch(t *testing.T) {
	const payload = `{"tool_name":"Bash","tool_input":{"command":"ls"}}`

	// Parse receives an already-Canonical name (Gate resolves "" → "claude-code"
	// before calling), so it is fed canonical names only — never "".
	p, err := Parse("claude-code", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Parse(claude-code) err: %v", err)
	}
	if p.ToolName != "Bash" || p.ToolInput.Command != "ls" {
		t.Errorf("Parse(claude-code) got %+v", p)
	}

	if _, err := Parse("codex", strings.NewReader(payload)); err == nil {
		t.Error("Parse(unknown harness) must error, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/adapter/ -run TestParseDispatch`
Expected: FAIL (undefined `Parse`).

- [ ] **Step 3: Write minimal implementation**

Add to `internal/adapter/adapter.go` (dispatch):

```go
import (
	"fmt"
	"io"

	"github.com/lucasngucii/argus/internal/hook"
)

// Parse turns a harness's raw PreToolUse payload into the normalized
// hook.Payload the classifier consumes. Unknown name → fail-closed error.
func Parse(name string, r io.Reader) (hook.Payload, error) {
	switch name {
	case "claude-code":
		return claudecodeParse(r)
	default:
		return hook.Payload{}, fmt.Errorf("parse: unknown harness %q", name)
	}
}
```

Create `internal/adapter/claudecode.go`:

```go
package adapter

import (
	"io"

	"github.com/lucasngucii/argus/internal/hook"
)

// claudecodeParse decodes Claude Code's PreToolUse stdin JSON. Claude Code's
// payload IS the normalized shape, so this delegates straight to hook.Parse.
func claudecodeParse(r io.Reader) (hook.Payload, error) {
	return hook.Parse(r)
}
```

Note: `Parse` takes the already-Canonical name (Gate resolves it first), so the `case` is `"claude-code"` only; `""` never reaches here.

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/adapter/` then `CGO_ENABLED=0 go build ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/
git commit -m "feat(adapter): Parse dispatch — claude-code delegates to hook.Parse"
```

---

### Task 3: `adapter.Emit` — dispatched serialize + fail-closed exit code

**Files:**
- Modify: `internal/adapter/adapter.go`, `internal/adapter/claudecode.go`
- Test: `internal/adapter/emit_test.go`

**Interfaces:**
- Consumes: `verdict.Emit(io.Writer, verdict, reason string) error`, `Outcome` (Task 1).
- Produces: `adapter.Emit(name string, w io.Writer, o Outcome) int` — returns the process exit code (0 normal, 2 fail-closed). Used by Gate (Task 4).

- [ ] **Step 1: Write the failing test**

```go
package adapter

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/verdict"
)

// errWriter fails every write, to exercise the fail-closed exit code.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestEmitByteIdentityWithVerdict(t *testing.T) {
	for _, v := range []struct{ verdict, reason string }{
		{"allow", "safe"}, {"ask", "sudo"}, {"deny", "rm -rf /"},
	} {
		var got, want bytes.Buffer
		if code := Emit("claude-code", &got, Outcome{Verdict: v.verdict, Reason: v.reason}); code != 0 {
			t.Fatalf("Emit(%s) code=%d, want 0", v.verdict, code)
		}
		if err := verdict.Emit(&want, v.verdict, v.reason); err != nil {
			t.Fatal(err)
		}
		if got.String() != want.String() {
			t.Errorf("Emit(%s) = %q, want byte-identical %q", v.verdict, got.String(), want.String())
		}
	}
}

func TestEmitFailsClosedOnWriteError(t *testing.T) {
	if code := Emit("claude-code", errWriter{}, Outcome{Verdict: "deny", Reason: "x"}); code != 2 {
		t.Errorf("Emit on write failure code=%d, want 2 (fail-closed)", code)
	}
}

func TestEmitUnknownHarnessFailsClosedNoWrite(t *testing.T) {
	var buf bytes.Buffer
	code := Emit("codex", &buf, Outcome{Verdict: "deny", Reason: "x"})
	if code != 2 {
		t.Errorf("Emit(unknown) code=%d, want 2", code)
	}
	if buf.Len() != 0 {
		t.Errorf("Emit(unknown) wrote %q; must write nothing (cannot speak the protocol)", buf.String())
	}
}

func TestEmitDenyNeverBecomesAllow(t *testing.T) {
	var buf bytes.Buffer
	Emit("claude-code", &buf, Outcome{Verdict: "deny", Reason: "floored"})
	s := buf.String()
	if !strings.Contains(s, `"permissionDecision":"deny"`) {
		t.Errorf("deny Outcome must serialize as deny; got %q", s)
	}
	if strings.Contains(s, `"permissionDecision":"allow"`) || strings.Contains(s, `"permissionDecision":"ask"`) {
		t.Errorf("deny Outcome must never emit allow/ask; got %q", s)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/adapter/ -run TestEmit`
Expected: FAIL (undefined `Emit`).

- [ ] **Step 3: Write minimal implementation**

Add dispatch to `internal/adapter/adapter.go` (it needs **no new import** — `io`
is already present from Task 2, and the dispatch never references `verdict`; do
NOT add `verdict` here or `go build` fails with `imported and not used`):

```go
// Emit serializes o for the harness and returns the process exit code: 0 on a
// successful write, 2 when the write fails or the harness is unknown. Fail-closed
// via exit code 2 is the only portable "do not proceed" signal when we cannot
// write (or cannot speak) the harness's protocol — an unknown harness must not
// emit some other harness's format, which that harness would ignore while the
// tool runs. An adapter may only translate a verdict more-restrictive (allow →
// ask → deny), never looser.
func Emit(name string, w io.Writer, o Outcome) int {
	switch name {
	case "claude-code":
		return claudecodeEmit(w, o)
	default:
		return 2
	}
}
```

Add to `internal/adapter/claudecode.go`:

```go
import "github.com/lucasngucii/argus/internal/verdict" // add to imports

// claudecodeEmit writes Claude Code's hookSpecificOutput JSON. A failed write
// means Claude Code sees no stdout JSON and, in bypassPermissions, would run the
// tool unprompted — so a write failure fails closed via exit code 2.
func claudecodeEmit(w io.Writer, o Outcome) int {
	if err := verdict.Emit(w, o.Verdict, o.Reason); err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: emit verdict: %v\n", err)
		return 2
	}
	return 0
}
```

Add `"fmt"` and `"os"` to claudecode.go imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/adapter/` then `CGO_ENABLED=0 go build ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/
git commit -m "feat(adapter): Emit dispatch — fail-closed exit code, byte-identical claude JSON"
```

---

### Task 4: Rewire `Gate` through the seam + `--harness` flag

**Files:**
- Modify: `internal/cli/gate.go`
- Modify: `cmd/argus/main.go` (gate case — flag parse; lands in THIS commit)
- Modify: `internal/cli/gate_test.go` (**edit, do not replace** — thread the harness arg through the shared `run()` helper and preserve `TestGateShadowRecordsRealVerdictButEmitsAllow`; add the new tests here)
- Modify: `internal/cli/gate_bench_test.go` (update the 3-arg `Gate(...)` call to 4-arg)
- Modify: `internal/cli/stats.go` (refresh the stale `emitOrBlock` comment near line 81 to point at `adapter.Emit`)

**Critical (build-breaks otherwise):** widening `Gate`'s signature breaks every
existing 3-arg caller. Before writing new tests, migrate ALL of them:
- `gate_test.go`'s shared `run(in string)` helper (used by `TestGateDeniesSudoRm`,
  `TestGateAllowsBenign`, `TestGateGarbageNotAllow`, **and by `gate_mcp_edge_test.go`
  via `decision(run(...))`**). **Keep `run`'s signature `run(in string) string`** —
  do NOT add a parameter (that would force editing every caller across two files);
  just add the literal 4th arg inside: `Gate(strings.NewReader(in), &o,
  "/nonexistent-home", "claude-code")`. Do NOT delete `run()` or the MCP-edge tests
  lose their helper and stop compiling.
- `TestGateShadowRecordsRealVerdictButEmitsAllow` (its own `Gate(...)` call).
- `gate_bench_test.go:12` — the ~5ms hot-path budget guard.
Confirm `gate_mcp_edge_test.go` still compiles against the edited `run()`.

**Interfaces:**
- Consumes: `adapter.Canonical/Parse/Emit/Outcome` (Tasks 1–3), `classify.Classify`, `verdict.Map`, `store`.
- Produces: `cli.Gate(stdin io.Reader, stdout io.Writer, home, harness string) (code int)`.

**Context:** current `Gate(stdin, stdout, home) (code int)` (gate.go:27) does parse → classify → map → best-effort record → `emitOrBlock`. It has a top-level `recover` that fail-closes to deny, and returns 2 when the stdout emit fails. This task threads `harness`, resolves it via `Canonical` under the recover, funnels every terminal path through a single `adapter.Emit` (plus the recover as the only other Emit site), and records `Harness: name`. `emitOrBlock` is removed (its role moves into `adapter.Emit`).

- [ ] **Step 1: Write the failing test**

Add these NEW tests to `gate_test.go` (alongside the migrated existing ones).
`errWriter` may already exist in the package from Task 3's adapter tests — those
live in `package adapter`, a different package, so define a local one here:

```go
// (the existing gate_test.go already imports bytes, os, path/filepath, strings,
//  testing, store; ADD "errors" for gateFailWriter.)

// gateFailWriter fails every write, to exercise Gate's fail-closed exit code.
type gateFailWriter struct{}

func (gateFailWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

// gatePanicReader panics on Read, so json decoding inside adapter.Parse panics
// and propagates to Gate's top-level recover — a deterministic way to drive the
// recover branch with no production-only test seam.
type gatePanicReader struct{}

func (gatePanicReader) Read([]byte) (int, error) { panic("boom") }

func gateOut(t *testing.T, payload, harness string) (string, int) {
	t.Helper()
	home := t.TempDir() // no policy.json → Gate falls back to policy.Default()
	var out bytes.Buffer
	code := Gate(strings.NewReader(payload), &out, home, harness)
	return out.String(), code
}

func TestGateDefaultHarnessIsClaudeCode(t *testing.T) {
	out, code := gateOut(t, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`, "")
	if code != 0 || !strings.Contains(out, `"permissionDecision":"allow"`) {
		t.Errorf("bare install (harness \"\") must behave as claude-code allow; got code=%d out=%q", code, out)
	}
}

func TestGateUnknownHarnessFailsClosed(t *testing.T) {
	out, code := gateOut(t, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`, "codex")
	if code != 2 {
		t.Errorf("unknown harness must exit 2 (fail-closed); got code=%d", code)
	}
	if out != "" {
		t.Errorf("unknown harness must write NOTHING (cannot speak the protocol); got %q", out)
	}
}

func TestGateParseErrorFunnelsDeny(t *testing.T) {
	out, _ := gateOut(t, `not json`, "claude-code")
	if !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Errorf("unparseable payload must emit deny (not empty verdict); got out=%q", out)
	}
}

func TestGateHighSeverityDenies(t *testing.T) {
	out, _ := gateOut(t, `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`, "claude-code")
	if !strings.Contains(out, `"permissionDecision":"deny"`) ||
		strings.Contains(out, `"permissionDecision":"allow"`) ||
		strings.Contains(out, `"permissionDecision":"ask"`) {
		t.Errorf("rm -rf / must deny via the floor and NEVER allow/ask; got %q", out)
	}
}

// Write failure on the terminal emit path must fail closed via exit 2, never a
// dropped 0 (which would be a silent allow in bypassPermissions).
func TestGateWriteFailureFailsClosed(t *testing.T) {
	home := t.TempDir()
	code := Gate(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`),
		gateFailWriter{}, home, "claude-code")
	if code != 2 {
		t.Errorf("stdout write failure must exit 2; got %d", code)
	}
}

// The top-level recover must emit deny (never allow) when the hot path panics.
func TestGateRecoverEmitsDeny(t *testing.T) {
	var out bytes.Buffer
	Gate(gatePanicReader{}, &out, t.TempDir(), "claude-code")
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) ||
		strings.Contains(out.String(), `"permissionDecision":"allow"`) {
		t.Errorf("a panic must recover to deny, never allow; got %q", out.String())
	}
}

// Backward-compat regression: a bare install (harness "") must record the row
// as "claude-code", or replay/close-loop's claudeCodeOnly filter drops it.
// Uses a NON-safe command because Gate only records non-safe decisions.
func TestGateRecordsCanonicalHarnessForBareInstall(t *testing.T) {
	home := t.TempDir()
	// recordDecision's store.Open does NOT create parents; the .argus dir must
	// exist or the row is silently not written (best-effort record).
	if err := os.MkdirAll(filepath.Join(home, ".argus"), 0o755); err != nil {
		t.Fatal(err)
	}
	Gate(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`),
		&bytes.Buffer{}, home, "")
	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, _, err := st.AllDecisions(10, true) // (rows, capped, err); claudeCodeOnly=true → filters harness="claude-code"
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Harness != "claude-code" {
		t.Errorf("bare install must record Harness=claude-code; got %+v", rows)
	}
}
```

Verify `store.Open`, `store.AllDecisions(cap, claudeCodeOnly)`, and `store.Row.Harness`
against the real signatures before writing (the store is created lazily by Gate's
`recordDecision`; a non-safe command guarantees a row).

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/cli/ -run TestGate`
Expected: FAIL (Gate signature mismatch — too few args).

- [ ] **Step 3: Write minimal implementation**

Rewrite `Gate` in `internal/cli/gate.go`. Add `adapter` to imports; drop `verdict` only if it becomes unused (it stays — `verdict.Map`). Remove `emitOrBlock`.

```go
// Gate is the synchronous PreToolUse hot path. It resolves the harness, parses,
// classifies, best-effort records, and emits through the per-harness adapter.
// Every terminal path funnels an explicit Outcome into a SINGLE adapter.Emit
// call; the deferred recover is the only other Emit caller and assigns its exit
// code to the named return. A top-level recover fail-closes to deny so a bug on
// this path can never silently allow a dangerous command (CLAUDE.md §2).
func Gate(stdin io.Reader, stdout io.Writer, home, harness string) (code int) {
	var name string // captured by the recover closure; "" → Emit default → exit 2
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "argus: gate: recovered panic: %v\n", r)
			code = adapter.Emit(name, stdout, adapter.Outcome{Verdict: "deny", Reason: "internal error (fail-closed)"})
		}
	}()

	name, err := adapter.Canonical(harness)
	if err != nil {
		// Unknown harness: we cannot speak its protocol, so emit nothing and
		// fail closed via a non-zero exit — the only portable "do not proceed".
		fmt.Fprintf(os.Stderr, "argus: gate: %v\n", err)
		return 2
	}

	return adapter.Emit(name, stdout, decide(stdin, home, name))
}

// decide runs the parse → classify → record pipeline and returns the Outcome to
// emit. A parse failure funnels an explicit deny (never a zero-value Outcome,
// which would serialize an empty verdict Claude Code treats as no-opinion).
// Shadow mode records the real verdict but emits allow.
func decide(stdin io.Reader, home, name string) adapter.Outcome {
	payload, err := adapter.Parse(name, stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: parse payload: %v\n", err)
		return adapter.Outcome{Verdict: "deny", Reason: "unparseable payload"}
	}

	pol, err := policy.Load(home + "/.argus/policy.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: load policy: %v (falling back to default)\n", err)
		pol = policy.Default()
	}

	decision := classify.Classify(payload, pol)
	mapped := verdict.Map(decision.Severity, payload.PermissionMode)

	if decision.Severity != "safe" {
		recordDecision(home, payload, pol, decision, mapped, name)
	}

	if pol.Defaults.Shadow {
		return adapter.Outcome{Verdict: "allow", Reason: decision.Reason}
	}
	return adapter.Outcome{Verdict: mapped, Reason: decision.Reason}
}
```

Update `recordDecision`'s signature to take the resolved harness and use it:

```go
func recordDecision(home string, p hook.Payload, pol policy.Policy, d classify.Decision, mappedVerdict, harness string) {
	// ... unchanged body ...
	row := store.Row{
		// ... unchanged fields ...
		Harness: harness, // was the literal "claude-code"
		// ...
	}
	// ...
}
```

Delete `emitOrBlock` (now unused). Verify no other file references it.

Update `cmd/argus/main.go` gate case to parse `--harness` and pass it:

```go
case "gate":
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	harness := fs.String("harness", "", "agent harness this gate serves (default claude-code)")
	fs.Parse(os.Args[2:])
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: user home dir: %v\n", err)
	}
	os.Exit(cli.Gate(os.Stdin, os.Stdout, home, *harness))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/cli/ ./cmd/argus/ ./internal/adapter/` then the full suite `CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test ./...`.
Expected: PASS, and the existing gate/corpus tests stay green.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/gate.go cmd/argus/main.go internal/cli/gate_test.go \
        internal/cli/gate_bench_test.go internal/cli/stats.go
git commit -m "feat(gate): route through adapter seam + --harness flag, fail-closed on unknown"
```

Note: a malformed `--harness` flag (a typo like `--harnes=x`) makes `ExitOnError`
call `os.Exit(2)` inside `fs.Parse` in `main.go`, before `Gate` runs — no
classification was possible and exit 2 blocks the tool, so that path is an
acceptable fail-closed outside the recover.

---

### Task 5: `cli.Wire` dispatch — write `--harness=claude-code` on fresh wiring

**Files:**
- Create: `internal/cli/wire.go`
- Modify: `internal/cli/init_hook.go` (fresh-wiring writes the harness flag), init call site (calls `Wire`)
- Test: `internal/cli/wire_test.go`

**Interfaces:**
- Consumes: `wireHook(home)`, `gateCommand`, `wiredMatcher`, `gateEntry`, `settingsPath`, `readSettings`, `writeSettings` (all in `cli`); `adapter.Canonical` (Task 1).
- Produces: `cli.Wire(name, home string) error` — used by init.

**Context:** `wireHook` (init_hook.go:27) idempotently appends a PreToolUse entry running `gateCommand` (`"argus gate"`). `gateEntry` recognizes an existing entry by substring `"argus gate"`. Fresh wiring must now write `argus gate --harness=claude-code`; the substring still matches so idempotency holds. NO self-heal of an existing bare command.

- [ ] **Step 1: Write the failing test**

```go
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readSettingsFile(t *testing.T, home string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWireFreshWritesHarnessFlag(t *testing.T) {
	home := t.TempDir()
	if err := Wire("claude-code", home); err != nil {
		t.Fatal(err)
	}
	got := readSettingsFile(t, home)
	if !strings.Contains(got, "argus gate --harness=claude-code") {
		t.Errorf("fresh wiring must write the harness flag; got %s", got)
	}
}

func TestWireIsIdempotent(t *testing.T) {
	home := t.TempDir()
	if err := Wire("claude-code", home); err != nil {
		t.Fatal(err)
	}
	if err := Wire("claude-code", home); err != nil {
		t.Fatal(err)
	}
	got := readSettingsFile(t, home)
	if n := strings.Count(got, "argus gate"); n != 1 {
		t.Errorf("Wire must be idempotent: %d gate entries, want 1\n%s", n, got)
	}
}

func TestWireUnknownHarnessErrors(t *testing.T) {
	if err := Wire("codex", t.TempDir()); err == nil {
		t.Error("Wire(unknown harness) must error, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/cli/ -run TestWire`
Expected: FAIL (undefined `Wire`).

- [ ] **Step 3: Write minimal implementation**

Create `internal/cli/wire.go`:

```go
package cli

import (
	"fmt"

	"github.com/lucasngucii/argus/internal/adapter"
)

// Wire installs the PreToolUse hook for the named harness into its config. It
// dispatches by harness; the claude-code case wires ~/.claude/settings.json.
// An unknown harness errors (init fails loudly) rather than writing to an
// arbitrary path.
func Wire(name, home string) error {
	canon, err := adapter.Canonical(name)
	if err != nil {
		return fmt.Errorf("wire: %w", err)
	}
	switch canon {
	case "claude-code":
		return wireHook(home)
	default:
		return fmt.Errorf("wire: no wiring for harness %q", canon)
	}
}
```

In `init_hook.go`, change the FRESH-wiring command from `gateCommand` to the flagged form. `gateCommand` stays `"argus gate"` (the match substring); introduce the written command separately:

```go
// gateWireCommand is what fresh wiring writes: the match constant plus the
// explicit harness flag. It MUST contain gateCommand as a substring so
// gateEntry/doctor recognize it and stay idempotent.
const gateWireCommand = gateCommand + " --harness=claude-code"
```

In `wireHook`, the append that currently uses `"command": gateCommand` becomes `"command": gateWireCommand`. Leave the `gateEntry`/matcher-self-heal logic untouched (it matches on `gateCommand` substring, which `gateWireCommand` contains).

Change init's wire call site — the only `wireHook(home)` call is at **`init.go:43`**
(inside `Init`, which `RunInit` calls) — to `Wire("claude-code", home)`. `wireHook`
stays referenced (now called by `Wire`), so no dead-code error. (Verify with
`grep -rn "wireHook(" internal/cli` before editing.)

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/cli/` then `CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test ./...`.
Expected: PASS (existing init tests stay green; if an init test asserts the exact bare `"argus gate"` command string, update it to the flagged form — that is an intended change, note it in the report).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/wire.go internal/cli/init_hook.go internal/cli/init.go internal/cli/wire_test.go
git commit -m "feat(cli): Wire dispatch — fresh wiring writes --harness=claude-code"
```

(Existing `init_test.go` matches the hook by substring `"argus gate"`, which
`gateWireCommand` still contains, so those tests stay green with no edit. Do NOT
stage `init_run.go` — it calls `Init`, not `wireHook`, so it does not change.)

---

### Task 6: `cli.Probe` dispatch — doctor discovers & validates the configured harness

**Files:**
- Create: `internal/cli/probe.go`
- Modify: `internal/cli/doctor.go` (call `Probe`)
- Test: `internal/cli/probe_test.go`

**Interfaces:**
- Consumes: `checkHook(home)`, `settingsPath`, `readSettings`, `gateEntry` (in `cli`); `adapter.Canonical` (Task 1).
- Produces: `cli.Probe(name, home string) error` — used by `Doctor`.

**Context:** doctor's `report(label string, err error)` prints `PASS` on nil, `FAIL %v` on error. `Probe` returns `error` so it drops straight in. It must (a) verify the hook is wired (existing `checkHook`) and (b) discover the configured harness from the wired command and reject an unknown one. Extraction rule (fixed): match `--harness=` followed by one run of non-whitespace; the space form and single-dash are not recognized (read as absent); absent ⇒ `""`. Tri-state: bare = PASS, known = PASS, unknown = FAIL.

- [ ] **Step 1: Write the failing test**

```go
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHookCommand(t *testing.T, home, command string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + command + `"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProbeTriState(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{"bare", "argus gate", false},
		{"known", "argus gate --harness=claude-code", false},
		{"unknown", "argus gate --harness=bogus", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			writeHookCommand(t, home, tt.command)
			err := Probe("claude-code", home)
			if (err != nil) != tt.wantErr {
				t.Errorf("Probe with command %q: err=%v wantErr=%v", tt.command, err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "bogus") {
				t.Errorf("unknown-harness FAIL must name the offending value; got %v", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/cli/ -run TestProbe`
Expected: FAIL (undefined `Probe`).

- [ ] **Step 3: Write minimal implementation**

Create `internal/cli/probe.go`:

```go
package cli

import (
	"fmt"
	"regexp"

	"github.com/lucasngucii/argus/internal/adapter"
)

// harnessFlag matches the harness value in a wired command: `--harness=` followed
// by one run of non-whitespace. Only the `=` form (what fresh wiring writes) is
// recognized; the space-separated form reads as absent, so a hand-editor who uses
// it is treated as a bare (claude-code) install.
var harnessFlag = regexp.MustCompile(`--harness=(\S+)`)

// Probe verifies the named harness's install is intact for doctor. For
// claude-code it checks the PreToolUse hook is wired AND that the harness the
// wired command actually configures is one Argus knows: an unknown value would
// make every live call fail closed, so doctor must FAIL loudly and name it
// rather than silently PASS. Returns nil (→ doctor PASS) or an error (→ FAIL %v).
func Probe(name, home string) error {
	canon, err := adapter.Canonical(name)
	if err != nil {
		return err
	}
	switch canon {
	case "claude-code":
		if err := checkHook(home); err != nil {
			return err
		}
		return checkConfiguredHarness(home)
	default:
		return fmt.Errorf("no probe for harness %q", canon)
	}
}

// checkConfiguredHarness reads the wired command and rejects an unknown
// --harness value. Absent flag ⇒ "" ⇒ claude-code (bare install) ⇒ PASS.
func checkConfiguredHarness(home string) error {
	settings, err := readSettings(settingsPath(home))
	if err != nil {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	entry := gateEntry(preToolUse)
	if entry == nil {
		return nil // no gate entry; checkHook already reported that
	}
	cmd := gateCommandString(entry)
	configured := ""
	if m := harnessFlag.FindStringSubmatch(cmd); m != nil {
		configured = m[1]
	}
	if _, err := adapter.Canonical(configured); err != nil {
		return fmt.Errorf("hook configures %w", err)
	}
	return nil
}
```

Add a small helper `gateCommandString(entry map[string]any) string` in
`init_hook.go` beside `gateEntry` (mirror how `gateEntry` walks
`entry["hooks"].([]any)` → inner `map[string]any` → `["command"].(string)`). It
must return the inner hook whose command **contains `gateCommand`** — the one
`gateEntry` matched on — not blindly the first inner hook, so a hand-edited
multi-hook entry is read correctly. Return `""` if none.

Wire it into `Doctor` (doctor.go): replace the raw `checkHook(home)` report with `Probe`:

```go
report("hook: PreToolUse -> argus gate wired in ~/.claude/settings.json", Probe("claude-code", home))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/cli/` then full `CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test ./...`.
Expected: PASS; existing doctor tests stay green (a bare-command fixture still PASSes).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/probe.go internal/cli/doctor.go internal/cli/init_hook.go internal/cli/probe_test.go
git commit -m "feat(cli): Probe dispatch — doctor discovers and validates the configured harness"
```

---

## Notes for the implementer

- **Deferred (not this plan):** `settings.local.json` is not inspected by `wireHook`/`Probe` (pre-existing single-file assumption); a hook living there is invisible. Out of scope.
- **Do not** touch `internal/classify`, the policy model, or the store schema.
- After the last task, the whole existing golden + evasion corpus and every package test must be green with `CGO_ENABLED=0 go test ./...`.
