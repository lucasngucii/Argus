# MCP Tool-Call Gating — Implementation Plan (Phase 4A)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. REQUIRED before each task: read `CLAUDE.md` + invoke **argus-architect**.

**Goal:** Gate MCP tool calls (`mcp__*`), which today classify `safe → allow` because `Subject()` returns empty. Default to allow; ask before an obviously-mutating MCP tool; hard-deny an MCP tool whose args target credential/system paths or Argus's own config. No change to the severity model, `verdict.Map`, or the Bash/Write/Edit path.

**Architecture:** Capture the raw `tool_input` JSON so the classifier can inspect MCP arguments; for an MCP call `Subject()` returns that JSON, so existing subject-`Raw` floor rules extend to MCP args once their `Tool` list includes a new `"mcp"` token. Add two `Match` fields (`mcpServer`, `mcpTool`) for name-based rules. Ship one `medium` mutating-verb rule and extend the self-protect/credential/destructive floor to MCP. There is **no shell AST for MCP** — matching is on the tool name and a regex over the args JSON only.

**Tech Stack:** Go 1.26 · `CGO_ENABLED=0` · existing `internal/{hook,classify,policy,cli}` · JSON policy + schema.

## Global Constraints

- Module `github.com/lucasngucii/argus`. Go **1.26**, **`CGO_ENABLED=0`**.
- **No change to `verdict.Map`, the severity ladder, or the Bash/Write/Edit classification path.** MCP is additive.
- **The 5 CLAUDE.md invariants hold:** pure `classify`, hot-path fail-closed, logging never changes the verdict, `high` is a non-downgradable floor, self-protection stays high — and now extends to MCP args.
- **Grounded facts (verified, do not re-derive):** `tool_name` = `mcp__<server>__<tool>` (plugin form `mcp__plugin_<plugin>_<server>__<tool>`); `tool_input` = flat arbitrary server-defined JSON, no guaranteed fields; deny/ask/allow use the same `hookSpecificOutput` contract; matcher regex `mcp__.*` catches all MCP tools.
- RE2 regex only (no lookahead/backreferences).
- Every rule/behavior ships golden + evasion coverage; deterministic tests only.
- Commit identity `lucasngucii <lucasalehwork@gmail.com>`. Conventional commits, one logical change each. **Never** a `Co-Authored-By: Claude` trailer. Stage files by explicit path (never `git add -A`/`.`).

## Consumes (exact, verified — do not guess)

```go
// internal/hook/payload.go (current)
type ToolInput struct{ Command, FilePath string } // json: command, file_path
type Payload struct{ SessionID, TranscriptPath, CWD, PermissionMode, HookEventName, ToolName, ToolUseID string; ToolInput ToolInput }
func (p Payload) Subject() string // Command if ToolName=="Bash" else FilePath

// internal/classify/match.go (current)
func Matches(tool, subject string, f shellast.Facts, r policy.Rule) (matched bool, regexErr bool)
func toolIn(tools []string, tool string) bool         // exact string membership
func usesShellFacts(mt policy.Match) bool             // Cmd|Flags|ArgsContain|ArgMatches|PipesInto|RedirectsTo
// Matches is called as Matches(p.ToolName, p.Subject(), f, r) in classify.go (main pass + applyAllowlist)

// internal/policy/policy.go (current Match)
type Match struct{ Cmd, Flags, ArgsContain, PipesInto []string; ArgMatches, RedirectsTo, TargetScorer, Raw string }

// internal/policy/defaults.go floor rules to extend (all use Match.Raw over the subject, Tool ["Bash","Write","Edit"]):
//   credential-system-write, self-protect-claude-settings, self-protect-argus
// leadBoundary / trailBoundary constants exist for anchoring Raw patterns.
```

## File Structure

```
internal/hook/payload.go        # ToolInput.UnmarshalJSON captures Raw; SplitMCP(); Payload.IsMCP/MCPServer/MCPTool; Subject() -> args JSON for MCP
internal/hook/payload_test.go   # MCP parse + Subject tests
internal/policy/policy.go       # Match: +McpServer []string, +McpTool string
internal/policy/schema.json     # allow mcpServer/mcpTool in match
internal/policy/validate_test.go# accept a rule using mcpServer/mcpTool
internal/classify/match.go      # toolIn "mcp" token; McpServer/McpTool matching; keep them out of usesShellFacts
internal/classify/classify_test.go # MCP classification golden/evasion
internal/policy/defaults.go     # extend 3 floor rules' Tool to include "mcp"; +mcp-destructive-args floor; +mcp-mutating-tool seed (medium)
internal/policy/defaults_test.go (or classify_test) # floor-non-downgrade for MCP
internal/cli/init_hook.go       # matcher "Bash|Write|Edit|mcp__.*"
internal/cli/init_test.go       # matcher assertion
internal/cli/doctor.go          # WARN if wired matcher lacks mcp__
internal/cli/doctor_test.go     # WARN test
docs/policy.md                  # mcpServer/mcpTool fields + an MCP section
```

---

### Task 1: Payload — capture raw `tool_input`, MCP helpers, MCP `Subject()`

**Files:** Modify `internal/hook/payload.go`; create/extend `internal/hook/payload_test.go`.

**Interfaces:**
- Produces: `ToolInput.Raw json.RawMessage` (the full args object); `hook.SplitMCP(name) (server, tool string, ok bool)`; `Payload.IsMCP() bool`, `MCPServer() string`, `MCPTool() string`; `Subject()` returns the raw `tool_input` JSON for an MCP call (unchanged for Bash/Write/Edit).

- [ ] **Step 1: Failing tests.** Add to `internal/hook/payload_test.go`:

```go
func TestParseMCPPayload(t *testing.T) {
	in := `{"tool_name":"mcp__filesystem__delete_file","permission_mode":"default","tool_input":{"path":"/home/dev/.ssh/id_rsa"}}`
	p, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsMCP() {
		t.Fatal("IsMCP should be true")
	}
	if p.MCPServer() != "filesystem" || p.MCPTool() != "delete_file" {
		t.Fatalf("parsed server/tool = %q/%q, want filesystem/delete_file", p.MCPServer(), p.MCPTool())
	}
	if !strings.Contains(p.Subject(), ".ssh/id_rsa") {
		t.Fatalf("MCP Subject must be the args JSON, got %q", p.Subject())
	}
}
func TestMCPPluginForm(t *testing.T) {
	p := Payload{ToolName: "mcp__plugin_myplug_db__query"}
	if p.MCPServer() != "plugin_myplug_db" || p.MCPTool() != "query" {
		t.Fatalf("plugin form parsed %q/%q", p.MCPServer(), p.MCPTool())
	}
}
func TestBashSubjectUnchanged(t *testing.T) {
	p := Payload{ToolName: "Bash", ToolInput: ToolInput{Command: "ls"}}
	if p.IsMCP() || p.Subject() != "ls" {
		t.Fatal("Bash path must be unchanged")
	}
}
```

- [ ] **Step 2: Run → FAIL.** `CGO_ENABLED=0 go test ./internal/hook/ -run 'TestParseMCP|TestMCPPlugin|TestBashSubject'` → FAIL (undefined IsMCP/MCPServer/MCPTool; Subject empty for MCP).

- [ ] **Step 3: Implement.** In `internal/hook/payload.go`:

Add `"strings"` to imports. Give `ToolInput` a raw-capturing unmarshal and a `Raw` field:

```go
type ToolInput struct {
	Command  string          `json:"command"`
	FilePath string          `json:"file_path"`
	Raw      json.RawMessage `json:"-"` // the full tool_input object (for MCP args)
}

// UnmarshalJSON captures the entire tool_input object as Raw while still
// decoding the typed command/file_path fields the Bash/Write paths use. MCP
// tool_input is arbitrary server-defined JSON, so Raw is how the classifier
// inspects it.
func (t *ToolInput) UnmarshalJSON(b []byte) error {
	t.Raw = append(json.RawMessage(nil), b...)
	type plain struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
	}
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return nil // MCP args may not be an object with these fields; Raw still captured
	}
	t.Command, t.FilePath = p.Command, p.FilePath
	return nil
}
```

Add MCP helpers and MCP-aware `Subject`:

```go
const mcpPrefix = "mcp__"

// SplitMCP parses an MCP tool_name of the form mcp__<server>__<tool> into its
// server and tool segments (the plugin form mcp__plugin_<p>_<server>__<tool>
// yields server="plugin_<p>_<server>", tool="<tool>"). ok is false for a
// non-MCP name.
func SplitMCP(name string) (server, tool string, ok bool) {
	rest, ok := strings.CutPrefix(name, mcpPrefix)
	if !ok {
		return "", "", false
	}
	server, tool, _ = strings.Cut(rest, "__")
	return server, tool, true
}

func (p Payload) IsMCP() bool { return strings.HasPrefix(p.ToolName, mcpPrefix) }
func (p Payload) MCPServer() string { s, _, _ := SplitMCP(p.ToolName); return s }
func (p Payload) MCPTool() string   { _, t, _ := SplitMCP(p.ToolName); return t }
```

Change `Subject()`:

```go
func (p Payload) Subject() string {
	switch {
	case p.ToolName == "Bash":
		return p.ToolInput.Command
	case p.IsMCP():
		return string(p.ToolInput.Raw)
	default:
		return p.ToolInput.FilePath
	}
}
```

- [ ] **Step 4: Run → PASS.** `CGO_ENABLED=0 go test ./internal/hook/` → PASS. Then `CGO_ENABLED=0 go test ./...` (ToolInput now has a custom UnmarshalJSON and a Raw field — confirm no existing consumer breaks; struct-literal `ToolInput{Command: …}` still compiles, Raw defaults nil).

- [ ] **Step 5: Commit** `feat(hook): capture raw tool_input + MCP tool_name parsing (Subject over MCP args)`.

---

### Task 2: `Match` fields `mcpServer` / `mcpTool` + schema

**Files:** Modify `internal/policy/policy.go`, `internal/policy/schema.json`, `internal/policy/validate_test.go`.

**Interfaces:**
- Consumes: nothing.
- Produces: `Match.McpServer []string` (json `mcpServer`), `Match.McpTool string` (json `mcpTool`); schema accepts them.

- [ ] **Step 1: Failing test.** Add to `internal/policy/validate_test.go`:

```go
func TestValidateAcceptsMCPMatch(t *testing.T) {
	doc := []byte(`{"version":1,"rules":[{"id":"m","tool":["mcp"],"reason":"x",
		"match":{"mcpServer":["github"],"mcpTool":"(?i)delete"}}]}`)
	if err := Validate(doc); err != nil {
		t.Fatalf("schema must accept mcpServer/mcpTool: %v", err)
	}
}
```

- [ ] **Step 2: Run → FAIL** (schema rejects unknown match keys).

- [ ] **Step 3: Implement.** In `internal/policy/policy.go`, add to `Match`:

```go
	McpServer []string `json:"mcpServer,omitempty"` // MCP server segment, ANY-of exact
	McpTool   string   `json:"mcpTool,omitempty"`   // regexp on the MCP tool segment
```

In `internal/policy/schema.json`, under the `match` `$defs` properties, add:

```json
        "mcpServer": { "type": "array", "items": { "type": "string" } },
        "mcpTool": { "type": "string" },
```

- [ ] **Step 4: Run → PASS** (`go test ./internal/policy/ -run TestValidate`). Confirm `Validate(Default())` still nil.

- [ ] **Step 5: Commit** `feat(policy): Match.mcpServer + Match.mcpTool (MCP name matching)`.

---

### Task 3: Classifier — `"mcp"` Tool token + `mcpServer`/`mcpTool` matching

**Files:** Modify `internal/classify/match.go`; add tests to `internal/classify/classify_test.go`.

**Interfaces:**
- Consumes: `hook.SplitMCP` (Task 1), `Match.McpServer/McpTool` (Task 2).
- Produces: `toolIn` treats `"mcp"` as "any `mcp__*` tool"; `Matches` honors `McpServer`/`McpTool`; these are NOT shell facts (they don't force `tool=="Bash"`).

- [ ] **Step 1: Failing tests.** Add to `internal/classify/classify_test.go` (a helper for MCP payloads):

```go
func mcp(name, argsJSON string) hook.Payload {
	return hook.Payload{ToolName: name, PermissionMode: "default",
		ToolInput: hook.ToolInput{Raw: json.RawMessage(argsJSON)}}
}
func TestMCPToolTokenMatches(t *testing.T) {
	pol := policy.Policy{Version: 1, Rules: []policy.Rule{
		{ID: "any-mcp", Enabled: true, Severity: "medium", Tool: []string{"mcp"},
			Match: policy.Match{McpTool: "(?i)delete"}, Reason: "x"}}}
	if Classify(mcp("mcp__fs__delete_file", `{"path":"/tmp/x"}`), pol).Severity != "medium" {
		t.Fatal("mcp token + mcpTool must match")
	}
	if Classify(mcp("mcp__fs__read_file", `{"path":"/tmp/x"}`), pol).Severity != "safe" {
		t.Fatal("read tool must not match mcpTool delete")
	}
	// the "mcp" token must NOT match a Bash call
	if Classify(bash("delete stuff", "default", "/tmp"), pol).Severity == "medium" {
		t.Fatal("mcp-token rule must not fire on Bash")
	}
}
func TestMCPServerMatch(t *testing.T) {
	pol := policy.Policy{Version: 1, Rules: []policy.Rule{
		{ID: "gh", Enabled: true, Severity: "high", AlwaysHigh: true, Tool: []string{"mcp"},
			Match: policy.Match{McpServer: []string{"github"}, McpTool: "(?i)delete"}, Reason: "x"}}}
	if Classify(mcp("mcp__github__delete_repo", `{}`), pol).Severity != "high" {
		t.Fatal("mcpServer github + delete must be high")
	}
	if Classify(mcp("mcp__memory__delete_entity", `{}`), pol).Severity == "high" {
		t.Fatal("different server must not match")
	}
}
```
(Ensure `encoding/json` is imported in the test file.)

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** In `internal/classify/match.go`:

Extend `toolIn` to honor the `"mcp"` token:

```go
func toolIn(tools []string, tool string) bool {
	isMCP := strings.HasPrefix(tool, "mcp__")
	for _, t := range tools {
		if t == tool || (t == "mcp" && isMCP) {
			return true
		}
	}
	return false
}
```
(Add `"strings"` to imports if not present.)

In `Matches`, after the existing shell-fact checks (and before `return matched, false`), add MCP name checks — they only constrain, never loosen:

```go
	if len(mt.McpServer) > 0 || mt.McpTool != "" {
		server, mtool, isMCP := hook.SplitMCP(tool)
		if !isMCP {
			matched = false
		} else {
			if len(mt.McpServer) > 0 && !contains(mt.McpServer, server) {
				matched = false
			}
			if mt.McpTool != "" {
				re, err := regexp.Compile(mt.McpTool)
				if err != nil {
					return false, true
				}
				if !re.MatchString(mtool) {
					matched = false
				}
			}
		}
	}
```
(Add `"github.com/lucasngucii/argus/internal/hook"` import if not present; `contains` already exists in the package — verify; if it's `contains(haystack []string, needle string)` reuse it, else use a local check.)

Leave `usesShellFacts` unchanged — `McpServer`/`McpTool`/`Raw` are deliberately NOT shell facts, so an MCP-only rule's `matched` starts true and the MCP checks apply.

- [ ] **Step 4: Run → PASS** (`go test ./internal/classify/`). Full `go test ./...` to confirm no Bash regression.

- [ ] **Step 5: Commit** `feat(classify): "mcp" Tool token + mcpServer/mcpTool matching`.

---

### Task 4: Floor coverage for MCP — extend Raw floor rules + `mcp-destructive-args`

**Files:** Modify `internal/policy/defaults.go`; tests in `internal/classify/classify_test.go`.

**Interfaces:** Produces MCP `high` (floor) coverage: an MCP call whose args reference credential/system/self-protect paths, or contain destructive SQL, is non-downgradable `high`.

- [ ] **Step 1: Failing tests.** Add to `internal/classify/classify_test.go`:

```go
func TestMCPArgsCredentialIsHighFloor(t *testing.T) {
	got := Classify(mcp("mcp__filesystem__write_file", `{"path":"/home/x/.ssh/authorized_keys","content":"k"}`), policy.Default())
	if got.Severity != "high" {
		t.Fatalf("MCP write to authorized_keys must be high, got %s", got.Severity)
	}
}
func TestMCPArgsSelfProtectIsHigh(t *testing.T) {
	if Classify(mcp("mcp__filesystem__delete_file", `{"path":"/home/x/.argus/policy.json"}`), policy.Default()).Severity != "high" {
		t.Fatal("MCP delete of .argus must be high")
	}
}
func TestMCPDestructiveSQLIsHigh(t *testing.T) {
	if Classify(mcp("mcp__db__query", `{"sql":"DROP TABLE users"}`), policy.Default()).Severity != "high" {
		t.Fatal("MCP args with DROP TABLE must be high")
	}
}
func TestMCPFloorNotDowngradable(t *testing.T) {
	pol := policy.Default()
	pol.Rules = append(pol.Rules, policy.Rule{ID: "allow-all-mcp", Enabled: true, Allow: true,
		Tool: []string{"mcp"}, Match: policy.Match{Raw: ".*"}, Reason: "x"})
	if Classify(mcp("mcp__filesystem__delete_file", `{"path":"~/.ssh/id_rsa"}`), pol).Severity != "high" {
		t.Fatal("allowlist must not downgrade an MCP floor hit")
	}
}
```

- [ ] **Step 2: Run → FAIL** (MCP not in the floor rules' Tool lists; no MCP SQL rule).

- [ ] **Step 3: Implement.** In `internal/policy/defaults.go`:

Add `"mcp"` to the `Tool` slice of the three Raw floor rules so their existing subject-`Raw` patterns apply to MCP args:
- `credential-system-write`: `Tool: []string{"Bash", "Write", "Edit", "mcp"}`
- `self-protect-claude-settings`: `Tool: []string{"Bash", "Write", "Edit", "mcp"}`
- `self-protect-argus`: `Tool: []string{"Bash", "Write", "Edit", "mcp"}`

Add a new floor rule to `Floor()` (before `return append(f, SelfProtectRules()...)`):

```go
{ID: "mcp-destructive-args", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"mcp"},
	// db-destructive's pattern, applied to the MCP args JSON (Subject) — an MCP
	// tool named innocuously (e.g. "query") can still carry a DROP in its args.
	Match:  Match{Raw: `(?i)\b(drop|truncate)\s+(table|database)\b|\bdelete\s+from\b|\.drop\(\)|deletemany`},
	Reason: "destructive SQL in MCP tool arguments"},
```

- [ ] **Step 4: Run → PASS** (`go test ./internal/classify/`). Full `go test ./...`.

- [ ] **Step 5: Commit** `feat(policy): extend the self-protect/credential floor to MCP args + mcp-destructive-args`.

---

### Task 5: Seed rule `mcp-mutating-tool` (medium)

**Files:** Modify `internal/policy/defaults.go`; tests in `internal/classify/classify_test.go`.

**Interfaces:** Produces `Default().Rules` id `mcp-mutating-tool` (medium, downgradable) — an MCP tool whose name announces a mutation asks a human.

- [ ] **Step 1: Failing tests.** Add to `internal/classify/classify_test.go`:

```go
func TestMCPMutatingToolIsMedium(t *testing.T) {
	for _, n := range []string{"mcp__fs__delete_file", "mcp__db__drop_table", "mcp__x__exec_command", "mcp__fs__write_file"} {
		if got := Classify(mcp(n, `{"a":"b"}`), policy.Default()).Severity; got != "medium" {
			t.Fatalf("%s must be medium, got %s", n, got)
		}
	}
}
func TestMCPReadToolIsSafe(t *testing.T) {
	for _, n := range []string{"mcp__fs__read_file", "mcp__gh__list_issues", "mcp__x__get_status", "mcp__x__search"} {
		if got := Classify(mcp(n, `{"a":"b"}`), policy.Default()).Severity; got != "safe" {
			t.Fatalf("%s must be safe, got %s", n, got)
		}
	}
}
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** Append to `Default()`'s `p.Rules` slice:

```go
{ID: "mcp-mutating-tool", Enabled: true, Severity: "medium", Tool: []string{"mcp"},
	// No shell AST for MCP — the tool name is the only intent signal. A name
	// announcing a mutation asks a human; read-style tools stay allow.
	Match:  Match{McpTool: `(?i)\b(delete|drop|remove|destroy|truncate|write|create|update|put|patch|exec|run|kill)\b`},
	Reason: "MCP tool with a mutating action — review before running"},
```

- [ ] **Step 4: Run → PASS.** Full `go test ./...` (mutating-verb medium is a Default seed rule → `SeedRuleIDs()` grows by 1; its test is dynamic, confirm still green).

- [ ] **Step 5: Commit** `feat(policy): seed rule mcp-mutating-tool (medium, mutating-verb heuristic)`.

---

### Task 6: Init matcher + doctor WARN + docs

**Files:** Modify `internal/cli/init_hook.go`, `internal/cli/init_test.go`, `internal/cli/doctor.go`, `internal/cli/doctor_test.go`, `docs/policy.md`.

**Interfaces:** Produces the MCP-aware wired matcher and a non-fatal doctor WARN for installs missing it; docs cover the new fields.

- [ ] **Step 1: Failing test (matcher).** In `internal/cli/init_test.go`, add/extend an assertion that after `Init`, the wired PreToolUse entry's `matcher` equals `"Bash|Write|Edit|mcp__.*"` (read `~/.claude/settings.json`, find the entry whose hook command contains `argus gate`, assert its matcher).

- [ ] **Step 2: Run → FAIL** (current matcher is `"Bash|Write|Edit"`).

- [ ] **Step 3: Implement matcher.** In `internal/cli/init_hook.go`, change the appended entry's `"matcher"` value from `"Bash|Write|Edit"` to `"Bash|Write|Edit|mcp__.*"`. Idempotency is unaffected (`hasGateHook` keys off the `argus gate` command, not the matcher).

- [ ] **Step 4: Run → PASS** (matcher test). Existing init idempotency tests still pass.

- [ ] **Step 5: Failing test (doctor WARN).** In `internal/cli/doctor_test.go`: after `Init`, `Doctor` emits no matcher WARN; after rewriting the settings' gate entry matcher to `"Bash|Write|Edit"` (no `mcp__`), `Doctor` returns its normal code but the output contains a WARN naming the missing MCP matcher.

- [ ] **Step 6: Implement doctor WARN.** In `internal/cli/doctor.go`, add a non-fatal check (like the seed-rule WARN): read the wired gate entry's matcher; if it does not contain `mcp__`, print `WARN hook: matcher does not gate MCP tools (mcp__*) — re-run 'argus init' or add mcp__.* to the matcher`. Does NOT change the exit code.

- [ ] **Step 7: Run → PASS.** Full `go test ./...` + `go vet ./...`.

- [ ] **Step 8: Docs.** In `docs/policy.md`: add `mcpServer` and `mcpTool` rows to the match-fields table, and a short **"Gating MCP tools"** section: default allow, the mutating-verb `medium` rule, the floor-over-args protection, and an example rule (`mcpServer: ["github"], mcpTool: "(?i)(create|delete|push)"`). Note the honest limit: no semantic parsing — a server that names a mutating tool innocuously (e.g. `process`) is judged only by its args unless a per-server rule is added.

- [ ] **Step 9: Commit** `feat(cli): init wires mcp__.* matcher + doctor WARN; docs: MCP gating`.

---

## Self-Review

**Spec coverage:** payload raw-capture + MCP parse + MCP Subject (T1) · `mcpServer`/`mcpTool` fields + schema (T2) · `"mcp"` Tool token + name matching, kept out of shell facts (T3) · floor extension to MCP args + destructive-SQL floor (T4) · mutating-verb medium seed (T5) · init matcher + doctor WARN + docs (T6). Default posture = allow (no rule fires ⇒ safe). All grounded in the verified hook facts.

**Placeholder scan:** every rule/step carries full Go/JSON code; no TBD.

**Type/name consistency:** `ToolInput.Raw`, `hook.SplitMCP`, `Payload.IsMCP/MCPServer/MCPTool`, `Match.McpServer/McpTool`, rule ids `mcp-destructive-args`/`mcp-mutating-tool`, the `"mcp"` token — all identical across producer/consumer tasks. `Matches(tool, subject, …)` gets the tool name, from which `SplitMCP` derives server/tool. RE2-safe regexes.

**Ordering:** T1 (payload) → T2 (fields) → T3 (classifier reads fields, needs SplitMCP) → T4/T5 (rules use the token + fields) → T6 (wiring + docs). Each of T1/T4/T5 ends with a full `go test ./...`.

**Invariants:** `verdict.Map` untouched; MCP floor hits are `alwaysHigh` and proven non-downgradable (T4); self-protection now covers MCP; `classify` stays pure. Known v1 gap (documented in T6 + spec): a mutating MCP tool with an innocuous name and benign-looking args that is actually dangerous is judged allow — mitigated by per-server user rules, not solvable generically without server schemas.
