# MCP Tool-Call Gating — Implementation Plan (Phase 4A, rev 2)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. REQUIRED before each task: read `CLAUDE.md` + invoke **argus-architect**.
> **Rev 2** — revised after three adversarial reviews (technical / ripple / design). Changelog at end. The three BLOCKINGs (fail-open UnmarshalJSON, broken `\b` verb regex, non-recoverable floor FP over freeform args) and the store/replay + doctor gaps are all fixed here.

**Goal:** Gate MCP tool calls (`mcp__*`), which today classify `safe → allow` because `Subject()` returns empty. Default to allow; ask before a mutating-named MCP tool; hard-deny only when a **file-op-named** MCP tool targets a credential/system/self-protect path. No change to the severity model, `verdict.Map`, or the Bash/Write/Edit path.

**Architecture:** Capture the raw `tool_input` JSON at the **Payload** level (so decode stays fail-closed for Bash/Write and tolerant for MCP); for an MCP call `Subject()` returns that JSON. Add `Match` fields `mcpServer`/`mcpTool` and a `"mcp"` Tool token. Ship two `medium` seed rules (mutating-verb name, destructive-SQL-in-args) and **one** `high` floor rule that AND-gates a file-op tool name against a sensitive-path match — precise enough to stay non-downgradable. Thread the MCP subject through the store + replay so MCP decisions are visible and replayable. Extend `explain` so MCP rules are dry-runnable. No shell AST for MCP — matching is tool-name + args-JSON regex only.

**Tech Stack:** Go 1.26 · `CGO_ENABLED=0` · existing `internal/{hook,classify,policy,cli,web,store,replay}` · JSON policy + schema.

## Global Constraints

- Module `github.com/lucasngucii/argus`. Go **1.26**, **`CGO_ENABLED=0`**.
- **No change to `verdict.Map`, the severity ladder, or the Bash/Write/Edit classification path.** MCP is additive.
- **The 5 CLAUDE.md invariants hold** — in particular the hot path **never fails open** (a malformed Bash/Write payload must still error → deny), and `high` is a floor reserved for genuine catastrophes (so MCP `high` is AND-gated on tool-name + path, never a bare substring in freeform prose).
- **Grounded facts (verified, do not re-derive):** `tool_name` = `mcp__<server>__<tool>` (plugin form `mcp__plugin_<plugin>_<server>__<tool>`); `tool_input` = flat arbitrary server-defined JSON, no guaranteed fields; deny/ask/allow use the same `hookSpecificOutput` contract; matcher regex `mcp__.*` catches all MCP tools.
- **MCP tool names are overwhelmingly snake_case** (`delete_file`, `create_issue`) — regexes must treat `_` as a token boundary; `\b` does NOT (Go `\w` includes `_`).
- RE2 regex only (no lookahead/backreferences). Every rule/behavior ships golden + evasion coverage; deterministic tests only.
- Commit identity `lucasngucii <lucasalehwork@gmail.com>`. Conventional commits, one logical change each. **Never** a `Co-Authored-By: Claude` trailer. Stage files by explicit path (never `git add -A`/`.`).

## Consumes (exact, verified in review — do not guess)

```go
// internal/hook/payload.go (current): Payload{...,ToolName,...,ToolInput ToolInput{Command,FilePath}}; Subject() = Command for Bash else FilePath.
// hook.Parse errors → cli/gate.go denies "unparseable payload" (the fail-closed path). Do NOT weaken this.
// internal/classify/match.go: Matches(tool, subject, f, r); toolIn exact membership; usesShellFacts excludes Raw (and will exclude the new mcp fields); contains(list []string, needle string) bool EXISTS.
//   leadBoundary/trailBoundary char classes include " and ' (verified) → a JSON-quoted path satisfies them.
//   db-destructive uses ArgMatches (a shell fact) → cannot fire on MCP; a Raw-based MCP rule is genuinely needed.
// internal/classify already imports internal/hook (no cycle adding hook to match.go).
// internal/policy/validate.go SeedRuleIDs()/TestSeedRuleIDsMatchesDefault are DYNAMIC over Default().Rules → new seed rules need no test edit.
// internal/policy/schema.json has NO additionalProperties:false on match → unknown keys already validate (the schema edit below is documentation, not a gate).
// internal/cli/init_hook.go: wireHook short-circuits on hasGateHook (command substring, NOT matcher). internal/cli/doctor.go checkHook uses hasGateHook (no matcher access).
// internal/cli/gate.go recordDecision writes store.Row{Command:p.ToolInput.Command, File:p.ToolInput.FilePath, Tool:p.ToolName, ...}.
// internal/store/store.go Row has Command/File string columns (no args column).
// internal/replay/replay.go reconstructs hook.Payload{ToolName:r.Tool, ToolInput:{Command:r.Command, FilePath:r.File}} → for MCP, Subject() needs Raw set.
// internal/web/explain.go / internal/cli/explain.go build a Payload from {command,tool,file} — no MCP args field today.
```

## File Structure

```
internal/hook/payload.go        # Payload.UnmarshalJSON: capture Raw; tolerate MCP, fail-closed Bash/Write; SplitMCP; IsMCP/MCPServer/MCPTool; Subject MCP branch
internal/hook/payload_test.go
internal/policy/policy.go        # Match: +McpServer []string, +McpTool string
internal/policy/schema.json      # document mcpServer/mcpTool
internal/policy/validate_test.go # accepts a rule using mcpServer/mcpTool
internal/classify/match.go       # toolIn "mcp" token; McpServer/McpTool matching (constrain-only, gated on IsMCP)
internal/classify/classify_test.go
internal/policy/defaults.go      # +floor mcp-fileop-sensitive-path (AND name-verb + path); +seed mcp-mutating-tool, +seed mcp-destructive-sql-args (both medium)
internal/cli/gate.go             # recordDecision: for MCP, persist Subject() into Command so it's visible + replayable
internal/replay/replay.go        # reconstruct ToolInput.Raw from r.Command for MCP rows
internal/replay/replay_test.go
internal/cli/init_hook.go        # matcher "Bash|Write|Edit|mcp__.*"; wireHook HEALS an existing entry's matcher; gateMatcher() helper
internal/cli/init_test.go
internal/cli/doctor.go           # WARN via gateMatcher() if matcher lacks mcp__
internal/cli/doctor_test.go
internal/web/explain.go          # explainRequest gains optional args; MCP-aware Payload build
internal/cli/explain.go / cmd wiring # allow `argus explain` of an MCP tool (optional args)
internal/cli/test.go             # comment: corpus is Bash/file-only; MCP covered by Go unit tests
docs/policy.md                   # mcpServer/mcpTool + "Gating MCP tools" section + honest floor-precision note
```

---

### Task 1: Payload — raw `tool_input` capture (fail-closed Bash, tolerant MCP), MCP parsing, MCP `Subject()`

**Files:** Modify `internal/hook/payload.go`, `internal/hook/payload_test.go`.

**Interfaces:** Produces `Payload.ToolInput.Raw json.RawMessage`; `hook.SplitMCP(name)(server,tool string,ok bool)`; `Payload.IsMCP/MCPServer/MCPTool`; `Subject()` returns the raw args JSON for MCP. **Invariant:** a Bash/Write/Edit payload with a wrong-typed `command`/`file_path` STILL errors (fail-closed); only an MCP payload tolerates a non-string `command`/`file_path`.

- [ ] **Step 1: Failing tests.** Add to `payload_test.go`:

```go
func TestParseMCPPayload(t *testing.T) {
	p, err := Parse(strings.NewReader(`{"tool_name":"mcp__filesystem__delete_file","permission_mode":"default","tool_input":{"path":"/home/dev/.ssh/id_rsa"}}`))
	if err != nil { t.Fatal(err) }
	if !p.IsMCP() || p.MCPServer() != "filesystem" || p.MCPTool() != "delete_file" {
		t.Fatalf("parse = %v/%q/%q", p.IsMCP(), p.MCPServer(), p.MCPTool())
	}
	if !strings.Contains(p.Subject(), ".ssh/id_rsa") { t.Fatalf("MCP Subject must be args JSON: %q", p.Subject()) }
}
func TestMCPPluginForm(t *testing.T) {
	p := Payload{ToolName: "mcp__plugin_myplug_db__query"}
	if p.MCPServer() != "plugin_myplug_db" || p.MCPTool() != "query" { t.Fatalf("%q/%q", p.MCPServer(), p.MCPTool()) }
}
func TestBashMistypedCommandFailsClosed(t *testing.T) {
	// invariant: a Bash payload whose command is the wrong type must ERROR (deny), not silently become "".
	if _, err := Parse(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":123}}`)); err == nil {
		t.Fatal("mistyped Bash command must error (fail-closed)")
	}
}
func TestMCPTolerantArgs(t *testing.T) {
	// an MCP tool whose args happen to have a non-string "command" must NOT error — classify on Raw instead.
	p, err := Parse(strings.NewReader(`{"tool_name":"mcp__shell__run","tool_input":{"command":["ls","-la"]}}`))
	if err != nil { t.Fatalf("MCP args must be tolerated: %v", err) }
	if !strings.Contains(p.Subject(), "ls") { t.Fatal("MCP Subject should carry raw args") }
}
```

- [ ] **Step 2: Run → FAIL.** `CGO_ENABLED=0 go test ./internal/hook/`.

- [ ] **Step 3: Implement.** In `payload.go`: add `"strings"` import; add `Raw json.RawMessage \`json:"-"\`` to `ToolInput`; give `Payload` a custom `UnmarshalJSON` (NOT `ToolInput` — it must see `tool_name`):

```go
// UnmarshalJSON captures the raw tool_input so the classifier can inspect MCP
// arguments, while keeping the Bash/Write path fail-closed: a wrong-typed
// command/file_path on a NON-MCP tool is a malformed payload and errors (→ the
// gate denies). MCP tool_input is arbitrary server JSON, so a non-string
// command/file_path there is tolerated — Raw carries the args.
func (p *Payload) UnmarshalJSON(b []byte) error {
	type alias Payload // no UnmarshalJSON → no recursion
	var a struct {
		alias
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return fmt.Errorf("parse hook payload: %w", err)
	}
	*p = Payload(a.alias)
	p.ToolInput.Raw = append(json.RawMessage(nil), a.ToolInput...)
	var typed struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(a.ToolInput, &typed); err != nil {
		if !strings.HasPrefix(p.ToolName, mcpPrefix) {
			return fmt.Errorf("parse tool_input: %w", err) // Bash/Write malformed → fail-closed
		}
		return nil // MCP: tolerate; Raw carries the args
	}
	p.ToolInput.Command, p.ToolInput.FilePath = typed.Command, typed.FilePath
	return nil
}
```

Note: `alias`/embedded struct decodes the scalar fields; `a.ToolInput` (RawMessage) shadows the alias's typed `ToolInput` for capture. Add the MCP helpers + Subject:

```go
const mcpPrefix = "mcp__"

func SplitMCP(name string) (server, tool string, ok bool) {
	rest, ok := strings.CutPrefix(name, mcpPrefix)
	if !ok { return "", "", false }
	server, tool, _ = strings.Cut(rest, "__")
	return server, tool, true
}
func (p Payload) IsMCP() bool      { return strings.HasPrefix(p.ToolName, mcpPrefix) }
func (p Payload) MCPServer() string { s, _, _ := SplitMCP(p.ToolName); return s }
func (p Payload) MCPTool() string   { _, t, _ := SplitMCP(p.ToolName); return t }

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
Keep the existing `Parse` (it calls `json.NewDecoder(r).Decode(&p)`, which now dispatches to `Payload.UnmarshalJSON`). Verify `Parse`'s existing signature/behavior is preserved.

- [ ] **Step 4: Run → PASS.** `CGO_ENABLED=0 go test ./internal/hook/` then `CGO_ENABLED=0 go test ./...` (confirm the gate's existing "unparseable payload" tests still deny, and Bash/Write classification is unchanged).

- [ ] **Step 5: Commit** `feat(hook): raw tool_input capture (fail-closed Bash, tolerant MCP) + MCP tool_name parsing`.

---

### Task 2: `Match` fields `mcpServer` / `mcpTool` + schema documentation

**Files:** `internal/policy/policy.go`, `internal/policy/schema.json`, `internal/policy/validate_test.go`.

**Interfaces:** `Match.McpServer []string` (json `mcpServer`), `Match.McpTool string` (json `mcpTool`).

- [ ] **Step 1: Write the test** (note: NOT a red step — the schema has no `additionalProperties:false`, so an unknown key already validates today; this test asserts a rule using the new fields validates AND round-trips through the Go struct):

```go
func TestValidateAndDecodeMCPMatch(t *testing.T) {
	doc := []byte(`{"version":1,"rules":[{"id":"m","tool":["mcp"],"reason":"x","match":{"mcpServer":["github"],"mcpTool":"(?i)delete"}}]}`)
	if err := Validate(doc); err != nil { t.Fatalf("must validate: %v", err) }
	var p Policy
	if err := json.Unmarshal(doc, &p); err != nil { t.Fatal(err) }
	if len(p.Rules[0].Match.McpServer) != 1 || p.Rules[0].Match.McpTool == "" {
		t.Fatal("mcpServer/mcpTool must decode into Match")
	}
}
```

- [ ] **Step 2: Run → FAIL** (`Match` has no `McpServer`/`McpTool` fields yet → the decode assertion fails to compile/pass).

- [ ] **Step 3: Implement.** In `policy.go` add to `Match`:
```go
	McpServer []string `json:"mcpServer,omitempty"` // MCP server segment, ANY-of exact
	McpTool   string   `json:"mcpTool,omitempty"`   // regexp on the MCP tool segment
```
In `schema.json`, under `$defs/match` properties, add (documentation + tooling; the schema doesn't reject unknown keys today, but keep it accurate):
```json
        "mcpServer": { "type": "array", "items": { "type": "string" } },
        "mcpTool": { "type": "string" },
```

- [ ] **Step 4: Run → PASS**; confirm `Validate(Default())` still nil.

- [ ] **Step 5: Commit** `feat(policy): Match.mcpServer + Match.mcpTool`.

---

### Task 3: Classifier — `"mcp"` Tool token + `mcpServer`/`mcpTool` matching (constrain-only)

**Files:** `internal/classify/match.go`, `internal/classify/classify_test.go`.

**Interfaces:** `toolIn` treats `"mcp"` as any `mcp__*`; a rule with `McpServer`/`McpTool` fires **only** on MCP and only when the parsed server/tool matches. A rule with `McpTool`/`McpServer` set can never fire on Bash (isMCP false → matched=false) — so MCP-specific rules are Bash-safe.

- [ ] **Step 1: Failing tests.** Add (import `encoding/json`; add an `mcp()` payload helper):
```go
func mcp(name, argsJSON string) hook.Payload {
	return hook.Payload{ToolName: name, PermissionMode: "default", ToolInput: hook.ToolInput{Raw: json.RawMessage(argsJSON)}}
}
func TestMCPToolTokenAndFieldMatch(t *testing.T) {
	pol := policy.Policy{Version: 1, Rules: []policy.Rule{
		{ID: "gh-del", Enabled: true, Severity: "high", AlwaysHigh: true, Tool: []string{"mcp"},
			Match: policy.Match{McpServer: []string{"github"}, McpTool: "(?i)(^|_)delete(_|$)"}, Reason: "x"}}}
	if Classify(mcp("mcp__github__delete_repo", `{}`), pol).Severity != "high" { t.Fatal("github delete must match") }
	if Classify(mcp("mcp__memory__delete_x", `{}`), pol).Severity == "high" { t.Fatal("other server must not match") }
	if Classify(bash("delete stuff", "default", "/tmp"), pol).Severity == "high" { t.Fatal("mcp rule must not fire on Bash") }
}
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** Add `"strings"` + `"github.com/lucasngucii/argus/internal/hook"` imports to `match.go` if absent. Extend `toolIn`:
```go
func toolIn(tools []string, tool string) bool {
	isMCP := strings.HasPrefix(tool, "mcp__")
	for _, t := range tools {
		if t == tool || (t == "mcp" && isMCP) { return true }
	}
	return false
}
```
In `Matches`, after the existing checks (before `return matched, false`):
```go
	if len(mt.McpServer) > 0 || mt.McpTool != "" {
		server, mtool, isMCP := hook.SplitMCP(tool)
		if !isMCP {
			matched = false
		} else {
			if len(mt.McpServer) > 0 && !contains(mt.McpServer, server) { matched = false }
			if mt.McpTool != "" {
				re, err := regexp.Compile(mt.McpTool)
				if err != nil { return false, true }
				if !re.MatchString(mtool) { matched = false }
			}
		}
	}
```
Leave `usesShellFacts` unchanged (McpServer/McpTool/Raw are not shell facts).

- [ ] **Step 4: Run → PASS**; full `go test ./...`.

- [ ] **Step 5: Commit** `feat(classify): "mcp" Tool token + mcpServer/mcpTool matching`.

---

### Task 4: Floor rule `mcp-fileop-sensitive-path` (AND-gate name-verb × sensitive path)

**Files:** `internal/policy/defaults.go`, `internal/classify/classify_test.go`.

**Rationale (from review):** do NOT extend the shared Bash floor rules to MCP (a bare path substring in freeform args would be a non-recoverable FP, e.g. a docs-search whose query mentions `~/.ssh`). Ship ONE MCP floor rule that requires **both** a file-op tool name **and** a sensitive path in the args — precise enough to stay `high`/non-downgradable.

**Interfaces:** Produces floor id `mcp-fileop-sensitive-path` (alwaysHigh, high, Tool ["mcp"]).

- [ ] **Step 1: Failing tests.**
```go
func TestMCPFileopSensitivePathIsHighFloor(t *testing.T) {
	for _, c := range []struct{ name, args string }{
		{"mcp__filesystem__write_file", `{"path":"/home/x/.ssh/authorized_keys","content":"k"}`},
		{"mcp__filesystem__delete_file", `{"path":"/home/x/.argus/policy.json"}`},
		{"mcp__fs__remove", `{"path":"/home/x/.aws/credentials"}`},
	} {
		if got := Classify(mcp(c.name, c.args), policy.Default()).Severity; got != "high" {
			t.Fatalf("%s must be high, got %s", c.name, got)
		}
	}
}
func TestMCPSearchMentioningPathNotFloored(t *testing.T) {
	// the FP the AND-gate prevents: a non-file-op tool whose args merely MENTION a path.
	if got := Classify(mcp("mcp__docs__search", `{"query":"how do I rotate ~/.ssh/id_rsa"}`), policy.Default()).Severity; got == "high" {
		t.Fatalf("a docs search mentioning .ssh must NOT be floored, got %s", got)
	}
}
func TestMCPFloorNotDowngradable(t *testing.T) {
	pol := policy.Default()
	pol.Rules = append(pol.Rules, policy.Rule{ID: "allow", Enabled: true, Allow: true, Tool: []string{"mcp"}, Match: policy.Match{Raw: ".*"}, Reason: "x"})
	if Classify(mcp("mcp__filesystem__delete_file", `{"path":"~/.ssh/id_rsa"}`), pol).Severity != "high" {
		t.Fatal("allowlist must not downgrade the MCP floor")
	}
}
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** Add to `Floor()` (before `return append(f, SelfProtectRules()...)`). The `Raw` reuses the credential/self-protect/system path shapes; the `McpTool` gate is the file-op verb set:
```go
{ID: "mcp-fileop-sensitive-path", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"mcp"},
	// A FILE-OP-named MCP tool whose args target a credential/system/self-protect
	// path. AND-gated on both signals so a non-file-op tool merely mentioning such
	// a path in freeform args (a docs search, a chat message) is NOT floored — the
	// floor stays reserved for a real write/delete against a sensitive target.
	Match: Match{
		McpTool: `(?i)(^|_)(write|delete|remove|move|copy|create|put|append|truncate|chmod|unlink)(_|$)`,
		Raw: leadBoundary + `\.ssh/(id_[A-Za-z0-9_]+|authorized_keys)\b` +
			`|` + leadBoundary + `\.ssh` + trailBoundary +
			`|` + leadBoundary + `\.aws/credentials\b` +
			`|` + leadBoundary + `\.aws` + trailBoundary +
			`|` + leadBoundary + `\.argus` + trailBoundary +
			`|` + leadBoundary + `\.claude/settings(\.local)?\.json\b` +
			`|` + leadBoundary + `\.claude` + trailBoundary +
			`|/etc/sudoers\b|>\s*/etc/`},
	Reason: "MCP file-op targeting a credential/system/self-protect path"},
```

- [ ] **Step 4: Run → PASS**; full `go test ./...`.

- [ ] **Step 5: Commit** `feat(policy): floor rule mcp-fileop-sensitive-path (name-verb AND sensitive path)`.

---

### Task 5: Seed rules `mcp-mutating-tool` + `mcp-destructive-sql-args` (both medium)

**Files:** `internal/policy/defaults.go`, `internal/classify/classify_test.go`.

**Rationale (from review):** the mutating-verb rule must use `(^|_)verb(_|$)` (not `\b`, which never splits snake_case) and include the high-impact verbs `send|publish|revoke|deploy|merge|apply|grant|transfer`. Destructive-SQL-in-args is `medium` (downgradable), consistent with the Bash `db-write` rule's severity and appropriate for a keyword heuristic over freeform args (NOT a floor).

- [ ] **Step 1: Failing tests.**
```go
func TestMCPMutatingToolIsMedium(t *testing.T) {
	for _, n := range []string{"mcp__fs__delete_file", "mcp__db__drop_table", "mcp__x__exec_command",
		"mcp__fs__write_file", "mcp__slack__send_message", "mcp__ci__deploy", "mcp__iam__grant_role", "mcp__gh__merge_pull_request"} {
		if got := Classify(mcp(n, `{"a":"b"}`), policy.Default()).Severity; got != "medium" {
			t.Fatalf("%s must be medium, got %s", n, got)
		}
	}
}
func TestMCPReadToolIsSafe(t *testing.T) {
	for _, n := range []string{"mcp__fs__read_file", "mcp__gh__list_issues", "mcp__x__get_status", "mcp__x__search", "mcp__fs__list_updates"} {
		if got := Classify(mcp(n, `{"a":"b"}`), policy.Default()).Severity; got != "safe" {
			t.Fatalf("%s must be safe, got %s", n, got)
		}
	}
}
func TestMCPDestructiveSQLArgsIsMedium(t *testing.T) {
	if got := Classify(mcp("mcp__db__query", `{"sql":"DROP TABLE users"}`), policy.Default()).Severity; got != "medium" {
		t.Fatalf("DROP in MCP args must be medium (downgradable), got %s", got)
	}
}
```
Note `list_updates` must stay safe — the `(_|$)` trailing anchor makes `update` not match inside `updates`.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** Append to `Default()`'s `p.Rules`:
```go
{ID: "mcp-mutating-tool", Enabled: true, Severity: "medium", Tool: []string{"mcp"},
	// No shell AST for MCP — the tool name is the only intent signal. Snake_case
	// is the norm, so verbs are anchored on _ / start / end (\b does NOT split _).
	Match:  Match{McpTool: `(?i)(^|_)(delete|drop|remove|destroy|truncate|write|create|update|put|patch|exec|run|kill|send|publish|revoke|deploy|merge|apply|grant|transfer)(_|$)`},
	Reason: "MCP tool with a mutating action — review before running"},
{ID: "mcp-destructive-sql-args", Enabled: true, Severity: "medium", Tool: []string{"mcp"},
	// Destructive SQL in MCP arguments. medium (ask), not a floor: args are
	// freeform JSON, so this keyword heuristic must stay downgradable — consistent
	// with the Bash db-write rule's severity for the same class of signal.
	Match:  Match{Raw: `(?i)\b(drop|truncate)\s+(table|database)\b|\bdelete\s+from\b|\.drop\(\)|deletemany`},
	Reason: "destructive SQL in MCP tool arguments"},
```

- [ ] **Step 4: Run → PASS**; full `go test ./...` (SeedRuleIDs grows by 2, dynamic test stays green).

- [ ] **Step 5: Commit** `feat(policy): seed rules mcp-mutating-tool + mcp-destructive-sql-args (medium)`.

---

### Task 6: Persist + replay the MCP subject (store/replay data path)

**Files:** `internal/cli/gate.go`, `internal/replay/replay.go`, `internal/replay/replay_test.go`.

**Rationale (from review):** today the gate writes `Command:p.ToolInput.Command` — empty for MCP — so MCP rows show blank in the Live tail and replay re-scores them as `safe` (reconstructed payload has no args). Reuse the existing `Command` column: persist the MCP subject there, and reconstruct `Raw` from it in replay. No schema migration.

**Interfaces:** MCP decisions carry their args JSON in `store.Row.Command`; `replay.Rescore` reconstructs `ToolInput.Raw` for MCP rows so re-scoring matches the original verdict.

- [ ] **Step 1: Failing test.** In `replay_test.go`:
```go
func TestRescoreMCPRowUsesArgs(t *testing.T) {
	// an MCP row whose Command holds the args JSON must re-score with a policy that
	// gates that MCP tool — proving replay reconstructs the MCP subject.
	rows := []store.Row{{Tool: "mcp__filesystem__delete_file", Command: `{"path":"/tmp/x"}`, Severity: "safe", Verdict: "allow", PermissionMode: "default"}}
	res := Rescore(rows, false, policy.Default())
	if len(res.Changed) != 1 || res.Changed[0].NewSeverity != "medium" {
		t.Fatalf("MCP row must re-score medium (mutating tool), got %+v", res.Changed)
	}
}
```

- [ ] **Step 2: Run → FAIL** (replay reconstructs only Command→Command, not Raw → Subject empty → still safe).

- [ ] **Step 3: Implement.**
- `internal/cli/gate.go` `recordDecision`: when `p.IsMCP()`, set the row's `Command` to `p.Subject()` (the args JSON) so it is stored and visible. (Keep `Tool: p.ToolName` as-is; `File` stays empty.)
- `internal/replay/replay.go`: in the payload reconstruction, set `Raw` for MCP rows:
```go
ti := hook.ToolInput{Command: r.Command, FilePath: r.File}
if strings.HasPrefix(r.Tool, "mcp__") {
	ti.Raw = json.RawMessage(r.Command)
}
p := hook.Payload{ToolName: r.Tool, PermissionMode: r.PermissionMode, CWD: r.CWD, ToolInput: ti}
```
(Add `strings`/`encoding/json` imports as needed.)

- [ ] **Step 4: Run → PASS**; full `go test ./...`.

- [ ] **Step 5: Commit** `feat(gate,replay): persist + reconstruct MCP args so MCP decisions are visible and replayable`.

---

### Task 7: Init matcher (self-healing) + doctor WARN

**Files:** `internal/cli/init_hook.go`, `internal/cli/init_test.go`, `internal/cli/doctor.go`, `internal/cli/doctor_test.go`.

**Rationale (from review):** the wired matcher must include `mcp__.*`; and a re-`init` on an existing install must actually **update** a stale matcher (today `wireHook` short-circuits on `hasGateHook` and leaves the old matcher, so the doctor's "re-run init" remedy would be a no-op). Fix `wireHook` to heal the matcher; add a `gateMatcher()` helper for the doctor WARN.

- [ ] **Step 1: Failing tests.**
  - `init_test.go`: after `Init`, the gate entry's matcher == `"Bash|Write|Edit|mcp__.*"`. And: rewrite an existing settings' gate matcher to `"Bash|Write|Edit"`, run `Init` again, assert the matcher is healed to include `mcp__.*` (and still no duplicate gate entry).
  - `doctor_test.go`: after `Init`, no matcher WARN; after downgrading the matcher to `"Bash|Write|Edit"`, `Doctor` returns its normal exit code but output contains a WARN naming the missing MCP matcher.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.**
- `init_hook.go`: add the wired matcher constant `gateMatcher = "Bash|Write|Edit|mcp__.*"`. Add `func gateMatcherOf(preToolUse []any) (string, bool)` mirroring `hasGateHook`'s traversal but returning the matcher of the entry whose hook command contains `argus gate`. In `wireHook`: if a gate entry exists but its matcher != the wired value (missing `mcp__`), update that entry's `matcher` in place and write; else append as today. Still idempotent (never duplicates the entry).
- `doctor.go`: add a non-fatal check using `gateMatcherOf`: if the gate entry's matcher does not contain `mcp__`, print `WARN hook: PreToolUse matcher does not gate MCP tools — re-run 'argus init' to update it`. Does NOT change the exit code.

- [ ] **Step 4: Run → PASS**; full `go test ./...` + `go vet ./...`.

- [ ] **Step 5: Commit** `feat(cli): init wires + heals the mcp__ matcher; doctor WARN on a stale matcher`.

---

### Task 8: Explain MCP support + corpus note + docs

**Files:** `internal/web/explain.go`, `internal/cli/explain.go` (+ `cmd/argus/main.go` if the CLI signature changes), `internal/cli/test.go`, `docs/policy.md`; tests in `internal/web/explain_test.go`.

**Rationale (from review):** a user who writes an `mcpServer`/`mcpTool` rule must be able to dry-run it. Extend `explain` to accept an MCP tool name + args JSON. Make the corpus's Bash-only boundary explicit.

- [ ] **Step 1: Failing test.** In `internal/web/explain_test.go`: POST `/api/explain` with `{"tool":"mcp__filesystem__delete_file","args":"{\"path\":\"~/.ssh/id_rsa\"}"}` → response severity `high`, verdict `deny` (proves MCP explain wires args into `ToolInput.Raw`).

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.**
- `explain.go` (web): add `Args string \`json:"args"\`` to `explainRequest`; when building the payload, if the tool name is MCP (or `Args` is set), set `ToolInput.Raw = json.RawMessage(req.Args)`. Keep Command/File for Bash/Write.
- `internal/cli/explain.go`: allow an MCP tool + args (an added optional flag or arg on `argus explain`, e.g. `--tool mcp__… --args '{...}'`); wire `Raw`. If the CLI change is larger than warranted, at minimum ensure the web path works and note the CLI addition — but prefer parity.
- `internal/cli/test.go`: add a comment on `corpusCase`/`payloadFor` stating the corpus format is Bash/file-only and MCP is intentionally covered by Go unit tests, so an `mcp__*` line is not meaningfully classified here.

- [ ] **Step 4: Docs.** In `docs/policy.md`: add `mcpServer`/`mcpTool` rows to the match-fields table and a **"Gating MCP tools"** section — default allow, the `medium` mutating-verb + destructive-SQL rules, the `high` floor (file-op name AND sensitive path), an example per-server rule, and the honest limits: no semantic parsing (name+args-regex only); a mutating tool with an innocuous name and benign-looking args is judged `allow` unless a per-server rule is added; the floor is deliberately AND-gated to avoid non-recoverable false positives on freeform args.

- [ ] **Step 5: Full-suite gate + commit.** `CGO_ENABLED=0 go test ./... && go vet ./...` green. Commit `feat(web,cli): explain MCP tool calls; docs: MCP gating + corpus scope note`.

---

## Self-Review

**Spec coverage:** payload raw-capture with fail-closed-Bash/tolerant-MCP (T1) · mcpServer/mcpTool + schema (T2) · "mcp" token + constrain-only matching, Bash-safe (T3) · precise `high` floor AND-gating name-verb × sensitive-path (T4) · two `medium` seed rules with `(^|_)verb(_|$)` snake-case anchoring + expanded verb list + destructive-SQL-as-medium (T5) · store+replay threading so MCP is visible and replayable (T6) · self-healing matcher + accurate doctor WARN (T7) · MCP-explain + corpus scope note + honest docs (T8). Default posture = allow (no rule fires ⇒ safe).

**Review fixes applied (rev 1 → rev 2):** UnmarshalJSON moved to Payload level, tolerant only for MCP (Bash stays fail-closed) [T1]; verb regex `\b`→`(^|_)…(_|$)` and verbs `send|publish|revoke|deploy|merge|apply|grant|transfer` added [T5]; floor no longer a bare args-substring — AND-gated on file-op tool name so a docs-search mentioning `.ssh` is NOT floored [T4]; destructive-SQL demoted floor→medium (consistent with `db-write`) [T5]; store/replay data hole closed [T6]; doctor "re-run init" made real via self-healing wireHook [T7]; MCP explain added + corpus boundary made explicit [T8]; Task 2 red-step reframed (schema has no additionalProperties:false — the test asserts acceptance+decode, not rejection).

**Placeholder scan:** every step carries literal Go/JSON, including the doctor `gateMatcherOf` helper (named, not "TBD").

**Type/name consistency:** `Payload.UnmarshalJSON`, `ToolInput.Raw`, `SplitMCP`, `IsMCP/MCPServer/MCPTool`, `Match.McpServer/McpTool`, the `"mcp"` token, rule ids `mcp-fileop-sensitive-path`/`mcp-mutating-tool`/`mcp-destructive-sql-args` — identical across producer/consumer. `contains` reused; `leadBoundary`/`trailBoundary` reused (verified to include the quote chars a JSON path is wrapped in).

**Invariants:** hot path fail-closed preserved (T1 test proves a mistyped Bash command still errors); `high` floor stays a genuine catastrophe (T4 AND-gate + the FP-avoidance test); `verdict.Map` untouched; `classify` pure; self-protection now covers a file-op MCP tool against Argus's own paths.

**Known v1 gaps (documented in T8 + spec):** a mutating MCP tool with an innocuous name and benign-looking args is `allow` (mitigated by per-server user rules; an "ask-once-per-new-(server,tool)" resolved in the dirty shell is noted for a later iteration); camelCase MCP tool names (rare vs. snake_case) are not caught by the verb anchors; the corpus harness stays Bash/file-only by design.
