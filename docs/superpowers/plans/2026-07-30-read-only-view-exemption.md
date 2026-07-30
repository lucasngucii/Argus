# Metadata-Read View Exemption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the self-protect / credential floor rules from firing on a pure metadata listing (`ls`/`stat`/`du`/…) of a protected path, so `ls ~/.argus` is `safe` while every write, content read, `git`, or mixed chain stays floored.

**Architecture:** A pure predicate `isReadOnlyChain` in a new `internal/classify/readonly.go`, wired into `classify.Classify`'s rule loop to make the three built-in floor rules decline to match (non-match, not downgrade) on a listing chain — Bash-only, built-in-floor-only. Plus two independent over-broad-match narrowings (`disk-format`, `docker-service`).

**Tech Stack:** Go 1.26, `internal/classify`, `internal/policy`, `internal/shellast`. `CGO_ENABLED=0`.

## Global Constraints

- Go **1.26**, `CGO_ENABLED=0`, pure-Go only. No new dependency.
- **DEPENDS ON** the shellast compound-flatten fix (`docs/superpowers/plans/2026-07-30-shellast-compound-flatten.md`) being merged first — `isReadOnlyChain`'s "every command is a listing verb" quantifier is only sound once `f.Commands` enumerates commands inside compound statements. Do not start this plan until that one is green on the base branch.
- `classify.Classify` stays **pure** (CLAUDE.md §1): no I/O, clock, globals, or panic.
- **§4/§5 are being deliberately narrowed** (user-approved, per spec) — the CLAUDE.md edit is part of Task 2 and lands with the code. The mechanism is **non-match, not downgrade**: the `continue` runs before severity/`floorHit` is set, so no code path lowers an already-matched `AlwaysHigh` verdict.
- Exemption is **Bash-only** (gated on `tool == "Bash"`) and **built-in-floor-only** (gated on `isBuiltinFloor`). MCP and content reads are never exempt.
- `listingVerbs` is **closed and final** — exactly `{ls, stat, du, realpath, basename, dirname, readlink}`. Adding a write/content/exec-capable verb reopens the floor.
- Every exemption bypass attempt is a **corpus entry that must stay caught** (CLAUDE.md Testing). Table-driven, deterministic.
- Conventional commits, identity `lucasngucii <lucasalehwork@gmail.com>`, **never** `Co-Authored-By: Claude`. Three logical commits (Task 2 bundles exemption + CLAUDE.md + doc comments; Tasks 3, 4 are independent).
- Source of truth: `docs/superpowers/specs/2026-07-30-read-only-view-exemption-design.md`.

---

### Task 1: `readonly.go` — the pure predicate and verb set

**Files:**
- Create: `internal/classify/readonly.go`
- Test: `internal/classify/readonly_test.go`

**Interfaces:**
- Consumes: `shellast.Facts` (`ParseOK`, `Obfuscated`, `Commands[].Name/.Resolved`, `Redirects`, `PipeSinks`).
- Produces: `isReadOnlyChain(f shellast.Facts) bool`, `isSelfProtectOrCredential(ruleID string) bool`, `var listingVerbs map[string]bool` — all package-private, consumed by `classify.go` in Task 2.

- [ ] **Step 1: Write the failing test**

```go
package classify

import (
	"testing"

	"github.com/lucasngucii/argus/internal/shellast"
)

func TestIsReadOnlyChain(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"single listing", "ls /x", true},
		{"stat", "stat /x", true},
		{"multi listing", "ls /x && stat /y", true},
		{"listing pipe listing", "ls /x", true},
		{"content read", "cat /x", false},
		{"grep", "grep foo /x", false},
		{"write verb", "rm -rf /x", false},
		{"mixed chain", "ls /x && rm -rf /x", false},
		{"redirect", "ls /x > /y", false},
		{"pipe to writer", "ls /x | tee /y", false},
		{"obfuscated", "ls $(evil) /x", false},
		{"empty commands", "X=$(rm -rf /x)", false},
		{"find is not a listing verb", "find /x -delete", false},
		{"sort is not a listing verb", "sort -o /y /x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isReadOnlyChain(shellast.Extract(tc.cmd)); got != tc.want {
				t.Fatalf("%q: isReadOnlyChain = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestIsReadOnlyChainConditionNegatives(t *testing.T) {
	// One negative per fail-closed condition, constructed as Facts directly so
	// each condition is isolated.
	ls := shellast.Cmd{Name: "ls", Resolved: true}
	base := shellast.Facts{ParseOK: true, Commands: []shellast.Cmd{ls}}
	if !isReadOnlyChain(base) {
		t.Fatal("baseline clean listing must be read-only")
	}
	parseFail := base
	parseFail.ParseOK = false
	if isReadOnlyChain(parseFail) {
		t.Fatal("!ParseOK must not be read-only")
	}
	obf := base
	obf.Obfuscated = true
	if isReadOnlyChain(obf) {
		t.Fatal("Obfuscated must not be read-only")
	}
	empty := shellast.Facts{ParseOK: true}
	if isReadOnlyChain(empty) {
		t.Fatal("empty Commands must not be read-only")
	}
	redir := base
	redir.Redirects = []string{"/y"}
	if isReadOnlyChain(redir) {
		t.Fatal("a redirect must not be read-only")
	}
	unresolved := shellast.Facts{ParseOK: true, Commands: []shellast.Cmd{{Name: "ls", Resolved: false}}}
	if isReadOnlyChain(unresolved) {
		t.Fatal("an unresolved command must not be read-only")
	}
	nonListing := shellast.Facts{ParseOK: true, Commands: []shellast.Cmd{{Name: "cat", Resolved: true}}}
	if isReadOnlyChain(nonListing) {
		t.Fatal("a non-listing command must not be read-only")
	}
	sink := shellast.Facts{ParseOK: true, Commands: []shellast.Cmd{ls}, PipeSinks: []string{"tee"}}
	if isReadOnlyChain(sink) {
		t.Fatal("a non-listing pipe sink must not be read-only")
	}
}

func TestIsSelfProtectOrCredential(t *testing.T) {
	for _, id := range []string{"self-protect-claude-settings", "self-protect-argus", "credential-system-write"} {
		if !isSelfProtectOrCredential(id) {
			t.Fatalf("%q must be recognized", id)
		}
	}
	for _, id := range []string{"rm-catastrophic", "disk-format", "sudo", ""} {
		if isSelfProtectOrCredential(id) {
			t.Fatalf("%q must NOT be recognized", id)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/classify/ -run 'TestIsReadOnlyChain|TestIsSelfProtectOrCredential' -v`
Expected: FAIL to compile (`isReadOnlyChain`/`isSelfProtectOrCredential`/`listingVerbs` undefined).

- [ ] **Step 3: Create `internal/classify/readonly.go`**

```go
package classify

import "github.com/lucasngucii/argus/internal/shellast"

// listingVerbs are the commands that reveal only names/metadata (never file
// content) and have no output-flag, in-place, delete, or exec mode in ANY
// argument form — audited against GNU and BSD/macOS variants. This set is
// closed and load-bearing: adding a verb with any write/content/exec mode would
// let that operation masquerade as a listing and suppress a self-protect or
// credential floor. Deliberately excluded: content readers (cat/grep/head/…),
// find (-delete/-exec), sort/uniq/tree (output flag/positional), xxd/rg/less
// (write or exec), and git (repo-local config can exec with no argv signal).
var listingVerbs = map[string]bool{
	"ls": true, "stat": true, "du": true, "realpath": true,
	"basename": true, "dirname": true, "readlink": true,
}

// isReadOnlyChain reports whether f is a pure metadata-listing chain: every
// command lists names/metadata and none reads content, writes, or executes.
// Fail-closed — any parse failure, obfuscation, empty command list, redirect,
// or non-listing command/pipe-sink returns false. The universal quantifier over
// Commands plus the non-empty guard is the security core: a mixed chain
// (`ls x && rm -rf x`) fails on the write verb, and an empty-command shell
// (`X=$(rm …)`) fails the non-empty guard. Depends on shellast surfacing every
// executed command (including inside if/for/while/case/…); without that this
// quantifier would be unsound.
func isReadOnlyChain(f shellast.Facts) bool {
	if !f.ParseOK || f.Obfuscated || len(f.Commands) == 0 || len(f.Redirects) != 0 {
		return false
	}
	for _, c := range f.Commands {
		if !c.Resolved || !listingVerbs[c.Name] {
			return false
		}
	}
	// Every pipe RHS also surfaces as a Command (so the loop above already
	// covers it); this is cheap fail-closed defense-in-depth.
	for _, s := range f.PipeSinks {
		if !listingVerbs[s] {
			return false
		}
	}
	return true
}

// isSelfProtectOrCredential reports whether ruleID is one of the three built-in
// floor rules whose protected paths are non-secret enough that a pure metadata
// listing is not a violation. Keyed by ID (only these three need it — no
// policy.Match field, per YAGNI). INVARIANT: these rules' regexes in
// internal/policy/defaults.go must never be broadened to cover secret file
// CONTENT — a listing reveals no content, so the exemption stays safe only
// while listingVerbs stays metadata-only. See the doc comments on those rules.
func isSelfProtectOrCredential(ruleID string) bool {
	switch ruleID {
	case "self-protect-claude-settings", "self-protect-argus", "credential-system-write":
		return true
	}
	return false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/classify/ -run 'TestIsReadOnlyChain|TestIsSelfProtectOrCredential' -v`
Expected: PASS. (If `shellast.Cmd` field names differ from `{Name, Resolved}`, fix the test to match `internal/shellast/parse.go:18-22` — they are `Name string`, `Resolved bool`.)

- [ ] **Step 5: Run the full suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/classify/readonly.go internal/classify/readonly_test.go
git commit -m "feat(classify): add isReadOnlyChain metadata-listing predicate"
```

---

### Task 2: Wire the exemption into `Classify` + narrow CLAUDE.md §4/§5 + rule doc comments

**Files:**
- Modify: `internal/classify/classify.go` (the `consider` closure and its two call sites, `internal/classify/classify.go:95-136`)
- Modify: `CLAUDE.md` (§4 line 14, §5 line 15)
- Modify: `internal/policy/defaults.go` (doc comments on the three rules)
- Test: `internal/classify/selfprotect_test.go`

**Interfaces:**
- Consumes: `isReadOnlyChain`, `isSelfProtectOrCredential` (Task 1); the existing `tool` (`effectiveTool(p)`), `f`, `r` in `Classify` scope.
- Produces: the three built-in floor rules decline to fire on a Bash listing chain.

- [ ] **Step 1: Write the failing test**

Add to `internal/classify/selfprotect_test.go` (package `classify`; uses the existing `sev`/`bash` helpers and, for the tool-boundary case, a `hook.Payload` directly).

```go
func TestListingExemptionAllowsMetadataReads(t *testing.T) {
	for _, cmd := range []string{
		"ls ~/.argus", "ls ~/.claude", "ls ~/.ssh", "stat ~/.aws",
		"stat ~/.claude/settings.json", "du ~/.claude/projects",
		"ls ~/.argus && stat ~/.claude",
	} {
		if got := sev(cmd, "/tmp"); got != "safe" {
			t.Fatalf("%q: metadata listing must be safe, got %s", cmd, got)
		}
	}
}

func TestListingExemptionStillFloorsEverythingElse(t *testing.T) {
	for _, cmd := range []string{
		// writes/deletes
		"rm -rf ~/.claude", "rm -rf ~/.argus",
		"echo x > ~/.claude/settings.json", "cat a > ~/.argus/db",
		// content reads (the main line held)
		"cat ~/.claude/settings.json", "cat ~/.claude/settings.local.json",
		"grep token ~/.claude/settings.local.json",
		"cat ~/.ssh/id_rsa", "grep key ~/.aws/credentials",
		"cat ~/.argus/policy.json",
		// disguised writes/exec via non-listing verbs
		"find ~/.claude -delete", "sort -o ~/.claude/settings.json in",
		"uniq in ~/.argus/db",
		// git (all forms floored)
		"git -C ~/.claude show HEAD:settings.local.json",
		// structural
		"cat ~/.claude/x && rm -rf ~/.argus", "X=$(rm -rf ~/.claude)",
		"ls $(evil) ~/.claude", "ls ~/.claude | tee /other",
		`bash -c "ls ~/.claude"`,
	} {
		if got := sev(cmd, "/tmp"); rank(got) < rank("high") {
			t.Fatalf("%q must stay high, got %s", cmd, got)
		}
	}
}

func TestListingExemptionIsBashOnly(t *testing.T) {
	// A Write-tool payload to a protected path must stay floored (tool != Bash).
	for _, fp := range []string{"~/.claude/settings.json", "~/.ssh/id_rsa"} {
		p := hook.Payload{ToolName: "Write", PermissionMode: "default",
			ToolInput: hook.ToolInput{FilePath: fp}}
		if got := Classify(p, policy.Default()).Severity; rank(got) < rank("high") {
			t.Fatalf("Write to %q must stay high, got %s", fp, got)
		}
	}
}

func TestListingExemptionIsBuiltinFloorOnly(t *testing.T) {
	// A USER policy rule reusing a built-in floor ID must NOT get the exemption.
	pol := policy.File{Version: 1, Rules: []policy.Rule{{
		ID: "self-protect-argus", Enabled: true, AlwaysHigh: true, Severity: "high",
		Tool: []string{"Bash"}, Reason: "user rule", Match: policy.Match{Raw: `secretfile`},
	}}}.Effective()
	got := Classify(bash("ls secretfile", "default", "/tmp"), pol).Severity
	if rank(got) < rank("high") {
		t.Fatalf("user rule with built-in ID must still floor, got %s", got)
	}
}
```

Ensure the test file imports `hook` and `policy` (add to the import block if missing).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/classify/ -run TestListingExemption -v`
Expected: FAIL — `TestListingExemptionAllowsMetadataReads` fails (listings still floored); the others pass or fail depending, but the positive test proves the exemption isn't wired yet.

- [ ] **Step 3: Add the `isBuiltinFloor` parameter and exemption to `consider`**

In `internal/classify/classify.go`, change the closure signature from
`consider := func(rules []policy.Rule) {` to
`consider := func(rules []policy.Rule, isBuiltinFloor bool) {`.

Immediately after the existing `if !ok { continue }` (currently `internal/classify/classify.go:104-106`), insert:

```go
			// Read-only view exemption (CLAUDE.md §4/§5, narrowed): a pure
			// metadata listing (ls/stat/du) of a protected path is not a
			// self-protect/credential violation. Bash-only and built-in-floor
			// only. Runs BEFORE severity/floorHit is set, so this is a narrowed
			// match, never a downgrade of an already-matched floor.
			if isBuiltinFloor && tool == "Bash" &&
				isSelfProtectOrCredential(r.ID) && isReadOnlyChain(f) {
				continue
			}
```

Update the two call sites (currently `internal/classify/classify.go:135-136`):

```go
	consider(policy.Floor(), true)
	consider(pol.Rules, false)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/classify/ -run TestListingExemption -v`
Expected: PASS (all four).

- [ ] **Step 5: Narrow CLAUDE.md §4 and §5**

In `CLAUDE.md`, replace line 14:

```
4. **`high` is a floor.** An `alwaysHigh` match cannot be downgraded by policy or allowlist. Never add a code path that can.
```

with:

```
4. **`high` is a floor.** An `alwaysHigh` match that *fires* cannot be downgraded by policy or allowlist — never add a code path that can. A rule may only *decline to match* (a narrowed match condition) when the narrowing is fail-closed: any parse failure, obfuscation, redirect, pipe, mixed chain, empty command list, or non-listing/write/exec command yields no exemption. Only a pure metadata-listing chain (`ls`/`stat`/`du`, Bash-only) is ever exempt.
```

Replace line 15:

```
5. **Self-protection stays high.** Never exempt Argus's own config / binary / hook / db paths.
```

with:

```
5. **Self-protection stays high.** Self-protection floors writes, deletes, and all content reads of Argus's own config / binary / hook / db paths and credential paths. Only a pure metadata listing (`ls`/`stat`/`du` — names and metadata, never content) is exempt, Bash-only, via `internal/classify/readonly.go`; MCP and content reads are never exempt.
```

- [ ] **Step 6: Add the invariant doc comments to the three rules**

In `internal/policy/defaults.go`, prepend a one-line comment to each of `self-protect-claude-settings`, `self-protect-argus` (both in `SelfProtectRules()`), and `credential-system-write` (in `Floor()`), e.g.:

```go
			// LISTING-EXEMPT (classify.isSelfProtectOrCredential): a pure ls/stat
			// of these paths is `safe`. These paths must stay non-secret-CONTENT
			// (a listing reveals only names) — never broaden this regex to a file
			// whose contents are a secret without revisiting readonly.go.
```

(Adapt wording per rule; `credential-system-write` already guards secret content, so note that its content reads stay floored and only metadata listing is exempt.)

- [ ] **Step 7: Run the full suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/classify/classify.go internal/classify/selfprotect_test.go CLAUDE.md internal/policy/defaults.go
git commit -m "feat(classify): exempt pure metadata listings from self-protect/credential floors"
```

---

### Task 3: Narrow `disk-format` — drop the bare `if=` alternative

**Files:**
- Modify: `internal/policy/defaults.go` (`disk-format` rule + its doc comment)
- Test: `internal/classify/classify_test.go`

**Interfaces:**
- Consumes: the `disk-format` rule's `Match.ArgMatches`.
- Produces: `dd if=/dev/sda of=backup.img` no longer floors; device writes/erase still do.

- [ ] **Step 1: Write the failing test**

```go
func TestDiskFormatAllowsDeviceBackup(t *testing.T) {
	if got := sev("dd if=/dev/sda of=backup.img bs=4M", "/tmp"); got == "high" {
		t.Fatalf("device backup (read into a file) must not floor, got %s", got)
	}
	for _, cmd := range []string{
		"dd if=/dev/zero of=/dev/sda", "dd of=/dev/sda", "diskutil eraseDisk x",
	} {
		if got := sev(cmd, "/tmp"); got != "high" {
			t.Fatalf("%q must stay high, got %s", cmd, got)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/classify/ -run TestDiskFormatAllowsDeviceBackup -v`
Expected: FAIL on the first case (`if=` still matches).

- [ ] **Step 3: Drop `if=` from the rule and update its comment**

In `internal/policy/defaults.go`, the `disk-format` rule's `ArgMatches: `if=|of=/dev/|erase`` becomes `ArgMatches: `of=/dev/|erase``. Update the rule's doc comment (currently says "reading or writing a raw device (if=…, of=/dev/…)") to reflect that a device *read* (e.g. `dd if=/dev/sda of=backup.img`) is no longer floored — only an output to a raw device (`of=/dev/…`) or an erase is.

- [ ] **Step 4: Update the stale test comment**

In `internal/classify/classify_test.go` around the existing dd/device floor test (the comment near line 470 asserting "Reading from … a device must hit the high floor"), correct it: reading a device into a *file* is a backup and is no longer floored; only writing a raw device or erasing is. Adjust any existing assertion that expected `dd if=/dev/… of=<file>` to be high (there should be none per review — `TestDdWriteToDeviceIsHighFloor`'s cases all match via `of=/dev/` — but verify and fix if present).

- [ ] **Step 5: Run tests**

Run: `go test ./internal/classify/ -run 'TestDiskFormat|TestDd' -v` then `go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/defaults.go internal/classify/classify_test.go
git commit -m "fix(policy): disk-format floors device output, not device reads"
```

---

### Task 4: Narrow `docker-service` — noun → mutating verb

**Files:**
- Modify: `internal/policy/defaults.go` (`docker-service` rule)
- Test: `internal/classify/classify_test.go`

**Interfaces:**
- Consumes: the `docker-service` rule's `Match` (switches from `ArgsContain` to `ArgMatches`).
- Produces: `docker service ls`/`ps`/`inspect` no longer ask; mutating docker ops still do.

- [ ] **Step 1: Write the failing test**

```go
func TestDockerServiceNarrowedToMutations(t *testing.T) {
	for _, cmd := range []string{"docker service ls", "docker stack ps s", "docker service inspect w"} {
		if got := sev(cmd, "/tmp"); got != "safe" {
			t.Fatalf("%q (a view) must be safe, got %s", cmd, got)
		}
	}
	for _, cmd := range []string{
		"docker service create --name x img", "docker service rm w",
		"docker system prune -f", "docker compose down", "docker-compose down",
	} {
		if got := sev(cmd, "/tmp"); got != "medium" {
			t.Fatalf("%q (a mutation) must be medium, got %s", cmd, got)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/classify/ -run TestDockerServiceNarrowedToMutations -v`
Expected: FAIL on the view cases (`ArgsContain` fires on the noun).

- [ ] **Step 3: Switch the rule to `ArgMatches`**

In `internal/policy/defaults.go`, the `docker-service` rule currently uses
`Match: Match{Cmd: []string{"docker", "docker-compose"}, ArgsContain: []string{"service", "stack", "swarm", "prune", "down"}}`.
Change it to:

```go
			Match: Match{Cmd: []string{"docker", "docker-compose"},
				ArgMatches: `(?i)\b(service|stack|swarm)\s+(create|rm|remove|scale|update|deploy|leave|init|rollback)\b|\bsystem\s+prune\b|\bcompose\s+down\b|\bprune\b|\bdown\b`},
```

Update the rule's doc comment to explain the noun→verb narrowing (views no longer ask). Note: the bare `\bprune\b`/`\bdown\b` alternatives make `system prune`/`compose down` redundant but keep the hyphenated `docker-compose down` (args = just `down`) caught.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/classify/ -run TestDocker -v` then `go test ./...`
Expected: PASS. (Check the existing `TestDockerComposeHyphenatedIsMedium`/`TestDockerBenignStaysSafe` still pass; per review they do.)

- [ ] **Step 5: Commit**

```bash
git add internal/policy/defaults.go internal/classify/classify_test.go
git commit -m "fix(policy): docker-service asks on mutating verbs, not listing subcommands"
```

---

## Self-Review Notes

- **Spec coverage:** Task 1 (predicate + verbs) + Task 2 (wiring + §4/§5 + doc comments) = the exemption; Task 3 = disk-format; Task 4 = docker-service. Three commits (Task 2 is one logical change bundling code + invariant edit + comments), matching the spec's decomposition.
- **Type consistency:** `shellast.Cmd` is `{Name string, Resolved bool}` (`internal/shellast/parse.go:18-22`); `isReadOnlyChain(shellast.Facts) bool`; `isSelfProtectOrCredential(string) bool`; `consider(rules []policy.Rule, isBuiltinFloor bool)`. `policy.File{Version, Rules}.Effective()` and `policy.Default()` are the existing constructors (see `internal/policy`). `hook.Payload`/`hook.ToolInput` fields `ToolName`/`FilePath` per `internal/hook/payload.go`.
- **Dependency:** requires the shellast compound-flatten plan merged first (Global Constraints).
- **No placeholders:** every step has runnable commands and complete code.
