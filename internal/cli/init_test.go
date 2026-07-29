package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

// seedSettingsWithUnrelatedHook writes a settings.json with a pre-existing,
// unrelated PreToolUse hook (and an unrelated top-level key) so tests can
// assert Init merges into hooks.PreToolUse rather than clobbering it.
func seedSettingsWithUnrelatedHook(t *testing.T, home string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{
		"otherKey": "value",
		"hooks": {
			"PreToolUse": [
				{"matcher": "AskUserQuestion", "hooks": [{"type": "command", "command": "bash unrelated-skip-questions.sh"}]}
			]
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readSettingsFile(t *testing.T, home string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// gateHookCount counts PreToolUse entries whose hooks list runs gateCommand.
func gateHookCount(settings map[string]any) int {
	hooks, _ := settings["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	count := 0
	for _, entry := range preToolUse {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, gateCommand) {
				count++
			}
		}
	}
	return count
}

func TestInitCreatesPolicyDBAndPreservesExistingHook(t *testing.T) {
	home := t.TempDir()
	seedSettingsWithUnrelatedHook(t, home)

	if err := Init(home); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if _, err := policy.Load(filepath.Join(home, ".argus", "policy.json")); err != nil {
		t.Fatalf("policy.json invalid: %v", err)
	}

	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.PolicyVersionCount()
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("policy_versions has %d rows, want >= 1", n)
	}

	settings := readSettingsFile(t, home)
	if settings["otherKey"] != "value" {
		t.Fatalf("unrelated top-level key was clobbered: %v", settings)
	}
	raw, _ := json.Marshal(settings)
	if !strings.Contains(string(raw), "unrelated-skip-questions.sh") {
		t.Fatalf("pre-seeded unrelated PreToolUse hook was lost: %s", raw)
	}
	if gateHookCount(settings) != 1 {
		t.Fatalf("argus gate hook entries = %d, want 1: %s", gateHookCount(settings), raw)
	}
}

func TestInitTwiceDoesNotDuplicateHook(t *testing.T) {
	home := t.TempDir()
	seedSettingsWithUnrelatedHook(t, home)

	if err := Init(home); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if err := Init(home); err != nil {
		t.Fatalf("second Init: %v", err)
	}

	settings := readSettingsFile(t, home)
	if got := gateHookCount(settings); got != 1 {
		t.Fatalf("argus gate hook entries after two Init calls = %d, want 1", got)
	}
}

func TestDoctorAfterInit(t *testing.T) {
	home := t.TempDir()
	if err := Init(home); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if code := Doctor(home, &out); code != 0 {
		t.Fatalf("Doctor after Init = %d, want 0\noutput:\n%s", code, out.String())
	}
}

func TestDoctorFailsWhenHookRemoved(t *testing.T) {
	home := t.TempDir()
	if err := Init(home); err != nil {
		t.Fatal(err)
	}

	// Simulate the hook wiring being deleted from settings.json.
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if code := Doctor(home, &out); code == 0 {
		t.Fatalf("Doctor with hook removed = 0, want non-zero\noutput:\n%s", out.String())
	}
}

func TestInitImportsLegacyDecisions(t *testing.T) {
	home := t.TempDir()
	legacyDir := filepath.Join(home, ".claude", "agent-review")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"ts":"2026-01-01T00:00:00Z","verdict":"ask","severity":"high","reason":"rm recursive","session":"s1","cwd":"/x","tool":"Bash","command":"rm -rf /x","file":""}
{"ts":"2026-01-01T00:00:01Z","verdict":"allow","tool":"Bash","command":"echo hi","session":"s1","cwd":"/x","file":""}
`
	if err := os.WriteFile(filepath.Join(legacyDir, "decisions.jsonl"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Init(home); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Command == "rm -rf /x" && r.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy decision not imported, got rows: %+v", rows)
	}
}

func TestInitWiresMCPMatcher(t *testing.T) {
	home := t.TempDir()
	if err := Init(home); err != nil {
		t.Fatal(err)
	}
	m := readGateMatcher(t, home)
	if !strings.Contains(m, "mcp__") {
		t.Fatalf("fresh init matcher must gate MCP, got %q", m)
	}
}

func TestInitHealsStaleMatcher(t *testing.T) {
	home := t.TempDir()
	if err := Init(home); err != nil {
		t.Fatal(err)
	}
	setGateMatcher(t, home, "Bash|Write|Edit") // simulate an old install
	if err := Init(home); err != nil {           // re-init must heal
		t.Fatal(err)
	}
	m := readGateMatcher(t, home)
	if !strings.Contains(m, "mcp__") {
		t.Fatalf("re-init must heal the matcher to include mcp__, got %q", m)
	}
	// and it must NOT have duplicated the gate entry
	if n := countGateEntries(t, home); n != 1 {
		t.Fatalf("re-init must not duplicate the gate entry, got %d", n)
	}
}

// readGateMatcher reads ~/.claude/settings.json, finds the PreToolUse entry
// whose inner hook command contains "argus gate", and returns its matcher.
func readGateMatcher(t *testing.T, home string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	hooks, _ := s["hooks"].(map[string]any)
	for _, e := range asSlice(hooks["PreToolUse"]) {
		m, _ := e.(map[string]any)
		for _, h := range asSlice(m["hooks"]) {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "argus gate") {
				mt, _ := m["matcher"].(string)
				return mt
			}
		}
	}
	t.Fatal("no argus gate entry found")
	return ""
}

// setGateMatcher reads ~/.claude/settings.json, finds the PreToolUse entry
// whose inner hook command contains "argus gate", sets its matcher, and writes
// the file back.
func setGateMatcher(t *testing.T, home, matcher string) {
	t.Helper()
	p := filepath.Join(home, ".claude", "settings.json")
	b, _ := os.ReadFile(p)
	var s map[string]any
	json.Unmarshal(b, &s)
	hooks, _ := s["hooks"].(map[string]any)
	for _, e := range asSlice(hooks["PreToolUse"]) {
		m, _ := e.(map[string]any)
		for _, h := range asSlice(m["hooks"]) {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "argus gate") {
				m["matcher"] = matcher
			}
		}
	}
	nb, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(p, nb, 0o644)
}

// countGateEntries counts PreToolUse entries whose hooks run the argus gate command.
func countGateEntries(t *testing.T, home string) int {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	var s map[string]any
	json.Unmarshal(b, &s)
	hooks, _ := s["hooks"].(map[string]any)
	n := 0
	for _, e := range asSlice(hooks["PreToolUse"]) {
		m, _ := e.(map[string]any)
		for _, h := range asSlice(m["hooks"]) {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "argus gate") {
				n++
			}
		}
	}
	return n
}

// asSlice converts v to []any if it is one, else returns an empty slice.
func asSlice(v any) []any { s, _ := v.([]any); return s }

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
