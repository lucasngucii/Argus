package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexWireWritesHooksJSON(t *testing.T) {
	home := t.TempDir()
	if err := Wire("codex", home); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "argus gate --harness=codex") {
		t.Errorf("codex wiring must write the gate command; got %s", b)
	}
}

// TestCodexWirePreservesExistingHook mirrors the Claude Code
// preserves-existing-hook coverage in init_test.go: Wire must decode the
// existing file into a generic map so an unrelated PreToolUse entry and an
// unrelated top-level key round-trip byte-for-byte, with the argus entry
// merely appended.
func TestCodexWirePreservesExistingHook(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
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
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Wire("codex", home); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(b, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["otherKey"] != "value" {
		t.Fatalf("unrelated top-level key was clobbered: %s", b)
	}
	if !strings.Contains(string(b), "unrelated-skip-questions.sh") {
		t.Fatalf("pre-seeded unrelated PreToolUse hook was lost: %s", b)
	}
	if !strings.Contains(string(b), "argus gate --harness=codex") {
		t.Fatalf("argus gate entry was not appended: %s", b)
	}
}

func TestCodexWireIsIdempotent(t *testing.T) {
	home := t.TempDir()
	_ = Wire("codex", home)
	_ = Wire("codex", home)
	b, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if n := strings.Count(string(b), "argus gate"); n != 1 {
		t.Errorf("idempotent: %d gate entries, want 1", n)
	}
}
