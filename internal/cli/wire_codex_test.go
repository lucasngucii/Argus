package cli

import (
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

func TestCodexWireIsIdempotent(t *testing.T) {
	home := t.TempDir()
	_ = Wire("codex", home)
	_ = Wire("codex", home)
	b, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if n := strings.Count(string(b), "argus gate"); n != 1 {
		t.Errorf("idempotent: %d gate entries, want 1", n)
	}
}
