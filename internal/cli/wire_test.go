package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readWiredSettingsFile returns the raw settings.json bytes as a string. This
// is distinct from the existing readSettingsFile helper in init_test.go
// (which decodes into map[string]any) — same package, different signature,
// so it needs its own name.
func readWiredSettingsFile(t *testing.T, home string) string {
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
	got := readWiredSettingsFile(t, home)
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
	got := readWiredSettingsFile(t, home)
	if n := strings.Count(got, "argus gate"); n != 1 {
		t.Errorf("Wire must be idempotent: %d gate entries, want 1\n%s", n, got)
	}
}

func TestWireUnknownHarnessErrors(t *testing.T) {
	if err := Wire("bogus", t.TempDir()); err == nil {
		t.Error("Wire(unknown harness) must error, got nil")
	}
}
