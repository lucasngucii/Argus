package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCodexConfig writes ~/.codex/config.toml with body under home.
func writeCodexConfig(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCodexProbeFailsWhenFlagOff(t *testing.T) {
	home := t.TempDir()
	_ = Wire("codex", home) // hooks.json only, no flag
	if err := Probe("codex", home); err == nil || !strings.Contains(err.Error(), "hooks") {
		t.Errorf("probe must FAIL and name the flag when off; got %v", err)
	}
}

func TestCodexProbePassesForEitherFlagKey(t *testing.T) {
	for _, body := range []string{"[features]\nhooks = true\n", "[features]\ncodex_hooks = true\n"} {
		home := t.TempDir()
		_ = Wire("codex", home)
		writeCodexConfig(t, home, body)
		if err := Probe("codex", home); err != nil {
			t.Errorf("probe must PASS for %q; got %v", body, err)
		}
	}
}

func TestCodexProbeFailClosedOnMisplacedFlag(t *testing.T) {
	// key under a DIFFERENT table must NOT PASS (it doesn't enable hooks).
	tests := []string{
		"[features.experimental]\nhooks = true\n",
		"[[features]]\nhooks = true\n",
	}
	for _, body := range tests {
		home := t.TempDir()
		_ = Wire("codex", home)
		writeCodexConfig(t, home, body)
		if Probe("codex", home) == nil {
			t.Errorf("hooks under %q must FAIL (not [features])", body)
		}
	}
}
