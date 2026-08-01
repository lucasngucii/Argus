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

func TestCodexProbeFailClosedOnFlagInsideMultilineString(t *testing.T) {
	// A [features] header and a hooks = true line that appear INSIDE a TOML
	// multiline basic string body must not be read as real TOML: they are
	// string content, not a table header/key, so the probe must FAIL.
	body := "[other]\n" +
		"note = \"\"\"\n" +
		"[features]\n" +
		"hooks = true\n" +
		"\"\"\"\n" +
		"more = 1\n"
	home := t.TempDir()
	_ = Wire("codex", home)
	writeCodexConfig(t, home, body)
	if Probe("codex", home) == nil {
		t.Error("hooks=true inside a multiline string body must not false-PASS")
	}
}

func TestCodexProbeFailClosedOnStateLeakingPastClosedMultilineString(t *testing.T) {
	// A bare "[features]"-looking line inside a multiline string must not
	// leave the scanner believing it's still inside [features] after the
	// string closes — an unrelated hooks = true AFTER the closing """ must
	// not false-PASS off state that leaked past the string boundary.
	body := "[other]\n" +
		"note = \"\"\"\n" +
		"[features]\n" +
		"\"\"\"\n" +
		"hooks = true\n"
	home := t.TempDir()
	_ = Wire("codex", home)
	writeCodexConfig(t, home, body)
	if Probe("codex", home) == nil {
		t.Error("hooks=true after a closed multiline string must not false-PASS via leaked [features] state")
	}
}

func TestCodexProbeFailClosedOnMismatchedDelimiterInsideString(t *testing.T) {
	// A lone '''-style triple inside a """-opened string must NOT close the
	// string: it's a different delimiter type. If it wrongly closed the
	// string, the [features]/hooks=true lines that follow (still inside the
	// unterminated """ body) would be misread as live TOML — a false-PASS in
	// the dangerous direction (doctor blesses an unset flag).
	body := "note = \"\"\"\n" +
		"some text with a lone triple: '''\n" +
		"[features]\n" +
		"hooks = true\n" +
		"\"\"\"\n"
	home := t.TempDir()
	_ = Wire("codex", home)
	writeCodexConfig(t, home, body)
	if Probe("codex", home) == nil {
		t.Error("hooks=true after a mismatched-delimiter line inside an open string must not false-PASS")
	}
}

func TestCodexProbePassesAfterSameLineOpenCloseString(t *testing.T) {
	// A same-line open+close string (parity-even) must not leave inString
	// stuck on: a real [features]/hooks=true AFTER it must still enable.
	body := "x = \"\"\"foo\"\"\"\n" +
		"[features]\n" +
		"hooks = true\n"
	home := t.TempDir()
	_ = Wire("codex", home)
	writeCodexConfig(t, home, body)
	if err := Probe("codex", home); err != nil {
		t.Errorf("real hooks=true after a same-line open+close string must PASS; got %v", err)
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
