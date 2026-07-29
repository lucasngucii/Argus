package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHookCommand(t *testing.T, home, command string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + command + `"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeMultiHookCommand wires a PreToolUse entry whose inner "hooks" array
// has a non-gate command first and the argus gate command second, mirroring
// a hand-edited multi-hook entry (e.g. a user's own logging hook alongside
// argus).
func writeMultiHookCommand(t *testing.T, home, gateCmd string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[` +
		`{"type":"command","command":"echo hi"},` +
		`{"type":"command","command":"` + gateCmd + `"}` +
		`]}]}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestProbeMultiHookPicksGateCommandNotFirst proves gateCommandString picks
// the hook whose command actually runs argus gate — not blindly inner[0] —
// by putting a non-gate command first and the gate command (with an unknown
// harness) second.
func TestProbeMultiHookPicksGateCommandNotFirst(t *testing.T) {
	home := t.TempDir()
	writeMultiHookCommand(t, home, "argus gate --harness=bogus")
	err := Probe("claude-code", home)
	if err == nil {
		t.Fatal("expected error naming the unknown harness, got nil")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("Probe error must name the offending harness \"bogus\" (proving it read the gate hook, not inner[0]); got %v", err)
	}
}

func TestProbeTriState(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{"bare", "argus gate", false},
		{"known", "argus gate --harness=claude-code", false},
		{"unknown", "argus gate --harness=bogus", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			writeHookCommand(t, home, tt.command)
			err := Probe("claude-code", home)
			if (err != nil) != tt.wantErr {
				t.Errorf("Probe with command %q: err=%v wantErr=%v", tt.command, err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "bogus") {
				t.Errorf("unknown-harness FAIL must name the offending value; got %v", err)
			}
		})
	}
}
