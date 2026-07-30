package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeHookCommand wires command as the sole PreToolUse hook. It JSON-encodes
// command rather than string-concatenating it into a template so a command
// containing shell double-quotes (a hand-editor's --harness="value") still
// produces valid settings.json instead of corrupting the surrounding JSON.
func writeHookCommand(t *testing.T, home, command string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":` + string(encoded) + `}]}]}}`
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

// TestProbeAgreesWithRuntimeFlagParsing proves checkConfiguredHarness parses
// --harness with the exact same semantics as cmd/argus/main.go's flag.FlagSet
// (both `=` and space forms, last-occurrence-wins, shell-quote stripping) so
// doctor can never PASS a wiring that would brick the live gate, nor FAIL one
// the live gate accepts.
func TestProbeAgreesWithRuntimeFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		// Space form: the runtime flag package accepts `--harness x` exactly
		// like `--harness=x`. The old regex only matched `=` and silently
		// read this as a bare (absent) flag — wrongly PASSing here would
		// have been fine by luck (claude-code is also the bare default), so
		// this case pins the *parsed value*, not just the PASS/FAIL bit.
		{"space form known", "argus gate --harness claude-code", false},
		// Duplicate flag, last wins (matches Go's flag package): the second
		// --harness=bogus is what the runtime gate actually uses, so this
		// must FAIL naming bogus even though claude-code appears first.
		{"duplicate last wins bogus", "argus gate --harness=claude-code --harness=bogus", true},
		// Reverse duplicate: bogus first, claude-code last — the runtime
		// gate uses claude-code, so this must PASS.
		{"duplicate last wins claude-code", "argus gate --harness=bogus --harness=claude-code", false},
		// Shell-quoted value: shellast tokenizes via a real shell AST and
		// strips the quotes, so the flag package sees the bare value
		// claude-code. The old regex's \S+ stopped at the quote character
		// and would have wrongly FAILed on `"claude-code`.
		{"shell quoted known", `argus gate --harness="claude-code"`, false},
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
