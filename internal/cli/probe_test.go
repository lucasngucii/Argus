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
