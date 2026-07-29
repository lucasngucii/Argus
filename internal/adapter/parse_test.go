package adapter

import (
	"strings"
	"testing"
)

func TestParseDispatch(t *testing.T) {
	const payload = `{"tool_name":"Bash","tool_input":{"command":"ls"}}`

	// Parse receives an already-Canonical name (Gate resolves "" → "claude-code"
	// before calling), so it is fed canonical names only — never "".
	p, err := Parse("claude-code", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Parse(claude-code) err: %v", err)
	}
	if p.ToolName != "Bash" || p.ToolInput.Command != "ls" {
		t.Errorf("Parse(claude-code) got %+v", p)
	}

	if _, err := Parse("codex", strings.NewReader(payload)); err == nil {
		t.Error("Parse(unknown harness) must error, got nil")
	}
}
