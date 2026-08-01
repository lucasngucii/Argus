package adapter

import (
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/classify"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/verdict"
)

func TestCodexParseShellCommand(t *testing.T) {
	const payload = `{"session_id":"s1","turn_id":"u1","tool_name":"Bash","tool_use_id":"t1","cwd":"/repo","permission_mode":"...","tool_input":{"command":"rm -rf /"}}`
	p, err := Parse("codex", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Parse(codex) err: %v", err)
	}
	if p.ToolInput.Command != "rm -rf /" || p.Subject() != "rm -rf /" {
		t.Errorf("codex shell payload must surface the command; got %+v", p)
	}
}

func TestCodexCanonical(t *testing.T) {
	if got, err := Canonical("codex"); err != nil || got != "codex" {
		t.Errorf("Canonical(codex) = %q, %v", got, err)
	}
}

// TestCodexParseMCPShaped documents that an mcp__server__tool-shaped payload
// still decodes fine through Parse("codex", ...) — codexParse delegates
// straight to hook.Parse, which is tool_name-agnostic — even though the
// Codex matcher itself is not wired to gate MCP tool calls today (Bash
// only; see wire_codex.go's codexWiredMatcher). Parsing is not the gap.
func TestCodexParseMCPShaped(t *testing.T) {
	const payload = `{"session_id":"s1","turn_id":"u1","tool_name":"mcp__filesystem__read_file","tool_use_id":"t1","cwd":"/repo","permission_mode":"default","tool_input":{"path":"/etc/passwd"}}`
	p, err := Parse("codex", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Parse(codex) err: %v", err)
	}
	if !p.IsMCP() {
		t.Fatalf("mcp__ tool_name must parse as MCP; got %+v", p)
	}
	if p.MCPServer() != "filesystem" || p.MCPTool() != "read_file" {
		t.Errorf("MCPServer/MCPTool = %q/%q, want filesystem/read_file", p.MCPServer(), p.MCPTool())
	}
}

// TestCodexParseDoesNotFailOpenTheFloor proves codexParse feeds the classifier
// a payload that still trips the rm-catastrophic floor: a Codex Bash payload
// carrying "rm -rf /" must classify high and deny, exactly as it would from
// Claude Code. If codexParse ever dropped or mangled the command field, this
// would silently downgrade the floor to an allow.
func TestCodexParseDoesNotFailOpenTheFloor(t *testing.T) {
	const payload = `{"session_id":"s1","turn_id":"u1","tool_name":"Bash","tool_use_id":"t1","cwd":"/repo","permission_mode":"default","tool_input":{"command":"rm -rf /"}}`
	p, err := Parse("codex", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Parse(codex) err: %v", err)
	}
	d := classify.Classify(p, policy.File{Version: 1}.Effective())
	if d.Severity != "high" {
		t.Fatalf("codex rm -rf / must classify high, got %q (%s)", d.Severity, d.RuleID)
	}
	if got := verdict.Map(d.Severity, p.PermissionMode); got != "deny" {
		t.Fatalf("codex rm -rf / must deny, got %q", got)
	}
}
