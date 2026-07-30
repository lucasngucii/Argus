package hook

import (
	"strings"
	"testing"
)

func TestParseBash(t *testing.T) {
	p, err := Parse(strings.NewReader(`{"tool_name":"Bash","permission_mode":"default","cwd":"/tmp","tool_input":{"command":"sudo rm -rf /"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.ToolName != "Bash" || p.Subject() != "sudo rm -rf /" {
		t.Fatalf("%+v", p)
	}
}

func TestParseWriteSubjectIsPath(t *testing.T) {
	p, _ := Parse(strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":"/etc/hosts"}}`))
	if p.Subject() != "/etc/hosts" {
		t.Fatalf("subject=%q", p.Subject())
	}
}

func TestParseMCPPayload(t *testing.T) {
	p, err := Parse(strings.NewReader(`{"tool_name":"mcp__filesystem__delete_file","permission_mode":"default","tool_input":{"path":"/home/dev/.ssh/id_rsa"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsMCP() || p.MCPServer() != "filesystem" || p.MCPTool() != "delete_file" {
		t.Fatalf("parse = %v/%q/%q", p.IsMCP(), p.MCPServer(), p.MCPTool())
	}
	if !strings.Contains(p.Subject(), ".ssh/id_rsa") {
		t.Fatalf("MCP Subject must be args JSON: %q", p.Subject())
	}
}

func TestMCPPluginForm(t *testing.T) {
	p := Payload{ToolName: "mcp__plugin_myplug_db__query"}
	if p.MCPServer() != "plugin_myplug_db" || p.MCPTool() != "query" {
		t.Fatalf("%q/%q", p.MCPServer(), p.MCPTool())
	}
}

func TestBashMistypedCommandFailsClosed(t *testing.T) {
	// invariant: a Bash payload whose command is the wrong type must ERROR (deny), not silently become "".
	if _, err := Parse(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":123}}`)); err == nil {
		t.Fatal("mistyped Bash command must error (fail-closed)")
	}
}

func TestSubjectMissingToolNameWithCommandIsCommand(t *testing.T) {
	// fail-open regression: a missing tool_name must not hide a real command
	// behind an empty subject — judge on Command presence, not tool_name.
	p, err := Parse(strings.NewReader(`{"tool_input":{"command":"rm -rf /"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject() != "rm -rf /" {
		t.Fatalf("subject=%q, want the command", p.Subject())
	}
}

func TestSubjectLowercaseToolNameWithCommandIsCommand(t *testing.T) {
	// fail-open regression: a mis-cased tool_name ("bash" vs "Bash") must not
	// hide a real command behind an empty subject.
	p, err := Parse(strings.NewReader(`{"tool_name":"bash","tool_input":{"command":"rm -rf /"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject() != "rm -rf /" {
		t.Fatalf("subject=%q, want the command", p.Subject())
	}
}

func TestMCPTolerantArgs(t *testing.T) {
	// an MCP tool whose args happen to have a non-string "command" must NOT error — classify on Raw instead.
	p, err := Parse(strings.NewReader(`{"tool_name":"mcp__shell__run","tool_input":{"command":["ls","-la"]}}`))
	if err != nil {
		t.Fatalf("MCP args must be tolerated: %v", err)
	}
	if !strings.Contains(p.Subject(), "ls") {
		t.Fatal("MCP Subject should carry raw args")
	}
}
