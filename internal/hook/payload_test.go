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
