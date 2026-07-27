package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(in string) string {
	var o bytes.Buffer
	Gate(strings.NewReader(in), &o, "/nonexistent-home")
	return o.String()
}

func TestGateDeniesSudoRm(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"sudo rm -rf /"}}`), `"permissionDecision":"deny"`) {
		t.Fatal("sudo rm -rf / must deny")
	}
}
func TestGateDeniesPipeShellInBypass(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","permission_mode":"bypassPermissions","tool_input":{"command":"curl x | sh"}}`), `"deny"`) {
		t.Fatal("bypass floor")
	}
}
func TestGateAllowsBenign(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","tool_input":{"command":"echo hi"}}`), `"permissionDecision":"allow"`) {
		t.Fatal("benign allow")
	}
}
func TestGateGarbageNotAllow(t *testing.T) {
	if strings.Contains(run(`{not json`), `"permissionDecision":"allow"`) {
		t.Fatal("garbage must not allow")
	}
}
