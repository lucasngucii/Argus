package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestDoctor_MCPMatcherWarn(t *testing.T) {
	home := t.TempDir()
	if err := Init(home); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	Doctor(home, &out)
	if strings.Contains(out.String(), "WARN") && strings.Contains(strings.ToLower(out.String()), "mcp") {
		t.Fatalf("fresh install must not WARN about MCP matcher:\n%s", out.String())
	}
	setGateMatcher(t, home, "Bash|Write|Edit") // downgrade to a stale matcher
	out.Reset()
	Doctor(home, &out)
	if !strings.Contains(out.String(), "WARN") || !strings.Contains(strings.ToLower(out.String()), "mcp") {
		t.Fatalf("stale matcher must WARN about MCP:\n%s", out.String())
	}
}
