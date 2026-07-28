package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDoctor_SeedRuleWarn: a full Default() install warns about nothing; a
// policy stripped of its baseline rules still passes the hard checks (returns
// 0) but emits a WARN naming the missing seed rules.
func TestDoctor_SeedRuleWarn(t *testing.T) {
	home := t.TempDir()
	if err := Init(home); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if code := Doctor(home, &out); code != 0 {
		t.Fatalf("Doctor after Init = %d, want 0", code)
	}
	if strings.Contains(out.String(), "WARN") {
		t.Fatalf("default install should not WARN:\n%s", out.String())
	}

	// Overwrite with a schema-valid but rule-less policy.
	if err := os.WriteFile(filepath.Join(home, ".argus", "policy.json"), []byte(`{"version":1,"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Doctor(home, &out); code != 0 {
		t.Fatalf("Doctor with empty-rules policy = %d, want 0 (WARN is non-fatal)\n%s", code, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "WARN") {
		t.Fatalf("expected a seed-rule WARN, got:\n%s", got)
	}
	if !strings.Contains(got, "sudo") {
		t.Errorf("WARN should name missing baseline rules (e.g. sudo):\n%s", got)
	}
}

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
