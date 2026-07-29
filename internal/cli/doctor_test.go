package cli

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestDoctorWarnsUnknownOverride(t *testing.T) {
	home := t.TempDir()
	argus := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argus, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(argus, "policy.json"),
		[]byte(`{"version":1,"overrides":{"ghost-rule":{"enabled":false}},"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	warnUnknownOverride(home, &b)
	if !strings.Contains(b.String(), "ghost-rule") {
		t.Errorf("expected WARN about unknown override id, got %q", b.String())
	}
}

func TestDoctorNoWarnOnCleanThinPolicy(t *testing.T) {
	home := t.TempDir()
	argus := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argus, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(argus, "policy.json"),
		[]byte(`{"version":1,"overrides":{"sudo":{"enabled":false}},"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	warnUnknownOverride(home, &b)
	if b.Len() != 0 {
		t.Errorf("clean policy must not warn, got %q", b.String())
	}
}

func TestDoctorWarnsBaselineDrift(t *testing.T) {
	home := t.TempDir()
	argus := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argus, 0o755); err != nil {
		t.Fatal(err)
	}
	// An old fat file with a hand-edited git-danger match (non-migratable).
	if err := os.WriteFile(filepath.Join(argus, "policy.json"),
		[]byte(`{"version":2,"rules":[{"id":"git-danger","enabled":true,"severity":"medium","tool":["Bash"],"reason":"g","match":{"cmd":["git","hub"],"targetScorer":"git_danger"}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	warnBaselineDrift(home, &b)
	if !strings.Contains(b.String(), "git-danger") {
		t.Errorf("expected drift WARN for git-danger, got %q", b.String())
	}
}
