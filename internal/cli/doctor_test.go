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
	if err := Init(home, "claude-code"); err != nil {
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

// TestDoctorFailsOnUnknownConfiguredHarness pins Doctor's CI-gate contract at
// the Doctor() level (not just Probe in isolation): a wired hook that
// configures an unknown --harness value must flip Doctor's exit code to 1 and
// surface a FAIL line naming the offending value, since every live gate call
// would otherwise fail closed silently.
func TestDoctorFailsOnUnknownConfiguredHarness(t *testing.T) {
	home := t.TempDir()
	writeHookCommand(t, home, "argus gate --harness=bogus")

	var out bytes.Buffer
	code := Doctor(home, &out)

	if code != 1 {
		t.Errorf("Doctor with hook configuring unknown harness must return 1, got %d", code)
	}
	if !strings.Contains(out.String(), "FAIL") || !strings.Contains(out.String(), "bogus") {
		t.Errorf("Doctor output must FAIL and name the offending harness \"bogus\"; got %s", out.String())
	}
}

// TestDoctorBothHarnessesInstalled pins Doctor's multi-harness fan-out: when
// both ~/.claude AND ~/.codex are present (a machine that runs both agents),
// Doctor must probe and report BOTH hook lines, and the Codex-specific trust
// and matcher-scope WARNs must both appear.
func TestDoctorBothHarnessesInstalled(t *testing.T) {
	home := t.TempDir()
	if err := Init(home, "claude-code"); err != nil {
		t.Fatal(err)
	}
	if err := Wire("codex", home); err != nil {
		t.Fatal(err)
	}
	writeCodexConfig(t, home, "[features]\nhooks = true\n")

	var out bytes.Buffer
	code := Doctor(home, &out)
	report := out.String()

	if code != 0 {
		t.Fatalf("Doctor with both harnesses fully configured = %d, want 0\n%s", code, report)
	}
	if !strings.Contains(report, "hook (claude-code)") {
		t.Errorf("missing claude-code hook line:\n%s", report)
	}
	if !strings.Contains(report, "hook (codex)") {
		t.Errorf("missing codex hook line:\n%s", report)
	}
	if !strings.Contains(report, "WARN hook (codex)") || !strings.Contains(report, "trusted") {
		t.Errorf("missing codex trust WARN:\n%s", report)
	}
	if !strings.Contains(report, "Bash") || !strings.Contains(report, "MCP") {
		t.Errorf("missing codex matcher-scope WARN naming Bash-only coverage:\n%s", report)
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
