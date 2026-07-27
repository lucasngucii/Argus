package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/policy"
)

func TestExplain_DangerousCommand(t *testing.T) {
	buf := &bytes.Buffer{}
	code := Explain("sudo rm -rf /", "Bash", "/tmp", "default", policy.Default(), buf)

	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	out := buf.String()
	if !strings.Contains(out, "severity: high") {
		t.Errorf("output missing %q:\n%s", "severity: high", out)
	}
	if !strings.Contains(out, "rule:") {
		t.Errorf("output missing a rule: line:\n%s", out)
	}
	// The rule: line must not be empty (non-empty RuleID after the label).
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "rule:") {
			if strings.TrimSpace(strings.TrimPrefix(line, "rule:")) == "" {
				t.Errorf("rule: line is empty:\n%s", out)
			}
		}
	}
	if !strings.Contains(out, "verdict: deny") {
		t.Errorf("output missing %q:\n%s", "verdict: deny", out)
	}
}

func TestExplain_BenignCommand(t *testing.T) {
	buf := &bytes.Buffer{}
	code := Explain("ls -la", "Bash", "/tmp", "default", policy.Default(), buf)

	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	out := buf.String()
	if !strings.Contains(out, "severity: safe") {
		t.Errorf("output missing %q:\n%s", "severity: safe", out)
	}
	if !strings.Contains(out, "verdict: allow") {
		t.Errorf("output missing %q:\n%s", "verdict: allow", out)
	}
}
