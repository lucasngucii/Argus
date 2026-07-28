package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

// TestReplay_ReportsEscalation seeds a claude-code low/allow row whose command
// Default() scores medium and asserts Replay reads it through
// AllDecisions(claudeCodeOnly), re-scores, and reports the transition. `sudo
// apt-get update` matches Default()'s `sudo` rule (medium), so a historically
// low/allow row escalates to medium/ask deterministically.
func TestReplay_ReportsEscalation(t *testing.T) {
	s := openTestStore(t)
	if err := s.Insert(store.Row{
		TS: "t1", Harness: "claude-code",
		Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "default",
		Severity: "low", Verdict: "allow",
	}); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	if code := Replay(s, policy.Default(), buf); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	out := buf.String()
	if !strings.Contains(out, "1 decision") || !strings.Contains(out, "1 changed") {
		t.Errorf("output missing scored/changed counts:\n%s", out)
	}
	if !strings.Contains(out, "allow->ask") {
		t.Errorf("output missing transition allow->ask:\n%s", out)
	}
	if !strings.Contains(out, "sudo apt-get update") {
		t.Errorf("output missing the changed command:\n%s", out)
	}
	// The scope caveat must always print so a reader knows safe/unlogged
	// decisions are out of replay's reach.
	if !strings.Contains(out, "safe") {
		t.Errorf("output missing safe-not-covered note:\n%s", out)
	}
}

// TestReplay_ExcludesLegacyImport proves Replay reads through
// AllDecisions(claudeCodeOnly=true): a legacy agent-review row (scored by the
// old engine) must not be re-scored, so it never appears in the diff.
func TestReplay_ExcludesLegacyImport(t *testing.T) {
	s := openTestStore(t)
	if err := s.Insert(store.Row{
		TS: "t1", Harness: "agent-review", RuleID: "legacy-import",
		Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "default",
		Severity: "low", Verdict: "allow",
	}); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	if code := Replay(s, policy.Default(), buf); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	out := buf.String()
	if !strings.Contains(out, "0 decision") {
		t.Errorf("legacy-import row must be excluded, got:\n%s", out)
	}
	if strings.Contains(out, "sudo apt-get update") {
		t.Errorf("legacy row leaked into replay diff:\n%s", out)
	}
}
