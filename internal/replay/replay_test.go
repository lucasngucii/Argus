package replay

import (
	"testing"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

// TestRescoreEscalation: a stored low/allow row whose command the current
// Default() policy scores medium must surface as a low/allow -> medium/ask
// change. `sudo apt-get update` matches Default()'s `sudo` rule (medium), so
// re-scoring a row that was historically logged low deterministically
// escalates it — no custom candidate needed.
func TestRescoreEscalation(t *testing.T) {
	rows := []store.Row{{
		Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "default",
		Severity: "low", Verdict: "allow",
	}}
	res := Rescore(rows, false, policy.Default())
	if res.Total != 1 {
		t.Fatalf("Total = %d, want 1", res.Total)
	}
	if len(res.Changed) != 1 {
		t.Fatalf("Changed = %+v, want exactly 1", res.Changed)
	}
	c := res.Changed[0]
	if c.OldSeverity != "low" || c.NewSeverity != "medium" {
		t.Fatalf("severity %s->%s, want low->medium", c.OldSeverity, c.NewSeverity)
	}
	if c.OldVerdict != "allow" || c.NewVerdict != "ask" {
		t.Fatalf("verdict %s->%s, want allow->ask", c.OldVerdict, c.NewVerdict)
	}
	if res.Summary["allow->ask"] != 1 {
		t.Fatalf("summary = %+v, want allow->ask:1", res.Summary)
	}
}

// TestRescoreUnchangedNotReported: a row whose stored severity/verdict already
// match what the candidate produces must NOT appear in Changed. `sudo apt-get
// update` scores medium under Default(); a stored medium/ask row is a no-op.
func TestRescoreUnchangedNotReported(t *testing.T) {
	rows := []store.Row{{
		Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "default",
		Severity: "medium", Verdict: "ask",
	}}
	res := Rescore(rows, false, policy.Default())
	if res.Total != 1 {
		t.Fatalf("Total = %d, want 1", res.Total)
	}
	if len(res.Changed) != 0 {
		t.Fatalf("unchanged row must not appear: %+v", res.Changed)
	}
	if len(res.Summary) != 0 {
		t.Fatalf("summary must be empty for a no-op: %+v", res.Summary)
	}
}

// TestRescorePropagatesCapped: the capped flag is carried straight through.
func TestRescorePropagatesCapped(t *testing.T) {
	if !Rescore(nil, true, policy.Default()).Capped {
		t.Fatal("Capped must propagate")
	}
	if Rescore(nil, false, policy.Default()).Capped {
		t.Fatal("Capped must not be set when false")
	}
}

// TestRescoreSeverityDiffersVerdictSame: the change predicate is "severity OR
// verdict differs" — this row proves the severity clause, which no other
// fixture exercises alone. Stored high/deny under acceptEdits; re-scored the
// `sudo` rule yields medium and verdict.Map("medium","acceptEdits")=="deny",
// so severity high->medium DIFFERS while verdict deny->deny is UNCHANGED. A
// weaker verdict-only impl would wrongly drop this row; it MUST be reported.
func TestRescoreSeverityDiffersVerdictSame(t *testing.T) {
	rows := []store.Row{{
		Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "acceptEdits",
		Severity: "high", Verdict: "deny",
	}}
	res := Rescore(rows, false, policy.Default())
	if len(res.Changed) != 1 {
		t.Fatalf("Changed = %+v, want exactly 1 (severity differs)", res.Changed)
	}
	c := res.Changed[0]
	if c.OldSeverity != "high" || c.NewSeverity != "medium" {
		t.Fatalf("severity %s->%s, want high->medium", c.OldSeverity, c.NewSeverity)
	}
	if c.OldVerdict != "deny" || c.NewVerdict != "deny" {
		t.Fatalf("verdict %s->%s, want deny->deny (unchanged)", c.OldVerdict, c.NewVerdict)
	}
	if res.Summary["deny->deny"] != 1 {
		t.Fatalf("summary = %+v, want deny->deny:1", res.Summary)
	}
}

// TestRescoreMixedRowsAndSummary: only changed rows are reported and the
// summary aggregates every transition across the batch. One escalating row
// (low/allow -> medium/ask), one no-op (already medium/ask, excluded), and one
// escalating row under a non-interactive mode where the verdict lands deny
// (low/allow -> medium/deny) exercise the counter keys.
func TestRescoreMixedRowsAndSummary(t *testing.T) {
	rows := []store.Row{
		// escalates: low/allow -> medium/ask
		{Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "default", Severity: "low", Verdict: "allow"},
		// no-op: already medium/ask
		{Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "default", Severity: "medium", Verdict: "ask"},
		// escalates under a non-interactive mode: low/allow -> medium/deny
		{Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "acceptEdits", Severity: "low", Verdict: "allow"},
	}
	res := Rescore(rows, false, policy.Default())
	if res.Total != 3 {
		t.Fatalf("Total = %d, want 3", res.Total)
	}
	if len(res.Changed) != 2 {
		t.Fatalf("Changed = %d, want 2 (the no-op excluded)", len(res.Changed))
	}
	if res.Summary["allow->ask"] != 1 || res.Summary["allow->deny"] != 1 {
		t.Fatalf("summary = %+v, want allow->ask:1, allow->deny:1", res.Summary)
	}
	// The reported Change carries the original row for the UI/CLI to render.
	if res.Changed[0].Row.Command != "sudo apt-get update" {
		t.Fatalf("Change.Row not carried: %+v", res.Changed[0].Row)
	}
}

// TestRescoreNilRowsEmptyResult: no rows means an empty, non-nil-summary result.
func TestRescoreNilRowsEmptyResult(t *testing.T) {
	res := Rescore(nil, false, policy.Default())
	if res.Total != 0 || len(res.Changed) != 0 {
		t.Fatalf("empty input must yield empty result: %+v", res)
	}
	if res.Summary == nil {
		t.Fatal("Summary must be non-nil even when empty")
	}
}
