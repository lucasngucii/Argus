package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/policy"
)

// TestHarnessCorporaAllPass is the permanent regression guard: every line of
// both the golden (precision) and evasion (must-catch) corpora must classify
// to its expected severity under the shipped default policy. A single drift —
// an evasion technique slipping below high, or a benign command false-firing —
// fails the build. Its output is captured so a failure names the offending
// lines.
func TestHarnessCorporaAllPass(t *testing.T) {
	var out strings.Builder
	paths := []string{"testdata/golden.jsonl", "testdata/evasion.jsonl"}
	if code := RunHarness(paths, policy.Default(), &out); code != 0 {
		t.Fatalf("RunHarness = %d, want 0\n%s", code, out.String())
	}
}

// TestHarnessReportsMismatch confirms the harness fails closed on a wrong
// expectation rather than silently passing: a corpus line whose expected
// severity is impossible must produce a non-zero code and a FAIL line.
func TestHarnessReportsMismatch(t *testing.T) {
	var out strings.Builder
	// evasion.jsonl expects high for `sudo rm -rf /`; golden alone is fine,
	// so point at a temp file asserting a deliberately wrong severity.
	bad := t.TempDir() + "/bad.jsonl"
	if err := os.WriteFile(bad, []byte(`{"tool":"Bash","command":"sudo rm -rf /","expect":"safe"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := RunHarness([]string{bad}, policy.Default(), &out); code == 0 {
		t.Fatalf("RunHarness = 0 on a wrong expectation, want non-zero\n%s", out.String())
	}
	if !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("expected a FAIL line, got:\n%s", out.String())
	}
}
