package policy

import "testing"

func TestBaselineMatchesSeedSet(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range Baseline() {
		if !r.Enabled || r.AlwaysHigh {
			t.Fatalf("baseline rule %q must be enabled and non-alwaysHigh", r.ID)
		}
		ids[r.ID] = true
	}
	for _, want := range []string{"sudo", "git-danger", "rm-recursive", "mcp-mutating-tool", "mcp-read-sensitive-path"} {
		if !ids[want] {
			t.Errorf("Baseline() missing seed rule %q", want)
		}
	}
	if ids["pipe-to-shell"] {
		t.Error("Baseline() must NOT include floor rules")
	}
}
