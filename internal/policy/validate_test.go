package policy

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestValidateRejectsBadVersion(t *testing.T) {
	if err := Validate([]byte(`{"version":"x"}`)); err == nil {
		t.Fatal("Validate must reject a non-integer version")
	}
}

func TestValidateAcceptsDefault(t *testing.T) {
	b, err := json.Marshal(Default())
	if err != nil {
		t.Fatalf("marshal Default(): %v", err)
	}
	if err := Validate(b); err != nil {
		t.Fatalf("Validate(Default()) = %v, want nil", err)
	}
}

func TestSeedRuleIDsMatchesDefault(t *testing.T) {
	ids := SeedRuleIDs()

	if !slices.Contains(ids, "sudo") {
		t.Fatalf("SeedRuleIDs() = %v, want it to contain %q", ids, "sudo")
	}

	var want []string
	for _, r := range Default().Rules {
		if r.Enabled && !r.AlwaysHigh {
			want = append(want, r.ID)
		}
	}
	if !slices.Equal(ids, want) {
		t.Fatalf("SeedRuleIDs() = %v, want %v (non-alwaysHigh enabled rule IDs of Default())", ids, want)
	}
}
