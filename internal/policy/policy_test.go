package policy

import "testing"

// TestFloorRulesPinHigh asserts every floor rule can pin the high floor, by
// one of the two sanctioned mechanisms: an AlwaysHigh+high rule (pins
// unconditionally), or a scorer-gated rule whose TargetScorer floors the
// verdict only when it returns "high" (see classify.Classify). rm-catastrophic
// is deliberately the latter so an ordinary `rm -r <path>` is not over-pinned.
func TestFloorRulesPinHigh(t *testing.T) {
	if len(Floor()) == 0 {
		t.Fatal("empty floor")
	}
	for _, r := range Floor() {
		alwaysHigh := r.AlwaysHigh && r.Severity == "high"
		scorerGated := r.Match.TargetScorer != ""
		if !alwaysHigh && !scorerGated {
			t.Fatalf("floor rule can neither always-high nor scorer-gate: %+v", r)
		}
	}
}

func TestDefaultDoesNotEmbedFloor(t *testing.T) {
	for _, r := range Default().Rules {
		if r.AlwaysHigh {
			t.Fatal("Default() must not embed floor rules (classifier owns them)")
		}
	}
}

func TestSchemaRejectsBadSeverity(t *testing.T) {
	if _, err := loadBytes([]byte(`{"version":1,"rules":[{"id":"x","enabled":true,"tool":["Bash"],"severity":"hgih","reason":"typo"}]}`)); err == nil {
		t.Fatal("schema must reject severity typo")
	}
}

func TestSchemaRejectsNonIntVersion(t *testing.T) {
	if _, err := loadBytes([]byte(`{"version":"nope","rules":[]}`)); err == nil {
		t.Fatal("version must be int")
	}
}
