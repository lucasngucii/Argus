package policy

import (
	"os"
	"testing"
)

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

func TestLoadOldFileGivesCurrentBaseline(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.json"
	// A minimal old file with NO mcp-mutating-tool inline (a stale install).
	if err := os.WriteFile(path, []byte(`{"version":2,"rules":[
	  {"id":"sudo","enabled":true,"severity":"medium","tool":["Bash"],"reason":"sudo","match":{"cmd":["sudo"]}}
	]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range pol.Rules {
		got[r.ID] = true
	}
	if !got["mcp-mutating-tool"] {
		t.Error("a stale old file must still get the current binary baseline (mcp-mutating-tool)")
	}
}

func TestSchemaRejectsBadSeverity(t *testing.T) {
	if err := Validate([]byte(`{"version":1,"rules":[{"id":"x","enabled":true,"tool":["Bash"],"severity":"hgih","reason":"typo"}]}`)); err == nil {
		t.Fatal("schema must reject severity typo")
	}
}

func TestSchemaRejectsNonIntVersion(t *testing.T) {
	if err := Validate([]byte(`{"version":"nope","rules":[]}`)); err == nil {
		t.Fatal("version must be int")
	}
}
