package policy

import "testing"

func TestFloorAllHigh(t *testing.T) {
	if len(Floor()) == 0 {
		t.Fatal("empty floor")
	}
	for _, r := range Floor() {
		if !r.AlwaysHigh || r.Severity != "high" {
			t.Fatalf("floor not always-high: %+v", r)
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
