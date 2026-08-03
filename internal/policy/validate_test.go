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

// A rule whose regex fails to compile must be rejected at load, not silently
// installed as a dead rule that matches nothing.
func TestValidateRejectsUncompilableRuleRegex(t *testing.T) {
	for _, field := range []string{"raw", "argMatches", "mcpTool"} {
		doc := `{"version":1,"rules":[{"id":"bad","tool":["Bash"],"reason":"x","match":{"` + field + `":"("}}]}`
		if err := Validate([]byte(doc)); err == nil {
			t.Fatalf("Validate must reject an uncompilable %s regex", field)
		}
	}
	// A valid regex still passes.
	ok := `{"version":1,"rules":[{"id":"good","tool":["Bash"],"reason":"x","match":{"raw":"rm\\s"}}]}`
	if err := Validate([]byte(ok)); err != nil {
		t.Fatalf("Validate(valid regex) = %v, want nil", err)
	}
}

// A misspelled rule/match field must be rejected (additionalProperties:false),
// so a mistyped alwaysHigh/cmd doesn't silently weaken coverage.
func TestValidateRejectsUnknownField(t *testing.T) {
	for _, doc := range []string{
		`{"version":1,"rules":[{"id":"t","tool":["Bash"],"reason":"x","alwaysHi":true,"match":{}}]}`,
		`{"version":1,"rules":[{"id":"t","tool":["Bash"],"reason":"x","match":{"comand":["rm"]}}]}`,
	} {
		if err := Validate([]byte(doc)); err == nil {
			t.Fatalf("Validate must reject a misspelled field: %s", doc)
		}
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

func TestValidateAcceptsOverrides(t *testing.T) {
	doc := []byte(`{"version":1,"overrides":{"sudo":{"enabled":false},"npm-x":{"severity":"low"}},"rules":[]}`)
	if err := Validate(doc); err != nil {
		t.Fatalf("valid overrides doc rejected: %v", err)
	}
}

func TestValidateRejectsBadOverrideSeverity(t *testing.T) {
	doc := []byte(`{"version":1,"overrides":{"sudo":{"severity":"nope"}},"rules":[]}`)
	if err := Validate(doc); err == nil {
		t.Fatal("override severity outside the enum must be rejected")
	}
}

func TestValidateAndDecodeMCPMatch(t *testing.T) {
	doc := []byte(`{"version":1,"rules":[{"id":"m","tool":["mcp"],"reason":"x","match":{"mcpServer":["github"],"mcpTool":"(?i)delete"}}]}`)
	if err := Validate(doc); err != nil {
		t.Fatalf("must validate: %v", err)
	}
	var p Policy
	if err := json.Unmarshal(doc, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Rules[0].Match.McpServer) != 1 || p.Rules[0].Match.McpTool == "" {
		t.Fatal("mcpServer/mcpTool must decode into Match")
	}
}
