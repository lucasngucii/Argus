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
