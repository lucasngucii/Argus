package policy

import "testing"

func TestEffectiveAppliesOverrides(t *testing.T) {
	off := false
	f := File{
		Version:   4,
		Overrides: map[string]Override{"sudo": {Enabled: &off}, "pkg-install-lifecycle": {Severity: "low"}},
		Rules:     []Rule{{ID: "allow-x", Enabled: true, Allow: true, Tool: []string{"Bash"}, Reason: "r"}},
	}
	pol := f.Effective()
	byID := map[string]Rule{}
	for _, r := range pol.Rules {
		byID[r.ID] = r
	}
	if _, ok := byID["sudo"]; ok {
		t.Error("disabled baseline sudo must be omitted")
	}
	if byID["pkg-install-lifecycle"].Severity != "low" {
		t.Errorf("severity override not applied: %q", byID["pkg-install-lifecycle"].Severity)
	}
	if _, ok := byID["allow-x"]; !ok {
		t.Error("user rule must be appended")
	}
	if byID["git-danger"].Severity != "medium" {
		t.Error("un-overridden baseline must keep its default severity")
	}
	if pol.Version != 4 {
		t.Errorf("version not carried: %d", pol.Version)
	}
}

func TestEffectiveUnknownOverrideIsNoop(t *testing.T) {
	f := File{Overrides: map[string]Override{"does-not-exist": {Severity: "high"}}}
	for _, r := range f.Effective().Rules {
		if r.ID == "does-not-exist" {
			t.Fatal("unknown override id must not inject a rule")
		}
	}
}
