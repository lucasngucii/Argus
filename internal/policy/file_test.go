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

func TestNormalizeFoldsOldInlineBaselines(t *testing.T) {
	old := []byte(`{"version":2,"rules":[
	  {"id":"sudo","enabled":false,"tool":["Bash"],"reason":"sudo","match":{"cmd":["sudo"]}},
	  {"id":"git-danger","enabled":true,"severity":"high","tool":["Bash"],"reason":"g","match":{"cmd":["git"],"targetScorer":"git_danger"}},
	  {"id":"rm-recursive","enabled":true,"severity":"medium","tool":["Bash"],"reason":"rm -r directory","match":{"cmd":["rm"],"flags":["r"],"targetScorer":"rm_target"}},
	  {"id":"allow-abc","enabled":true,"allow":true,"tool":["Bash"],"reason":"x","match":{"raw":"^echo hi$"}}
	]}`)
	f, err := normalize(old)
	if err != nil {
		t.Fatal(err)
	}
	if f.Overrides["sudo"].Enabled == nil || *f.Overrides["sudo"].Enabled {
		t.Error("disabled sudo must become an enabled:false override")
	}
	if f.Overrides["git-danger"].Severity != "high" {
		t.Errorf("edited git-danger severity must become an override, got %q", f.Overrides["git-danger"].Severity)
	}
	if _, ok := f.Overrides["rm-recursive"]; ok {
		t.Error("a stock baseline copy must be dropped, not overridden")
	}
	if len(f.Rules) != 1 || f.Rules[0].ID != "allow-abc" {
		t.Errorf("user allowlist rule must be kept, got %+v", f.Rules)
	}
}

func TestNormalizeThinRoundTrips(t *testing.T) {
	thin := []byte(`{"version":1,"overrides":{"sudo":{"enabled":false}},"rules":[]}`)
	f, err := normalize(thin)
	if err != nil {
		t.Fatal(err)
	}
	if f.Overrides["sudo"].Enabled == nil || *f.Overrides["sudo"].Enabled {
		t.Error("explicit override must survive normalize")
	}
	if len(f.Rules) != 0 {
		t.Errorf("no user rules expected, got %d", len(f.Rules))
	}
}

func TestNormalizeKeepsAllowRuleOnIDCollision(t *testing.T) {
	// A user allowlist rule that reuses a baseline id must survive as a user
	// rule, not be misread as a baseline copy and swallowed.
	doc := []byte(`{"version":1,"rules":[{"id":"sudo","enabled":true,"allow":true,"tool":["Bash"],"reason":"x","match":{"raw":"^sudo -l$"}}]}`)
	f, err := normalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 1 || !f.Rules[0].Allow {
		t.Errorf("allow rule colliding with a baseline id must be kept, got %+v", f.Rules)
	}
	if _, ok := f.Overrides["sudo"]; ok {
		t.Error("an allow rule must not become a baseline override")
	}
}

func TestBaselineDriftIDsFlagsNonMigratableEdit(t *testing.T) {
	// git-danger with a hand-edited match regex (non-migratable) → drift.
	doc := []byte(`{"version":2,"rules":[{"id":"git-danger","enabled":true,"severity":"medium","tool":["Bash"],"reason":"g","match":{"cmd":["git","hub"],"targetScorer":"git_danger"}}]}`)
	got := BaselineDriftIDs(doc)
	if len(got) != 1 || got[0] != "git-danger" {
		t.Errorf("expected drift on git-danger, got %v", got)
	}
	// A thin file has no inline baselines → no drift.
	if d := BaselineDriftIDs([]byte(`{"version":1,"overrides":{"sudo":{"enabled":false}},"rules":[]}`)); len(d) != 0 {
		t.Errorf("thin file must report no drift, got %v", d)
	}
}
