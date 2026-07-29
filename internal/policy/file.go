package policy

// Override is a user tweak to one binary-owned baseline rule. Enabled is a
// *bool so "absent" (use baseline) is distinct from an explicit false;
// Severity "" means "unchanged".
type Override struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// File is the on-disk policy document: a thin layer over Baseline(). It stores
// per-baseline overrides and user-authored rules (allowlist + custom) — never
// the baselines themselves.
type File struct {
	Version   int                 `json:"version"`
	Meta      map[string]string   `json:"meta,omitempty"`
	Defaults  Defaults            `json:"defaults,omitempty"`
	Overrides map[string]Override `json:"overrides,omitempty"`
	Rules     []Rule              `json:"rules"`
}

// Effective assembles the policy classify sees: every Baseline() rule with its
// override applied (a disabled one is omitted; a severity override replaces the
// rank), followed by the user rules. Overrides referencing an unknown id are
// ignored. Floor()/SelfProtectRules() are NOT added here — classify applies
// them in its own pass, so no override can ever reach them.
func (f File) Effective() Policy {
	rules := make([]Rule, 0, len(Baseline())+len(f.Rules))
	for _, b := range Baseline() { // b is a copy; mutating b.Severity is safe
		if o, ok := f.Overrides[b.ID]; ok {
			if o.Enabled != nil && !*o.Enabled {
				continue
			}
			if o.Severity != "" {
				b.Severity = o.Severity
			}
		}
		rules = append(rules, b)
	}
	rules = append(rules, f.Rules...)
	return Policy{Version: f.Version, Meta: f.Meta, Defaults: f.Defaults, Rules: rules}
}

// DefaultFile is the thin document a fresh install writes: no overrides, no user
// rules — the full binary baseline applies, and stays current across upgrades.
func DefaultFile() File { return File{Version: 1, Rules: []Rule{}} }
