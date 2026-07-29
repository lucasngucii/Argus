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
