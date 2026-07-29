package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
)

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

// normalize converts any historically-valid policy document into a canonical
// File. An inline rule whose id is a Baseline() id is an old-format copy: an
// edit (disabled, or a differing severity) becomes an override; an identical
// stock copy is dropped (the binary owns it now). Every other rule (allowlist /
// custom) is kept. It is total and pure — the single migration authority shared
// by Load, LoadFile, and the web save path. (M1 in the design spec.)
func normalize(b []byte) (File, error) {
	var raw File
	if err := json.Unmarshal(b, &raw); err != nil {
		return File{}, fmt.Errorf("decode policy: %w", err)
	}
	base := map[string]Rule{}
	for _, r := range Baseline() {
		base[r.ID] = r
	}
	out := File{Version: raw.Version, Meta: raw.Meta, Defaults: raw.Defaults, Overrides: map[string]Override{}, Rules: []Rule{}}
	for id, o := range raw.Overrides {
		out.Overrides[id] = o
	}
	for _, r := range raw.Rules {
		b0, isBaseline := base[r.ID]
		if !isBaseline || r.Allow { // an allow rule is never a baseline, even on an id collision
			out.Rules = append(out.Rules, r)
			continue
		}
		ov := out.Overrides[r.ID]
		if !r.Enabled {
			off := false
			ov.Enabled = &off
		}
		if r.Severity != "" && r.Severity != b0.Severity {
			ov.Severity = r.Severity
		}
		if ov.Enabled != nil || ov.Severity != "" {
			out.Overrides[r.ID] = ov
		}
		// A match/reason/tool/contextEscalation edit has no override
		// representation and is intentionally dropped (the binary owns those);
		// BaselineDriftIDs surfaces it via doctor so the discard is not silent.
	}
	return out, nil
}

// BaselineDriftIDs reports the ids of inline baseline copies in a raw (old-
// format) document that differ from the binary baseline in a field normalize
// cannot migrate (match/reason/tool/contextEscalation). doctor warns on these
// so an operator's superseded hand-edit is visible, not silently discarded.
// Returns nil for a thin/new document (no inline baselines).
func BaselineDriftIDs(b []byte) []string {
	var raw File
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}
	base := map[string]Rule{}
	for _, r := range Baseline() {
		base[r.ID] = r
	}
	var drift []string
	for _, r := range raw.Rules {
		b0, ok := base[r.ID]
		if !ok || r.Allow {
			continue
		}
		// Compare only the non-migratable fields; enabled/severity are handled
		// as overrides and are not "drift".
		norm := r
		norm.Enabled, norm.Severity = b0.Enabled, b0.Severity
		if !reflect.DeepEqual(norm, b0) {
			drift = append(drift, r.ID)
		}
	}
	sort.Strings(drift)
	return drift
}

// LoadFile reads, validates, and normalizes the on-disk document to its thin
// canonical File — for callers that edit or re-serialize the file (web editor,
// close-the-loop allowlist), which must NOT round-trip through Effective() or
// they would write the baselines back into the file.
func LoadFile(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("load policy: %w", err)
	}
	if err := Validate(b); err != nil {
		return File{}, fmt.Errorf("load policy %s: %w", path, err)
	}
	return normalize(b)
}

// EffectiveFromBytes validates + normalizes + assembles a policy document held
// in memory (a candidate upload, a stored snapshot) into the Policy classify
// consumes — so an old-format candidate re-scores against the CURRENT binary
// baseline. The in-memory twin of Load.
func EffectiveFromBytes(b []byte) (Policy, error) {
	if err := Validate(b); err != nil {
		return Policy{}, fmt.Errorf("validate policy: %w", err)
	}
	f, err := normalize(b)
	if err != nil {
		return Policy{}, err
	}
	return f.Effective(), nil
}
