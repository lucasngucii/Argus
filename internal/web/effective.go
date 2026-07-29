package web

import (
	"net/http"

	"github.com/lucasngucii/argus/internal/policy"
)

// overrideView is the API view of a policy.Override.
type overrideView struct {
	Enabled  *bool  `json:"enabled"`
	Severity string `json:"severity"`
}

// baselineView is a binary baseline rule paired with its current override
// state (nil when unmodified).
type baselineView struct {
	ID              string        `json:"id"`
	Reason          string        `json:"reason"`
	Tool            []string      `json:"tool"`
	DefaultSeverity string        `json:"defaultSeverity"`
	Override        *overrideView `json:"override"`
}

// effectiveResponse is the GET /api/policy/effective payload: every binary
// baseline with its override state, plus the user-authored rules.
type effectiveResponse struct {
	Baselines []baselineView `json:"baselines"`
	UserRules []policy.Rule  `json:"userRules"`
}

// handleEffective serves GET /api/policy/effective: every binary baseline with
// its current override state, plus the user rules — the data the structured
// policy editor renders. Baselines come from the binary (policy.Baseline()), so
// they are always current; overrides/userRules come from the thin file on disk.
func (srv *Server) handleEffective(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	f := srv.loadFile()
	views := make([]baselineView, 0, len(policy.Baseline()))
	for _, b := range policy.Baseline() {
		bv := baselineView{ID: b.ID, Reason: b.Reason, Tool: b.Tool, DefaultSeverity: b.Severity}
		if o, ok := f.Overrides[b.ID]; ok {
			bv.Override = &overrideView{Enabled: o.Enabled, Severity: o.Severity}
		}
		views = append(views, bv)
	}
	userRules := f.Rules
	if userRules == nil {
		userRules = []policy.Rule{}
	}
	writeJSON(w, http.StatusOK, effectiveResponse{Baselines: views, UserRules: userRules})
}
