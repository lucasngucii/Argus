package web

import (
	"encoding/json"
	"net/http"

	"github.com/lucasngucii/argus/internal/store"
)

// statsResponse is the GET /api/stats payload: full-history severity counts,
// the deny total, distinct-session count, and the most recent decisions for
// an at-a-glance dashboard. Per-project heatmap + trend are descoped to a
// later iteration (kept out of v1 deliberately, not silently dropped).
type statsResponse struct {
	Counts   map[string]int `json:"counts"`
	Deny     int            `json:"deny"`
	Sessions int            `json:"sessions"`
	Recent   []store.Row    `json:"recent"`
}

// handleStats answers GET /api/stats by reading the store's aggregate views.
// It reuses store.Counts (full-history severity), store.VerdictCount, and
// store.DistinctSessions rather than recomputing over a scan, and pulls the
// recent list from store.Page (the same paginated read the decisions view
// uses) — not a second Recent call site. A read failure is a 500; the store
// is local and a failure here is genuinely exceptional.
func (srv *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	counts, err := srv.store.Counts()
	if err != nil {
		serverError(w, "counts", err)
		return
	}
	deny, err := srv.store.VerdictCount("deny")
	if err != nil {
		serverError(w, "deny count", err)
		return
	}
	sessions, err := srv.store.DistinctSessions()
	if err != nil {
		serverError(w, "sessions", err)
		return
	}
	recent, err := srv.store.Page("", 50, 0)
	if err != nil {
		serverError(w, "recent", err)
		return
	}
	if recent == nil {
		recent = []store.Row{}
	}
	writeJSON(w, http.StatusOK, statsResponse{
		Counts:   counts,
		Deny:     deny,
		Sessions: sessions,
		Recent:   recent,
	})
}

// writeJSON encodes v as the response body with the given status. A late
// encode failure (client hung up mid-write) can't be recovered — the status
// line is already sent — so it is not surfaced; there is nothing a caller
// could do with it.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// serverError writes a structured 500 carrying a short context label and the
// error text, so an API client always gets JSON.
func serverError(w http.ResponseWriter, ctx string, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": ctx + ": " + err.Error()})
}

// methodNotAllowed writes a structured 405 for a route hit with the wrong verb.
func methodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}
