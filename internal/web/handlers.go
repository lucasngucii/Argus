package web

import (
	"encoding/json"
	"net/http"
	"strconv"

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

// decisionsResponse is the GET /api/decisions payload: one page of rows
// (newest-first) plus the id to pass as ?before= for the next older page.
// NextBefore is 0 when the page is empty (no more to fetch).
type decisionsResponse struct {
	Rows       []store.Row `json:"rows"`
	NextBefore int         `json:"nextBefore"`
}

// handleDecisions answers GET /api/decisions?severity=&limit=&before= by
// paging the store newest-first. limit is clamped to [1,200] (default 50) so a
// client can't request an unbounded scan; an empty severity means all
// severities; before<=0 starts at the newest row. NextBefore carries the
// oldest returned id so the client can request the next page without the
// server holding cursor state.
func (srv *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	q := r.URL.Query()
	limit := clampInt(atoiOr(q.Get("limit"), 50), 1, 200)
	before := atoiOr(q.Get("before"), 0)

	rows, err := srv.store.Page(q.Get("severity"), limit, before)
	if err != nil {
		serverError(w, "decisions", err)
		return
	}
	next := 0
	if len(rows) > 0 {
		next = rows[len(rows)-1].ID
	}
	if rows == nil {
		rows = []store.Row{}
	}
	writeJSON(w, http.StatusOK, decisionsResponse{Rows: rows, NextBefore: next})
}

// atoiOr parses s as an int, returning def when s is empty or malformed — the
// tolerant parse a query parameter wants (a bad ?limit= falls back to the
// default rather than erroring the request).
func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// clampInt bounds n to [lo, hi].
func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
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
