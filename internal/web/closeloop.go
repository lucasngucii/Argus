package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/replay"
	"github.com/lucasngucii/argus/internal/store"
)

// errMissingCommandTool rejects an allowlist request that omits either field —
// both are required to build a scoped, specific allow rule.
var errMissingCommandTool = fmt.Errorf("command and tool are required")

// replayChange is the API view of a replay.Change with camelCase keys.
type replayChange struct {
	Row         store.Row `json:"row"`
	OldSeverity string    `json:"oldSeverity"`
	NewSeverity string    `json:"newSeverity"`
	OldVerdict  string    `json:"oldVerdict"`
	NewVerdict  string    `json:"newVerdict"`
}

// replayResponse is the POST /api/replay payload: how many logged decisions
// were scored, only the rows whose severity/verdict would change, a
// per-transition tally, and whether the input was truncated at MaxReplay.
type replayResponse struct {
	Total   int            `json:"total"`
	Changed []replayChange `json:"changed"`
	Summary map[string]int `json:"summary"`
	Capped  bool           `json:"capped"`
}

// handleReplay re-scores the logged decision history against a candidate policy
// and returns the diff. It validates the candidate first (400 on invalid),
// reads through store.AllDecisions(claudeCodeOnly) so legacy agent-review rows
// are excluded, and reuses the pure replay.Rescore engine — never a parallel
// classifier. It writes nothing: replay is read-only.
func (srv *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		badRequest(w, "read body", err)
		return
	}
	candidate, err := parsePolicy(body)
	if err != nil {
		badRequest(w, "invalid policy", err)
		return
	}

	rows, capped, err := srv.store.AllDecisions(replay.MaxReplay, true)
	if err != nil {
		serverError(w, "read decisions", err)
		return
	}
	res := replay.Rescore(rows, capped, candidate)
	writeJSON(w, http.StatusOK, toReplayResponse(res))
}

// allowlistRequest is the POST /api/allowlist body: close-the-loop from a
// decision row. Command is the subject to allow (a Bash command, or a file
// path for a Write/Edit decision); Tool scopes the rule; Note annotates the
// version.
type allowlistRequest struct {
	Command string `json:"command"`
	Tool    string `json:"tool"`
	Note    string `json:"note"`
}

// handleAllowlist appends an Allow rule matching exactly the given command to
// the current policy, then goes through the SAME validate -> version -> write
// -> snapshot path as PUT. The always-high floor still wins: classify.Classify
// only applies allowlist downgrades when no floor/AlwaysHigh rule hit, so this
// endpoint needs no special-casing — a floor command stays denied after an
// allowlist attempt (proven by test).
func (srv *Server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req allowlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "allowlist", err)
		return
	}
	if req.Command == "" || req.Tool == "" {
		badRequest(w, "allowlist", errMissingCommandTool)
		return
	}

	f := srv.loadFile()
	f.Rules = append(f.Rules, allowRule(req))

	body, err := json.Marshal(f)
	if err != nil {
		serverError(w, "marshal policy", err)
		return
	}
	if err := policy.Validate(body); err != nil {
		// A validation failure here means the current policy.json is itself
		// invalid — surface it rather than writing over it.
		badRequest(w, "resulting policy invalid", err)
		return
	}
	next, err := srv.persistPolicy(body, allowlistNote(req))
	if err != nil {
		serverError(w, "persist policy", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"version": next})
}

// allowRule builds an Allow rule that matches exactly the observed subject via
// an anchored Raw regexp — the most specific shape possible, so close-the-loop
// waves through this one command, not a broad class. Raw is a subject-text
// match (not a shell-AST fact), so it works for Bash commands and file paths
// alike.
func allowRule(req allowlistRequest) policy.Rule {
	return policy.Rule{
		ID:      "allow-" + shortHash(req.Tool+"\x00"+req.Command),
		Enabled: true,
		Allow:   true,
		Tool:    []string{req.Tool},
		Match:   policy.Match{Raw: "^" + regexp.QuoteMeta(req.Command) + "$"},
		Reason:  allowlistNote(req),
	}
}

// allowlistNote returns the rule/version note, defaulting to a stable label
// when the caller gave none.
func allowlistNote(req allowlistRequest) string {
	if req.Note != "" {
		return req.Note
	}
	return "allowlisted via web: " + req.Command
}

// shortHash returns a stable 12-hex-char digest, giving each allow rule a
// deterministic id derived from what it allows (no clock, no randomness).
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// parsePolicy schema-validates then decodes a candidate policy document — the
// shared "bytes to Policy" path for endpoints that need the parsed value.
func parsePolicy(body []byte) (policy.Policy, error) {
	return policy.EffectiveFromBytes(body)
}

// toReplayResponse maps the engine Result to the camelCase API view.
func toReplayResponse(res replay.Result) replayResponse {
	changed := make([]replayChange, 0, len(res.Changed))
	for _, c := range res.Changed {
		changed = append(changed, replayChange{
			Row:         c.Row,
			OldSeverity: c.OldSeverity,
			NewSeverity: c.NewSeverity,
			OldVerdict:  c.OldVerdict,
			NewVerdict:  c.NewVerdict,
		})
	}
	return replayResponse{Total: res.Total, Changed: changed, Summary: res.Summary, Capped: res.Capped}
}
