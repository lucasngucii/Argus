package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lucasngucii/argus/internal/classify"
	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/shellast"
	"github.com/lucasngucii/argus/internal/verdict"
)

// explainRequest is the POST /api/explain body: a hypothetical tool call to
// dry-run. File carries a Write/Edit path so file rules explain too, not only
// Bash commands.
type explainRequest struct {
	Command string `json:"command"`
	Tool    string `json:"tool"`
	CWD     string `json:"cwd"`
	Mode    string `json:"mode"`
	File    string `json:"file"`
}

// explainResponse mirrors the CLI `argus explain` output as JSON: the firing
// rule, severity, reason, mapped verdict, the obfuscation flag, and the AST
// facts (resolved commands and pipe sinks) the classifier judged.
type explainResponse struct {
	Severity   string   `json:"severity"`
	RuleID     string   `json:"ruleId"`
	Reason     string   `json:"reason"`
	Verdict    string   `json:"verdict"`
	Obfuscated bool     `json:"obfuscated"`
	Commands   []string `json:"commands"`
	PipeSinks  []string `json:"pipeSinks"`
}

// handleExplain dry-runs a hypothetical tool call through the same
// parse -> classify -> map pipeline Gate uses and returns why it lands where
// it does. It loads the policy per-request from policyPath so an explain always
// reflects the current policy.json (right after an edit, with no cached
// staleness and no lock). It reuses classify.Classify / verdict.Map /
// shellast.Extract — never a parallel classifier.
func (srv *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req explainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "explain", err)
		return
	}

	payload := hook.Payload{
		ToolName:       req.Tool,
		CWD:            req.CWD,
		PermissionMode: req.Mode,
		ToolInput:      hook.ToolInput{Command: req.Command, FilePath: req.File},
	}
	facts := shellast.Extract(payload.Subject())
	d := classify.Classify(payload, srv.loadPolicy())
	v := verdict.Map(d.Severity, req.Mode)

	writeJSON(w, http.StatusOK, explainResponse{
		Severity:   d.Severity,
		RuleID:     d.RuleID,
		Reason:     d.Reason,
		Verdict:    v,
		Obfuscated: d.Obfuscated,
		Commands:   renderCommands(facts.Commands),
		PipeSinks:  nonNilStrings(facts.PipeSinks),
	})
}

// loadPolicy returns the current policy for the read-classify endpoints
// (explain, replay default). A missing or unreadable policy.json falls back to
// Default() so the control-plane still explains against the baseline rules
// before a first edit — matching the CLI's explain behavior.
func (srv *Server) loadPolicy() policy.Policy {
	pol, err := policy.Load(srv.policyPath)
	if err != nil {
		return policy.Default()
	}
	return pol
}

// renderCommands formats the resolved AST commands as `name arg1 arg2` strings
// so a reader sees the same argv the classifier judged. Always non-nil so the
// JSON field is [] rather than null.
func renderCommands(cmds []shellast.Cmd) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, strings.TrimSpace(c.Name+" "+strings.Join(c.Args, " ")))
	}
	return out
}

// nonNilStrings coerces a nil slice to empty so JSON encodes [] not null.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
