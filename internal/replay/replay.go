// Package replay re-scores stored decisions against a candidate policy and
// reports only what would change. This is Argus's moat over a stateless
// deny-list: because classify.Classify is pure, the same payload replayed
// against a different policy is a deterministic what-if — "which past
// commands this edit would newly flag (or newly wave through)" — answerable
// without re-running any agent.
//
// Rescore covers the LOGGED history only. Plan-1's gate does not persist
// `safe` decisions (noise reduction), so a stored Row is never `safe`;
// replay therefore surfaces low/medium/high transitions but cannot resurface
// a command that was safe-and-unlogged. Callers should say so in their output.
package replay

import (
	"encoding/json"
	"strings"

	"github.com/lucasngucii/argus/internal/classify"
	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
	"github.com/lucasngucii/argus/internal/verdict"
)

// MaxReplay caps how many stored rows a single replay re-scores, bounding
// worst-case work on a large history. Callers pass `capped` through so the
// result can honestly flag a truncated run.
const MaxReplay = 50000

// Change is a single row whose re-scored severity or verdict differs from
// what was stored. It carries the original Row so a UI/CLI can render the
// command that would move.
type Change struct {
	Row         store.Row
	OldSeverity string
	NewSeverity string
	OldVerdict  string
	NewVerdict  string
}

// Result is the diff of a replay: the total rows scored, only the rows that
// changed, a per-verdict-transition tally (keyed "<old>-><new>"), and whether
// the input was truncated at MaxReplay.
type Result struct {
	Total   int
	Changed []Change
	Summary map[string]int
	Capped  bool
}

// Rescore re-runs each stored decision through the candidate policy and
// returns the diff. It is pure: no I/O, no clock, no globals — the same rows
// and policy always yield the same Result. Unchanged rows are not reported.
//
// For each row it reconstructs the hook.Payload the gate originally saw,
// re-classifies it under candidate, maps the new severity to a verdict under
// the row's own permission mode, and records a Change only when either the
// severity or the verdict differs from what was stored.
func Rescore(rows []store.Row, capped bool, candidate policy.Policy) Result {
	res := Result{Total: len(rows), Summary: map[string]int{}, Capped: capped}
	for _, r := range rows {
		ti := hook.ToolInput{Command: r.Command, FilePath: r.File}
		if strings.HasPrefix(r.Tool, "mcp__") {
			ti.Raw = json.RawMessage(r.Command)
		}
		p := hook.Payload{
			ToolName:       r.Tool,
			PermissionMode: r.PermissionMode,
			CWD:            r.CWD,
			ToolInput:      ti,
		}
		d := classify.Classify(p, candidate)
		nv := verdict.Map(d.Severity, r.PermissionMode)
		if d.Severity == r.Severity && nv == r.Verdict {
			continue
		}
		res.Changed = append(res.Changed, Change{
			Row:         r,
			OldSeverity: r.Severity,
			NewSeverity: d.Severity,
			OldVerdict:  r.Verdict,
			NewVerdict:  nv,
		})
		res.Summary[r.Verdict+"->"+nv]++
	}
	return res
}
