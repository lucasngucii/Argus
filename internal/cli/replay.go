package cli

import (
	"fmt"
	"io"
	"sort"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/replay"
	"github.com/lucasngucii/argus/internal/store"
)

// Replay re-scores the logged decision history against a candidate policy and
// prints the what-if diff: how many decisions were scored, how many would
// change, the per-verdict-transition table, and each changed command's
// old->new move. It reads through store.AllDecisions with claudeCodeOnly=true
// so legacy agent-review rows (scored by the old engine) are excluded, and it
// re-uses the pure replay.Rescore engine — no parallel classification.
//
// It always prints the safe-not-covered caveat: Plan-1's gate does not persist
// `safe` decisions, so replay can surface low/medium/high transitions but can
// never resurface a command that was safe-and-unlogged. It returns non-zero
// only when the store read fails; a clean no-change replay is a success.
func Replay(s *store.Store, candidate policy.Policy, w io.Writer) int {
	rows, capped, err := s.AllDecisions(replay.MaxReplay, true)
	if err != nil {
		fmt.Fprintf(w, "replay: read decisions: %v\n", err)
		return 1
	}

	res := replay.Rescore(rows, capped, candidate)

	fmt.Fprintf(w, "%d decisions scored, %d changed\n", res.Total, len(res.Changed))

	for _, t := range sortedTransitions(res.Summary) {
		fmt.Fprintf(w, "  %s: %d\n", t.key, t.n)
	}

	for _, c := range res.Changed {
		fmt.Fprintf(w, "  %s -> %s  [%s] %s\n",
			c.OldVerdict, c.NewVerdict, c.NewSeverity, subject(c.Row))
	}

	if res.Capped {
		fmt.Fprintf(w, "NOTE: only first %d scored\n", replay.MaxReplay)
	}
	fmt.Fprintln(w, "NOTE: safe (unlogged) decisions are not covered")

	return 0
}

// transition is one "<old>-><new>" tally, extracted so the summary prints in a
// stable order (map iteration is randomized, and a non-deterministic CLI is a
// bug per CLAUDE.md's testing rules).
type transition struct {
	key string
	n   int
}

// sortedTransitions returns the summary counts sorted by transition key so the
// table is deterministic across runs.
func sortedTransitions(summary map[string]int) []transition {
	ts := make([]transition, 0, len(summary))
	for k, n := range summary {
		ts = append(ts, transition{k, n})
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].key < ts[j].key })
	return ts
}

// subject renders the command a changed row moved on — the Bash command, or
// the file path for a Write/Edit decision.
func subject(r store.Row) string {
	if r.Command != "" {
		return r.Command
	}
	return r.File
}
