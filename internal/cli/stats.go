package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/lucasngucii/argus/internal/store"
)

// statsScanLimit bounds the store.Recent read Stats uses to derive the deny
// count, distinct-session count, notable rows, and the jsonl export. The
// store package exposes full-history aggregation only for severity
// (store.Counts); everything else Stats reports comes from this bounded
// scan rather than a new store method for a single caller's bookkeeping. A
// six-figure limit covers any realistic history for a local, single-user
// gate log.
const statsScanLimit = 100000

// Stats prints a terminal digest of recorded decisions: full-history
// severity counts (via store.Counts, never a partial count over Recent),
// how many were denied, how many distinct sessions appear, and the recent
// high/medium rows worth a second look. With jsonl=true it instead streams
// every scanned decision as one JSON object per line, oldest first — the
// continuity export the old /agents-review habit needs (spec §10). It
// always returns 0: a read failure is reported inline to w, and there is no
// separate action a caller could take on a distinct exit code.
func Stats(s *store.Store, w io.Writer, jsonl bool) int {
	rows, err := s.Recent(statsScanLimit)
	if err != nil {
		fmt.Fprintf(w, "recent: %v\n", err)
		return 0
	}

	if jsonl {
		writeJSONL(rows, w)
		return 0
	}

	counts, err := s.Counts()
	if err != nil {
		fmt.Fprintf(w, "counts: %v\n", err)
		return 0
	}
	for _, sev := range []string{"safe", "low", "medium", "high"} {
		fmt.Fprintf(w, "%s: %d\n", sev, counts[sev])
	}

	deny := 0
	sessions := map[string]struct{}{}
	var notable []store.Row
	for _, r := range rows {
		if r.Verdict == "deny" {
			deny++
		}
		if r.Session != "" {
			sessions[r.Session] = struct{}{}
		}
		if r.Severity == "high" || r.Severity == "medium" {
			notable = append(notable, r)
		}
	}
	fmt.Fprintf(w, "deny: %d\n", deny)
	fmt.Fprintf(w, "sessions: %d\n", len(sessions))

	fmt.Fprintln(w, "recent high/medium:")
	for _, r := range notable {
		fmt.Fprintf(w, "  %s [%s] %s: %s\n", r.TS, r.Severity, r.Tool, r.Command)
	}

	return 0
}

// writeJSONL streams rows as one JSON object per line, oldest first. rows
// arrives newest-first (store.Recent's order); a continuity export reads
// naturally in the order decisions actually happened.
func writeJSONL(rows []store.Row, w io.Writer) {
	enc := json.NewEncoder(w)
	for i := len(rows) - 1; i >= 0; i-- {
		if err := enc.Encode(rows[i]); err != nil {
			return
		}
	}
}
