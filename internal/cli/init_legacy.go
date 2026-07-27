package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lucasngucii/argus/internal/store"
)

// legacyDecision mirrors the pre-Argus agent-review gate's JSONL schema.
// Fields decode to their Go zero value when absent (some early lines
// predate "severity") — exactly the "missing fields default" behavior the
// import needs.
type legacyDecision struct {
	TS       string `json:"ts"`
	Verdict  string `json:"verdict"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	Session  string `json:"session"`
	CWD      string `json:"cwd"`
	Tool     string `json:"tool"`
	Command  string `json:"command"`
	File     string `json:"file"`
}

// importLegacyDecisions best-effort imports the pre-Argus agent-review
// gate's decision log into the decisions table, once, so history survives
// the cutover. A missing legacy file is the common case (nothing to do), a
// line that isn't valid JSON is skipped, and a row that fails to insert is
// skipped — none of this can fail Init, which has already done the work
// that actually matters (policy + hook wiring) by the time this runs.
func importLegacyDecisions(home, dbPath string) {
	legacyPath := filepath.Join(home, ".claude", "agent-review", "decisions.jsonl")
	f, err := os.Open(legacyPath)
	if err != nil {
		return // no legacy log to import
	}
	defer f.Close()

	// A sentinel file, not a DB query, guards against re-importing on a
	// repeat Init: it's the simplest way to make a one-time migration
	// idempotent without adding a query to the store package for a single
	// caller's bookkeeping.
	argusDir := filepath.Dir(dbPath)
	sentinel := filepath.Join(argusDir, ".legacy-imported")
	if _, err := os.Stat(sentinel); err == nil {
		return // already imported once
	}

	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: init: import legacy decisions: open store: %v\n", err)
		return
	}

	imported, skipped := importLegacyLines(f, st)
	fmt.Fprintf(os.Stderr, "argus: init: imported %d legacy decision(s), skipped %d\n", imported, skipped)

	// Best-effort marker: if this write itself fails, the worst case is a
	// repeat import on the next Init, not a correctness bug.
	_ = os.WriteFile(sentinel, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// importLegacyLines scans f as newline-delimited legacy decisions and
// inserts each into st, tolerating malformed lines and insert failures.
func importLegacyLines(f *os.File, st *store.Store) (imported, skipped int) {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // legacy commands can embed long heredocs
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var d legacyDecision
		if err := json.Unmarshal(line, &d); err != nil {
			skipped++
			continue
		}
		row := store.Row{
			TS:       d.TS,
			Session:  d.Session,
			CWD:      d.CWD,
			Tool:     d.Tool,
			Command:  d.Command,
			File:     d.File,
			Severity: d.Severity,
			Verdict:  d.Verdict,
			RuleID:   "legacy-import",
			Harness:  "agent-review",
		}
		if err := st.Insert(row); err != nil {
			skipped++
			continue
		}
		imported++
	}
	return imported, skipped
}
