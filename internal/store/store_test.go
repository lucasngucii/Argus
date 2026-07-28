package store

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestInsertRecentCounts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Insert(Row{TS: "t", Severity: "high", Verdict: "deny"})
	_ = s.Insert(Row{TS: "t", Severity: "low", Verdict: "allow"})
	c, _ := s.Counts()
	if c["high"] != 1 || c["low"] != 1 {
		t.Fatalf("counts=%v", c)
	}
}

// Recent must round-trip every field exactly (not just "no error") — Task 11's
// gate and Task 15's stats both read decisions back through this method.
func TestRecentRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	rows := []Row{
		{TS: "t1", Session: "s1", CWD: "/a", Tool: "Bash", Command: "ls", File: "", Severity: "low", Verdict: "allow", PermissionMode: "default", RuleID: "r1", Harness: "claude-code", PolicyVersion: 1, Obfuscation: false},
		{TS: "t2", Session: "s2", CWD: "/b", Tool: "Write", Command: "rm -rf /", File: "x", Severity: "high", Verdict: "deny", PermissionMode: "plan", RuleID: "r2", Harness: "claude-code", PolicyVersion: 2, Obfuscation: true},
		{TS: "t3", Session: "s3", CWD: "/c", Tool: "Edit", Command: "echo hi", File: "y", Severity: "medium", Verdict: "ask", PermissionMode: "default", RuleID: "r3", Harness: "claude-code", PolicyVersion: 3, Obfuscation: false},
	}
	for _, r := range rows {
		if err := s.Insert(r); err != nil {
			t.Fatal(err)
		}
	}

	// LIMIT truncates: 3 inserted, ask for 2.
	got, err := s.Recent(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("Recent(2) returned %d rows, want 2", len(got))
	}

	// Newest-first ordering: last inserted (rows[2]) comes back first.
	// Rows now carry a real assigned ID, so zero it before comparing the
	// rest of the fields against the ID-less want literals.
	if got0 := got[0]; func() Row { got0.ID = 0; return got0 }() != rows[2] {
		t.Fatalf("Recent()[0]=%+v, want newest row %+v", got[0], rows[2])
	}
	if got1 := got[1]; func() Row { got1.ID = 0; return got1 }() != rows[1] {
		t.Fatalf("Recent()[1]=%+v, want %+v", got[1], rows[1])
	}
	if got[0].ID == 0 || got[1].ID == 0 {
		t.Fatalf("Recent() must assign real ids: got[0].ID=%d got[1].ID=%d", got[0].ID, got[1].ID)
	}

	// Fetch all 3 and confirm every field round-trips exactly, including
	// the Obfuscation bool and PolicyVersion int (not just non-error).
	all, err := s.Recent(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("Recent(3) returned %d rows, want 3", len(all))
	}
	want := []Row{rows[2], rows[1], rows[0]}
	for i := range want {
		r := all[i]
		if r.ID == 0 {
			t.Fatalf("Recent()[%d] must have a real id", i)
		}
		r.ID = 0
		if r != want[i] {
			t.Fatalf("Recent()[%d]=%+v, want %+v", i, all[i], want[i])
		}
	}
}

func TestClose(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "close.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	if _, err := s.Recent(1); err == nil {
		t.Fatal("expected an error using the store after Close")
	}
}

func TestMaxID(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "maxid.db"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.MaxID()
	if err != nil {
		t.Fatal(err)
	}
	if m != 0 {
		t.Fatalf("MaxID on empty store = %d, want 0", m)
	}
	if err := s.Insert(Row{TS: "t", Severity: "low"}); err != nil {
		t.Fatal(err)
	}
	m, err = s.MaxID()
	if err != nil {
		t.Fatal(err)
	}
	if m <= 0 {
		t.Fatalf("MaxID after insert = %d, want >0", m)
	}
}

func TestDecisionsAfterCursor(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cursor.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ts := range []string{"t1", "t2", "t3", "t4"} {
		if err := s.Insert(Row{TS: ts, Severity: "low"}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.Recent(4)
	if err != nil {
		t.Fatal(err)
	}
	var midID int
	for _, r := range all {
		if r.TS == "t2" {
			midID = r.ID
		}
	}
	if midID == 0 {
		t.Fatal("could not locate t2's id")
	}

	tail, err := s.DecisionsAfter(midID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 2 {
		t.Fatalf("DecisionsAfter tail len = %d, want 2: %+v", len(tail), tail)
	}
	if tail[0].TS != "t3" || tail[1].TS != "t4" {
		t.Fatalf("DecisionsAfter tail = %+v, want oldest-first t3,t4", tail)
	}
	if tail[0].ID == 0 || tail[1].ID == 0 {
		t.Fatal("DecisionsAfter must return rows with real ids")
	}
}

func TestPageFilter(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "page.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Insert(Row{TS: "t1", Severity: "high"})
	_ = s.Insert(Row{TS: "t2", Severity: "low"})
	_ = s.Insert(Row{TS: "t3", Severity: "high"})

	high, err := s.Page("high", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(high) != 2 {
		t.Fatalf("Page(\"high\") len = %d, want 2: %+v", len(high), high)
	}
	if high[0].TS != "t3" || high[1].TS != "t1" {
		t.Fatalf("Page(\"high\") = %+v, want newest-first t3,t1", high)
	}

	all, err := s.Page("", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("Page(\"\") len = %d, want 3", len(all))
	}

	before, err := s.Page("", 10, all[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 2 {
		t.Fatalf("Page before newest id len = %d, want 2: %+v", len(before), before)
	}
}

func TestDistinctSessionsIgnoresEmpty(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Insert(Row{TS: "t1", Session: ""})
	_ = s.Insert(Row{TS: "t2", Session: "s1"})
	n, err := s.DistinctSessions()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("DistinctSessions() = %d, want 1", n)
	}
}

func TestVerdictCount(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "verdict.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Insert(Row{TS: "t1", Verdict: "deny"})
	_ = s.Insert(Row{TS: "t2", Verdict: "allow"})
	_ = s.Insert(Row{TS: "t3", Verdict: "deny"})
	n, err := s.VerdictCount("deny")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("VerdictCount(\"deny\") = %d, want 2", n)
	}
}

func TestPolicyVersionsRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "versions.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertPolicyVersion(1, "web", "seed", `{"version":1}`, "hash1"); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertPolicyVersion(2, "web", "tighten", `{"version":2}`, "hash2"); err != nil {
		t.Fatal(err)
	}

	metas, err := s.PolicyVersions()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("PolicyVersions() len = %d, want 2", len(metas))
	}
	if metas[0].Version != 2 || metas[1].Version != 1 {
		t.Fatalf("PolicyVersions() = %+v, want newest-first [2,1]", metas)
	}
	if metas[0].Hash != "hash2" || metas[0].Note != "tighten" {
		t.Fatalf("PolicyVersions()[0] = %+v", metas[0])
	}

	j, err := s.PolicyVersionJSON(1)
	if err != nil {
		t.Fatal(err)
	}
	if j != `{"version":1}` {
		t.Fatalf("PolicyVersionJSON(1) = %q, want %q", j, `{"version":1}`)
	}
}

func TestAllDecisionsCapped(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "all.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ts := range []string{"t1", "t2", "t3", "t4", "t5"} {
		if err := s.Insert(Row{TS: ts, Harness: "claude-code"}); err != nil {
			t.Fatal(err)
		}
	}
	rows, capped, err := s.AllDecisions(3, false)
	if err != nil {
		t.Fatal(err)
	}
	if !capped {
		t.Fatal("AllDecisions(3, false) capped = false, want true")
	}
	if len(rows) != 3 {
		t.Fatalf("AllDecisions(3, false) len = %d, want 3", len(rows))
	}
	if rows[0].TS != "t1" || rows[2].TS != "t3" {
		t.Fatalf("AllDecisions must be oldest-first: %+v", rows)
	}
}

func TestAllDecisionsClaudeCodeOnly(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "all2.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Insert(Row{TS: "t1", Harness: "claude-code"})
	_ = s.Insert(Row{TS: "t2", Harness: "agent-review"})
	rows, capped, err := s.AllDecisions(100, true)
	if err != nil {
		t.Fatal(err)
	}
	if capped {
		t.Fatal("AllDecisions(100, true) capped = true, want false")
	}
	if len(rows) != 1 || rows[0].TS != "t1" {
		t.Fatalf("AllDecisions(100, true) = %+v, want only the claude-code row", rows)
	}
}

// Real deployment model: many SEPARATE connections writing + a concurrent reader.
func TestProcessLevelConcurrencyNoBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	seed, _ := Open(path)
	_ = seed.Insert(Row{TS: "t", Severity: "low"})
	var wg sync.WaitGroup
	errc := make(chan error, 40)
	// 30 independent writer connections (proxy for separate processes)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, e := Open(path)
			if e != nil {
				errc <- e
				return
			}
			errc <- w.Insert(Row{TS: "t", Severity: "low"})
		}()
	}
	// concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := Open(path)
			if e != nil {
				errc <- e
				return
			}
			_, e = r.Recent(5)
			errc <- e
		}()
	}
	wg.Wait()
	close(errc)
	for e := range errc {
		if e != nil {
			t.Fatalf("SQLITE_BUSY/err under process-level load: %v", e)
		}
	}
}
