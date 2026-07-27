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
	if got[0] != rows[2] {
		t.Fatalf("Recent()[0]=%+v, want newest row %+v", got[0], rows[2])
	}
	if got[1] != rows[1] {
		t.Fatalf("Recent()[1]=%+v, want %+v", got[1], rows[1])
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
		if all[i] != want[i] {
			t.Fatalf("Recent()[%d]=%+v, want %+v", i, all[i], want[i])
		}
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
