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
