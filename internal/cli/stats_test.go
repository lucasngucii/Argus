package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStats_SeverityCounts(t *testing.T) {
	s := openTestStore(t)
	rows := []store.Row{
		{TS: "t1", Severity: "high", Verdict: "deny"},
		{TS: "t2", Severity: "low", Verdict: "allow"},
		{TS: "t3", Severity: "low", Verdict: "allow"},
	}
	for _, r := range rows {
		if err := s.Insert(r); err != nil {
			t.Fatal(err)
		}
	}

	buf := &bytes.Buffer{}
	code := Stats(s, buf, false)

	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	out := buf.String()
	if !strings.Contains(out, "high: 1") {
		t.Errorf("output missing %q:\n%s", "high: 1", out)
	}
	if !strings.Contains(out, "low: 2") {
		t.Errorf("output missing %q:\n%s", "low: 2", out)
	}
}

func TestStats_JSONL(t *testing.T) {
	s := openTestStore(t)
	rows := []store.Row{
		{TS: "t1", Severity: "high", Verdict: "deny"},
		{TS: "t2", Severity: "low", Verdict: "allow"},
		{TS: "t3", Severity: "low", Verdict: "allow"},
	}
	for _, r := range rows {
		if err := s.Insert(r); err != nil {
			t.Fatal(err)
		}
	}

	buf := &bytes.Buffer{}
	code := Stats(s, buf, true)

	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d JSONL lines, want 3:\n%s", len(lines), buf.String())
	}
	// Each line must decode into a real store.Row (not just "looks like
	// JSON"), and the export is oldest-first: t1 (high), t2 (low), t3 (low).
	wantTS := []string{"t1", "t2", "t3"}
	wantSeverity := []string{"high", "low", "low"}
	for i, line := range lines {
		var got store.Row
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d did not decode as store.Row: %v\nline: %s", i, err, line)
		}
		if got.TS != wantTS[i] {
			t.Errorf("line %d TS = %q, want %q", i, got.TS, wantTS[i])
		}
		if got.Severity != wantSeverity[i] {
			t.Errorf("line %d Severity = %q, want %q", i, got.Severity, wantSeverity[i])
		}
	}
}
