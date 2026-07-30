package adapter

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/verdict"
)

// errWriter fails every write, to exercise the fail-closed exit code.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestEmitByteIdentityWithVerdict(t *testing.T) {
	for _, v := range []struct{ verdict, reason string }{
		{"allow", "safe"}, {"ask", "sudo"}, {"deny", "rm -rf /"},
	} {
		var got, want bytes.Buffer
		if code := Emit("claude-code", &got, Outcome{Verdict: v.verdict, Reason: v.reason}); code != 0 {
			t.Fatalf("Emit(%s) code=%d, want 0", v.verdict, code)
		}
		if err := verdict.Emit(&want, v.verdict, v.reason); err != nil {
			t.Fatal(err)
		}
		if got.String() != want.String() {
			t.Errorf("Emit(%s) = %q, want byte-identical %q", v.verdict, got.String(), want.String())
		}
	}
}

func TestEmitFailsClosedOnWriteError(t *testing.T) {
	if code := Emit("claude-code", errWriter{}, Outcome{Verdict: "deny", Reason: "x"}); code != 2 {
		t.Errorf("Emit on write failure code=%d, want 2 (fail-closed)", code)
	}
}

func TestEmitUnknownHarnessFailsClosedNoWrite(t *testing.T) {
	var buf bytes.Buffer
	code := Emit("codex", &buf, Outcome{Verdict: "deny", Reason: "x"})
	if code != 2 {
		t.Errorf("Emit(unknown) code=%d, want 2", code)
	}
	if buf.Len() != 0 {
		t.Errorf("Emit(unknown) wrote %q; must write nothing (cannot speak the protocol)", buf.String())
	}
}

// TestEmitUnknownVerdictCoercedToDeny pins the defense-in-depth choke point:
// an Outcome.Verdict outside {"allow","ask","deny"} (an empty zero-value, or
// some other stray string) must never reach verdict.Emit as-is — it must be
// coerced to "deny" before serialization, since an unrecognized
// permissionDecision is no-opinion to Claude Code, which is fail-open.
func TestEmitUnknownVerdictCoercedToDeny(t *testing.T) {
	for _, v := range []string{"", "block"} {
		var buf bytes.Buffer
		if code := Emit("claude-code", &buf, Outcome{Verdict: v, Reason: "x"}); code != 0 {
			t.Fatalf("Emit(%q) code=%d, want 0", v, code)
		}
		s := buf.String()
		if !strings.Contains(s, `"permissionDecision":"deny"`) {
			t.Errorf("Emit(verdict=%q) must coerce to deny; got %q", v, s)
		}
		if strings.Contains(s, `"permissionDecision":""`) || strings.Contains(s, `"permissionDecision":"`+v+`"`) && v != "" {
			t.Errorf("Emit(verdict=%q) must not serialize the raw unknown verdict; got %q", v, s)
		}
	}
}

func TestEmitDenyNeverBecomesAllow(t *testing.T) {
	var buf bytes.Buffer
	Emit("claude-code", &buf, Outcome{Verdict: "deny", Reason: "floored"})
	s := buf.String()
	if !strings.Contains(s, `"permissionDecision":"deny"`) {
		t.Errorf("deny Outcome must serialize as deny; got %q", s)
	}
	if strings.Contains(s, `"permissionDecision":"allow"`) || strings.Contains(s, `"permissionDecision":"ask"`) {
		t.Errorf("deny Outcome must never emit allow/ask; got %q", s)
	}
}
