package adapter

import (
	"bytes"
	"strings"
	"testing"
)

func TestShapeCodexCollapsesAsk(t *testing.T) {
	for in, want := range map[string]string{"allow": "allow", "ask": "deny", "deny": "deny"} {
		if got := Shape("codex", in); got != want {
			t.Errorf("Shape(codex, %q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodexEmitAllowIsEmptyExit0(t *testing.T) {
	var buf bytes.Buffer
	if code := Emit("codex", &buf, Outcome{Verdict: "allow", Reason: "safe"}); code != 0 {
		t.Fatalf("allow code=%d, want 0", code)
	}
	if got := strings.TrimSpace(buf.String()); got != "{}" {
		t.Errorf("codex allow must be {}; got %q", got)
	}
}

func TestCodexEmitDenyExits2AndNames(t *testing.T) {
	var buf bytes.Buffer
	code := Emit("codex", &buf, Outcome{Verdict: "deny", Reason: "rm -rf /"})
	if code != 2 { // exit 2 blocks even if Codex ignores the JSON body
		t.Errorf("codex deny must exit 2; got %d", code)
	}
	if !strings.Contains(buf.String(), `"permissionDecision":"deny"`) {
		t.Errorf("codex deny must serialize a deny body for the reason; got %q", buf.String())
	}
	// Both the wrapper key and hookEventName must be present, or a regression
	// dropping the hookSpecificOutput wrapper would go uncaught.
	if !strings.Contains(buf.String(), `"hookSpecificOutput"`) {
		t.Errorf("codex deny must wrap the body in hookSpecificOutput; got %q", buf.String())
	}
	if !strings.Contains(buf.String(), `"hookEventName":"PreToolUse"`) {
		t.Errorf("codex deny must name hookEventName PreToolUse; got %q", buf.String())
	}
}

func TestCodexEmitFailsClosedOnWriteError(t *testing.T) {
	if code := Emit("codex", errWriter{}, Outcome{Verdict: "deny", Reason: "x"}); code != 2 {
		t.Errorf("codex write failure must exit 2; got %d", code)
	}
}
