package verdict

import (
	"bytes"
	"strings"
	"testing"
)

func TestMap(t *testing.T) {
	for _, c := range []struct{ sev, mode, want string }{
		{"low", "default", "allow"}, {"medium", "default", "ask"}, {"medium", "plan", "ask"},
		{"medium", "acceptEdits", "deny"}, {"medium", "dontAsk", "deny"}, {"medium", "auto", "deny"},
		{"medium", "bypassPermissions", "deny"}, {"high", "default", "deny"},
		{"bogus", "default", "deny"}, {"medium", "", "ask"}, {"safe", "default", "allow"},
	} {
		if g := Map(c.sev, c.mode); g != c.want {
			t.Errorf("%s/%s: %s!=%s", c.sev, c.mode, g, c.want)
		}
	}
}

func TestEmit(t *testing.T) {
	var b bytes.Buffer
	_ = Emit(&b, "deny", "pipe-to-shell")
	out := b.String()
	if !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, `"hookEventName":"PreToolUse"`) {
		t.Fatalf("bad emit: %s", out)
	}
	if !strings.Contains(out, `"permissionDecisionReason":"argus: pipe-to-shell"`) {
		t.Fatalf("missing argus: prefix in reason: %s", out)
	}
	if strings.Contains(out, "suppressOutput") {
		t.Fatalf("deny should not set suppressOutput: %s", out)
	}
}

func TestEmitSuppressOutput(t *testing.T) {
	var allow bytes.Buffer
	_ = Emit(&allow, "allow", "x")
	if !strings.Contains(allow.String(), `"suppressOutput":true`) {
		t.Fatalf("allow should set suppressOutput:true: %s", allow.String())
	}
	if !strings.Contains(allow.String(), `"permissionDecisionReason":"argus: x"`) {
		t.Fatalf("missing argus: prefix in reason: %s", allow.String())
	}

	var ask bytes.Buffer
	_ = Emit(&ask, "ask", "x")
	if strings.Contains(ask.String(), "suppressOutput") {
		t.Fatalf("ask should not set suppressOutput: %s", ask.String())
	}
}
