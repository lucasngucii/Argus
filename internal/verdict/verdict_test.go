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
	} {
		if g := Map(c.sev, c.mode); g != c.want {
			t.Errorf("%s/%s: %s!=%s", c.sev, c.mode, g, c.want)
		}
	}
}

func TestEmit(t *testing.T) {
	var b bytes.Buffer
	_ = Emit(&b, "deny", "pipe-to-shell")
	if !strings.Contains(b.String(), `"permissionDecision":"deny"`) || !strings.Contains(b.String(), `"hookEventName":"PreToolUse"`) {
		t.Fatalf("bad emit: %s", b.String())
	}
}
