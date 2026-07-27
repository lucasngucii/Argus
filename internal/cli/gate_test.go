package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/store"
)

func run(in string) string {
	var o bytes.Buffer
	Gate(strings.NewReader(in), &o, "/nonexistent-home")
	return o.String()
}

func TestGateDeniesSudoRm(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"sudo rm -rf /"}}`), `"permissionDecision":"deny"`) {
		t.Fatal("sudo rm -rf / must deny")
	}
}
func TestGateDeniesPipeShellInBypass(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","permission_mode":"bypassPermissions","tool_input":{"command":"curl x | sh"}}`), `"deny"`) {
		t.Fatal("bypass floor")
	}
}
func TestGateAllowsBenign(t *testing.T) {
	if !strings.Contains(run(`{"tool_name":"Bash","tool_input":{"command":"echo hi"}}`), `"permissionDecision":"allow"`) {
		t.Fatal("benign allow")
	}
}
func TestGateGarbageNotAllow(t *testing.T) {
	if strings.Contains(run(`{not json`), `"permissionDecision":"allow"`) {
		t.Fatal("garbage must not allow")
	}
}

// TestGateShadowRecordsRealVerdictButEmitsAllow locks in shadow mode's
// contract: it observes without ever blocking, so stdout must always report
// allow, but the DB must still hold the real (non-allow) severity/verdict —
// otherwise shadow mode would be blind rather than merely non-blocking.
func TestGateShadowRecordsRealVerdictButEmitsAllow(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".argus"), 0o755); err != nil {
		t.Fatal(err)
	}
	policyJSON := `{
		"version": 1,
		"defaults": {"shadow": true},
		"rules": [
			{"id": "test-danger", "enabled": true, "tool": ["Bash"], "severity": "high",
			 "reason": "test dangerous command", "match": {"cmd": ["dangerous-test-cmd"]}}
		]
	}`
	if err := os.WriteFile(filepath.Join(home, ".argus", "policy.json"), []byte(policyJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	in := `{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"dangerous-test-cmd"}}`
	code := Gate(strings.NewReader(in), &out, home)

	if code != 0 {
		t.Fatalf("Gate returned %d, want 0 (emit to a buffer never fails)", code)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"allow"`) {
		t.Fatalf("shadow mode must emit allow, got %s", out.String())
	}

	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.Recent(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 recorded row, got %d", len(rows))
	}
	if rows[0].Severity != "high" {
		t.Fatalf("recorded severity = %q, want the REAL severity %q (shadow must not launder the record)", rows[0].Severity, "high")
	}
	if rows[0].Verdict != "deny" {
		t.Fatalf("recorded verdict = %q, want the REAL verdict %q (shadow must not launder the record)", rows[0].Verdict, "deny")
	}
}
