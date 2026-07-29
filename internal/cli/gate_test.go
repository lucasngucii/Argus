package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/store"
)

func run(in string) string {
	var o bytes.Buffer
	Gate(strings.NewReader(in), &o, "/nonexistent-home", "claude-code")
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
	code := Gate(strings.NewReader(in), &out, home, "claude-code")

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

// gateFailWriter fails every write, to exercise Gate's fail-closed exit code.
type gateFailWriter struct{}

func (gateFailWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

// gatePanicReader panics on Read, so json decoding inside adapter.Parse panics
// and propagates to Gate's top-level recover — a deterministic way to drive the
// recover branch with no production-only test seam.
type gatePanicReader struct{}

func (gatePanicReader) Read([]byte) (int, error) { panic("boom") }

func gateOut(t *testing.T, payload, harness string) (string, int) {
	t.Helper()
	home := t.TempDir() // no policy.json → Gate falls back to policy.Default()
	var out bytes.Buffer
	code := Gate(strings.NewReader(payload), &out, home, harness)
	return out.String(), code
}

func TestGateDefaultHarnessIsClaudeCode(t *testing.T) {
	out, code := gateOut(t, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`, "")
	if code != 0 || !strings.Contains(out, `"permissionDecision":"allow"`) {
		t.Errorf("bare install (harness \"\") must behave as claude-code allow; got code=%d out=%q", code, out)
	}
}

func TestGateUnknownHarnessFailsClosed(t *testing.T) {
	out, code := gateOut(t, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`, "codex")
	if code != 2 {
		t.Errorf("unknown harness must exit 2 (fail-closed); got code=%d", code)
	}
	if out != "" {
		t.Errorf("unknown harness must write NOTHING (cannot speak the protocol); got %q", out)
	}
}

func TestGateParseErrorFunnelsDeny(t *testing.T) {
	out, _ := gateOut(t, `not json`, "claude-code")
	if !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Errorf("unparseable payload must emit deny (not empty verdict); got out=%q", out)
	}
}

func TestGateHighSeverityDenies(t *testing.T) {
	out, _ := gateOut(t, `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`, "claude-code")
	if !strings.Contains(out, `"permissionDecision":"deny"`) ||
		strings.Contains(out, `"permissionDecision":"allow"`) ||
		strings.Contains(out, `"permissionDecision":"ask"`) {
		t.Errorf("rm -rf / must deny via the floor and NEVER allow/ask; got %q", out)
	}
}

// Write failure on the terminal emit path must fail closed via exit 2, never a
// dropped 0 (which would be a silent allow in bypassPermissions).
func TestGateWriteFailureFailsClosed(t *testing.T) {
	home := t.TempDir()
	code := Gate(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`),
		gateFailWriter{}, home, "claude-code")
	if code != 2 {
		t.Errorf("stdout write failure must exit 2; got %d", code)
	}
}

// The top-level recover must emit deny (never allow) when the hot path panics.
func TestGateRecoverEmitsDeny(t *testing.T) {
	var out bytes.Buffer
	Gate(gatePanicReader{}, &out, t.TempDir(), "claude-code")
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) ||
		strings.Contains(out.String(), `"permissionDecision":"allow"`) {
		t.Errorf("a panic must recover to deny, never allow; got %q", out.String())
	}
}

// Backward-compat regression: a bare install (harness "") must record the row
// as "claude-code", or replay/close-loop's claudeCodeOnly filter drops it.
// Uses a NON-safe command because Gate only records non-safe decisions.
func TestGateRecordsCanonicalHarnessForBareInstall(t *testing.T) {
	home := t.TempDir()
	// recordDecision's store.Open does NOT create parents; the .argus dir must
	// exist or the row is silently not written (best-effort record).
	if err := os.MkdirAll(filepath.Join(home, ".argus"), 0o755); err != nil {
		t.Fatal(err)
	}
	Gate(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`),
		&bytes.Buffer{}, home, "")
	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, _, err := st.AllDecisions(10, true) // (rows, capped, err); claudeCodeOnly=true → filters harness="claude-code"
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Harness != "claude-code" {
		t.Errorf("bare install must record Harness=claude-code; got %+v", rows)
	}
}
