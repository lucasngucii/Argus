package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

func TestReplayHandler_ReportsTransition(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	// A claude-code low/allow row that Default() escalates to medium/ask.
	if err := srv.store.Insert(store.Row{
		TS: "t1", Harness: "claude-code", Tool: "Bash",
		Command: "sudo apt-get update", PermissionMode: "default",
		Severity: "low", Verdict: "allow",
	}); err != nil {
		t.Fatal(err)
	}

	candidate, _ := json.Marshal(policy.Default())
	var res struct {
		Total   int            `json:"total"`
		Summary map[string]int `json:"summary"`
		Changed []struct {
			NewVerdict string `json:"newVerdict"`
		} `json:"changed"`
	}
	rec := postJSON(t, srv, "/api/replay", json.RawMessage(candidate), &res)
	if rec.Code != http.StatusOK {
		t.Fatalf("replay = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if res.Total < 1 {
		t.Fatalf("total = %d, want >=1", res.Total)
	}
	if res.Summary["allow->ask"] != 1 {
		t.Fatalf("summary = %+v, want allow->ask:1", res.Summary)
	}
}

// explainVerdict is a small helper: allowlist-then-explain flows need to check
// what a command classifies as after a policy write.
func explainVerdict(t *testing.T, srv *Server, command, tool string) explainResult {
	t.Helper()
	var res explainResult
	rec := postJSON(t, srv, "/api/explain", map[string]string{
		"command": command, "tool": tool, "mode": "default",
	}, &res)
	if rec.Code != http.StatusOK {
		t.Fatalf("explain %q = %d (%s)", command, rec.Code, rec.Body.String())
	}
	return res
}

func TestAllowlistHandler_DowngradesNonFloor(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	// Before: sudo apt-get update is medium/ask under Default().
	if v := explainVerdict(t, srv, "sudo apt-get update", "Bash"); v.Verdict != "ask" {
		t.Fatalf("precondition: verdict = %q, want ask", v.Verdict)
	}

	var res struct {
		Version int `json:"version"`
	}
	rec := postJSON(t, srv, "/api/allowlist", map[string]string{
		"command": "sudo apt-get update", "tool": "Bash",
	}, &res)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowlist = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if res.Version < 1 {
		t.Fatalf("version = %d, want a written version", res.Version)
	}

	// After: the same command now classifies safe/allow (per-request policy load).
	if v := explainVerdict(t, srv, "sudo apt-get update", "Bash"); v.Verdict != "allow" || v.Severity != "safe" {
		t.Fatalf("after allowlist = %s/%s, want safe/allow", v.Severity, v.Verdict)
	}
}

// TestAllowlistHandler_FloorStaysDenied proves the always-high floor is
// non-downgradable: allowlisting a catastrophic command must NOT wave it
// through — classify.Classify skips allowlist downgrades on a floor hit.
func TestAllowlistHandler_FloorStaysDenied(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, srv, "/api/allowlist", map[string]string{
		"command": "sudo rm -rf /", "tool": "Bash",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowlist = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if v := explainVerdict(t, srv, "sudo rm -rf /", "Bash"); v.Verdict != "deny" {
		t.Fatalf("floor after allowlist = %s/%s, want still deny", v.Severity, v.Verdict)
	}
}

// TestAllowlistPersistsThinFile proves the allowlist handler writes back the
// thin policy File (overrides + user rules), never the effective Policy —
// otherwise baseline rules like sudo/git-danger would get re-fattened into
// policy.json.
func TestAllowlistPersistsThinFile(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"tool":"Bash","command":"echo hi"}`
	req := httptest.NewRequest(http.MethodPost, "/api/allowlist", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Argus-CSRF", "1")
	req.Host = "127.0.0.1:4600"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowlist POST: %d %s", rec.Code, rec.Body.String())
	}
	written, err := os.ReadFile(srv.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var f policy.File
	if err := json.Unmarshal(written, &f); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.Rules {
		if r.ID == "sudo" || r.ID == "git-danger" {
			t.Fatalf("baseline %q must NOT be written back into the file", r.ID)
		}
	}
	if len(f.Rules) != 1 || !f.Rules[0].Allow {
		t.Errorf("expected exactly the new allow rule, got %+v", f.Rules)
	}
}
