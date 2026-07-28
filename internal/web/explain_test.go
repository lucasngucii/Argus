package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// postJSON drives a POST through the full Handler() chain with a loopback Host
// and the CSRF header + application/json content-type the csrfGuard requires,
// decoding the response body into out when the status is 200.
func postJSON(t *testing.T, srv *Server, path string, body, out any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Host = "127.0.0.1:4600"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Argus-CSRF", "1")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("POST %s: decode body: %v (%s)", path, err, rec.Body.String())
		}
	}
	return rec
}

type explainResult struct {
	Severity   string   `json:"severity"`
	RuleID     string   `json:"ruleId"`
	Reason     string   `json:"reason"`
	Verdict    string   `json:"verdict"`
	Obfuscated bool     `json:"obfuscated"`
	Commands   []string `json:"commands"`
	PipeSinks  []string `json:"pipeSinks"`
}

func TestExplainHandler_Bash(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	var res explainResult
	rec := postJSON(t, srv, "/api/explain", map[string]string{
		"command": "sudo rm -rf /", "tool": "Bash", "mode": "default",
	}, &res)
	if rec.Code != http.StatusOK {
		t.Fatalf("explain = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if res.Severity != "high" {
		t.Errorf("severity = %q, want high", res.Severity)
	}
	if res.Verdict != "deny" {
		t.Errorf("verdict = %q, want deny", res.Verdict)
	}
	if res.RuleID == "" {
		t.Errorf("ruleId empty, want a firing rule")
	}
}

// TestExplainHandler_File proves the `file` field is wired into the payload so
// a Write/Edit decision explains correctly — not just Bash commands.
func TestExplainHandler_File(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	var res explainResult
	postJSON(t, srv, "/api/explain", map[string]string{
		"file": "/home/x/.ssh/id_ed25519", "tool": "Write", "mode": "default",
	}, &res)
	if res.Severity != "high" || res.Verdict != "deny" {
		t.Fatalf("file explain = %s/%s, want high/deny (file not wired?)", res.Severity, res.Verdict)
	}
}

// TestExplainHandler_CSRF proves the endpoint is behind the mutating-route
// guard: a POST without the CSRF header is rejected before reaching it.
func TestExplainHandler_CSRF(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/explain", bytes.NewReader([]byte(`{}`)))
	req.Host = "127.0.0.1:4600"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("explain without CSRF = %d, want 403", rec.Code)
	}
}
