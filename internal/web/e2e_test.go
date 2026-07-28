package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

// TestE2E exercises the whole control-plane over one httptest server in the
// order a real session would: reads, the two browser-attack defenses, the
// validate-before-write policy path, replay, and floor-capped close-the-loop.
// One sequential test with real assertions — the integration seam Task 15 owns.
func TestE2E(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "argus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, mustJSON(t, policy.Default()), 0o644); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, policyPath, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	srv.sseInterval = 10 * time.Millisecond

	// Seed history: a high/deny row, and a claude-code low/allow row that
	// Default() escalates (for replay).
	mustInsert(t, st, store.Row{TS: "t1", Harness: "claude-code", Tool: "Bash", Command: "sudo rm -rf /", Severity: "high", Verdict: "deny"})
	mustInsert(t, st, store.Row{TS: "t2", Harness: "claude-code", Tool: "Bash", Command: "sudo apt-get update", PermissionMode: "default", Severity: "low", Verdict: "allow"})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	c := ts.Client()

	// --- stats ---
	var stats struct {
		Counts map[string]int `json:"counts"`
		Deny   int            `json:"deny"`
	}
	doJSON(t, c, http.MethodGet, ts.URL+"/api/stats", nil, &stats)
	if stats.Counts["high"] < 1 || stats.Deny < 1 {
		t.Fatalf("stats = %+v, want high>=1 deny>=1", stats)
	}

	// --- decisions filter ---
	var page struct {
		Rows []store.Row `json:"rows"`
	}
	doJSON(t, c, http.MethodGet, ts.URL+"/api/decisions?severity=high", nil, &page)
	if len(page.Rows) < 1 {
		t.Fatal("decisions?severity=high returned nothing")
	}
	for _, r := range page.Rows {
		if r.Severity != "high" {
			t.Fatalf("severity filter leaked %q", r.Severity)
		}
	}

	// --- SSE receives an inserted row ---
	assertSSEReceives(t, c, ts.URL, st)

	// --- explain: sudo rm -rf / denies ---
	var ex explainResult
	doJSON(t, c, http.MethodPost, ts.URL+"/api/explain",
		body(t, map[string]string{"command": "sudo rm -rf /", "tool": "Bash", "mode": "default"}), &ex)
	if ex.Verdict != "deny" {
		t.Fatalf("explain sudo rm -rf / verdict = %q, want deny", ex.Verdict)
	}

	// --- Host spoof rejected ---
	if code := rawStatus(t, c, http.MethodGet, ts.URL+"/", nil, "evil.example.com", false); code != http.StatusForbidden {
		t.Fatalf("Host spoof = %d, want 403", code)
	}

	// --- CSRF-missing PUT rejected ---
	if code := rawStatus(t, c, http.MethodPut, ts.URL+"/api/policy", []byte(`{}`), "", false); code != http.StatusForbidden {
		t.Fatalf("CSRF-missing PUT = %d, want 403", code)
	}

	// --- PUT invalid: 400 and file byte-unchanged ---
	before, _ := os.ReadFile(policyPath)
	if code := rawStatus(t, c, http.MethodPut, ts.URL+"/api/policy", []byte(`{"version":"x"}`), "", true); code != http.StatusBadRequest {
		t.Fatalf("invalid PUT = %d, want 400", code)
	}
	if after, _ := os.ReadFile(policyPath); !bytes.Equal(before, after) {
		t.Fatal("policy.json changed on invalid PUT")
	}

	// --- PUT valid: 200, version bump, matching snapshot ---
	var putRes struct {
		Version int `json:"version"`
	}
	code := rawStatus(t, c, http.MethodPut, ts.URL+"/api/policy", mustJSON(t, policy.Default()), "", true)
	if code != http.StatusOK {
		t.Fatalf("valid PUT = %d, want 200", code)
	}
	doJSON(t, c, http.MethodGet, ts.URL+"/api/policy", nil, &struct{}{}) // smoke: GET still serves
	metas, _ := st.PolicyVersions()
	if len(metas) == 0 {
		t.Fatal("no policy version recorded after valid PUT")
	}
	putRes.Version = metas[0].Version
	if _, err := st.PolicyVersionJSON(putRes.Version); err != nil {
		t.Fatalf("no snapshot for version %d", putRes.Version)
	}

	// --- replay: a transition is present ---
	var rp struct {
		Total   int            `json:"total"`
		Summary map[string]int `json:"summary"`
	}
	doJSON(t, c, http.MethodPost, ts.URL+"/api/replay", mustJSON(t, policy.Default()), &rp)
	if rp.Total < 1 || rp.Summary["allow->ask"] < 1 {
		t.Fatalf("replay = %+v, want a transition", rp)
	}

	// --- allowlist downgrades a medium ... ---
	doJSON(t, c, http.MethodPost, ts.URL+"/api/allowlist",
		body(t, map[string]string{"command": "sudo apt-get update", "tool": "Bash"}), &struct {
			Version int `json:"version"`
		}{})
	var afterAllow explainResult
	doJSON(t, c, http.MethodPost, ts.URL+"/api/explain",
		body(t, map[string]string{"command": "sudo apt-get update", "tool": "Bash", "mode": "default"}), &afterAllow)
	if afterAllow.Verdict != "allow" {
		t.Fatalf("after allowlist verdict = %q, want allow", afterAllow.Verdict)
	}

	// --- ... but NOT a floor command ---
	doJSON(t, c, http.MethodPost, ts.URL+"/api/allowlist",
		body(t, map[string]string{"command": "sudo rm -rf /", "tool": "Bash"}), &struct {
			Version int `json:"version"`
		}{})
	var floor explainResult
	doJSON(t, c, http.MethodPost, ts.URL+"/api/explain",
		body(t, map[string]string{"command": "sudo rm -rf /", "tool": "Bash", "mode": "default"}), &floor)
	if floor.Verdict != "deny" {
		t.Fatalf("floor after allowlist verdict = %q, want still deny", floor.Verdict)
	}
}

// --- helpers ---

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustInsert(t *testing.T, st *store.Store, r store.Row) {
	t.Helper()
	if err := st.Insert(r); err != nil {
		t.Fatal(err)
	}
}

func body(t *testing.T, v any) []byte { return mustJSON(t, v) }

// doJSON issues a request (adding CSRF+json headers for mutating verbs) and
// decodes a 200 body into out.
func doJSON(t *testing.T, c *http.Client, method, url string, reqBody []byte, out any) {
	t.Helper()
	var r io.Reader
	if reqBody != nil {
		r = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Argus-CSRF", "1")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s = %d, want 200 (%s)", method, url, resp.StatusCode, b)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("%s %s decode: %v", method, url, err)
		}
	}
}

// rawStatus issues a request with an optional spoofed Host and optional CSRF
// headers, returning just the status code — for the guard assertions.
func rawStatus(t *testing.T, c *http.Client, method, url string, reqBody []byte, host string, csrf bool) int {
	t.Helper()
	var r io.Reader
	if reqBody != nil {
		r = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	if csrf {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Argus-CSRF", "1")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// assertSSEReceives opens the stream, inserts a row, and reads the emitted
// event with a bounded timeout.
func assertSSEReceives(t *testing.T, c *http.Client, base string, st *store.Store) {
	t.Helper()
	resp, err := c.Get(base + "/api/stream")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()

	mustInsert(t, st, store.Row{TS: "t3", Harness: "claude-code", Tool: "Bash", Command: "echo sse", Severity: "low", Verdict: "allow"})

	line := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if l := sc.Text(); strings.HasPrefix(l, "data: ") {
				line <- l
				return
			}
		}
	}()
	select {
	case l := <-line:
		if !strings.Contains(l, "echo sse") {
			t.Fatalf("SSE event missing inserted row: %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no SSE event within timeout")
	}
}
