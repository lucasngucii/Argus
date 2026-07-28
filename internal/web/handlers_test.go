package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lucasngucii/argus/internal/store"
)

// getJSON drives a GET through the full Handler() chain with a loopback Host
// and decodes the JSON body into v.
func getJSON(t *testing.T, srv *Server, path string, v any) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1:4600"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && v != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatalf("GET %s: decode body: %v (%s)", path, err, rec.Body.String())
		}
	}
	return rec
}

func TestStatsHandler(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	rows := []store.Row{
		{TS: "t1", Session: "s1", Severity: "high", Verdict: "deny"},
		{TS: "t2", Session: "s1", Severity: "low", Verdict: "allow"},
		{TS: "t3", Session: "s2", Severity: "low", Verdict: "allow"},
	}
	for _, r := range rows {
		if err := srv.store.Insert(r); err != nil {
			t.Fatal(err)
		}
	}

	var body struct {
		Counts   map[string]int `json:"counts"`
		Deny     int            `json:"deny"`
		Sessions int            `json:"sessions"`
		Recent   []store.Row    `json:"recent"`
	}
	rec := getJSON(t, srv, "/api/stats", &body)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/stats = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if body.Counts["high"] != 1 {
		t.Errorf("counts.high = %d, want 1", body.Counts["high"])
	}
	if body.Counts["low"] != 2 {
		t.Errorf("counts.low = %d, want 2", body.Counts["low"])
	}
	if body.Deny < 1 {
		t.Errorf("deny = %d, want >=1", body.Deny)
	}
	if body.Sessions != 2 {
		t.Errorf("sessions = %d, want 2", body.Sessions)
	}
	if len(body.Recent) != 3 {
		t.Errorf("recent len = %d, want 3", len(body.Recent))
	}
}
