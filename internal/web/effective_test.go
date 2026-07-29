package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestEffectiveEndpointShape(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srv.policyPath,
		[]byte(`{"version":1,"overrides":{"sudo":{"enabled":false}},"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/policy/effective", nil)
	req.Host = "127.0.0.1:4600"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("effective GET: %d", rec.Code)
	}
	var resp struct {
		Baselines []struct {
			ID              string `json:"id"`
			DefaultSeverity string `json:"defaultSeverity"`
			Override        *struct {
				Enabled  *bool  `json:"enabled"`
				Severity string `json:"severity"`
			} `json:"override"`
		} `json:"baselines"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Baselines) == 0 {
		t.Fatal("expected baseline rules in the response")
	}
	var sudo *bool
	seen := false
	for _, b := range resp.Baselines {
		if b.ID == "sudo" {
			seen = true
			if b.Override == nil {
				t.Fatal("sudo should report its override")
			}
			sudo = b.Override.Enabled
		}
	}
	if !seen {
		t.Fatal("sudo baseline missing from response")
	}
	if sudo == nil || *sudo {
		t.Error("sudo override enabled:false must be reflected")
	}
}
