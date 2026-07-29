package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// putRaw drives a PUT with a raw body through the full Handler() chain with the
// loopback Host + CSRF header + application/json the csrfGuard requires.
func putRaw(t *testing.T, srv *Server, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(body))
	req.Host = "127.0.0.1:4600"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Argus-CSRF", "1")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

const minimalPolicy = `{"version":1,"rules":[]}`

func TestPolicy_PutInvalidLeavesFileUntouched(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	before := []byte(minimalPolicy)
	if err := os.WriteFile(srv.policyPath, before, 0o644); err != nil {
		t.Fatal(err)
	}

	rec := putRaw(t, srv, "/api/policy", []byte(`{"version":"x"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid PUT = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	after, _ := os.ReadFile(srv.policyPath)
	if !bytes.Equal(before, after) {
		t.Fatalf("policy.json changed on invalid PUT:\nbefore=%s\nafter=%s", before, after)
	}
	if n, _ := srv.store.PolicyVersionCount(); n != 0 {
		t.Fatalf("policy_versions gained a row on invalid PUT: %d", n)
	}
}

func TestPolicy_PutValidBumpsVersionAndSnapshots(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	// Mimic init: an existing version 1 on disk + a matching snapshot.
	if err := os.WriteFile(srv.policyPath, []byte(minimalPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.InsertPolicyVersion(1, "init", "seed", minimalPolicy, "h1"); err != nil {
		t.Fatal(err)
	}

	var res struct {
		Version int `json:"version"`
	}
	rec := putRaw(t, srv, "/api/policy", []byte(minimalPolicy))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid PUT = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Version != 2 {
		t.Fatalf("returned version = %d, want 2 (maxVersion+1)", res.Version)
	}

	// On-disk document's version field is now 2.
	onDisk, _ := os.ReadFile(srv.policyPath)
	var doc map[string]any
	if err := json.Unmarshal(onDisk, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != float64(2) {
		t.Fatalf("on-disk version = %v, want 2", doc["version"])
	}

	// A matching policy_versions row exists with the SAME number, and its
	// snapshot text equals what was written to disk.
	snap, err := srv.store.PolicyVersionJSON(2)
	if err != nil {
		t.Fatalf("no snapshot for version 2: %v", err)
	}
	if snap != string(onDisk) {
		t.Fatalf("snapshot != on-disk:\nsnap=%s\ndisk=%s", snap, onDisk)
	}
}

func TestPolicy_GetReturnsJSONAndVersions(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srv.policyPath, []byte(minimalPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.InsertPolicyVersion(1, "init", "seed", minimalPolicy, "h1"); err != nil {
		t.Fatal(err)
	}

	var res struct {
		JSON     string `json:"json"`
		Versions []struct {
			Version int    `json:"version"`
			Author  string `json:"author"`
		} `json:"versions"`
	}
	getJSON(t, srv, "/api/policy", &res)
	if !strings.Contains(res.JSON, `"version"`) {
		t.Errorf("GET /api/policy json missing policy text: %q", res.JSON)
	}
	if len(res.Versions) != 1 || res.Versions[0].Version != 1 {
		t.Fatalf("versions = %+v, want one version 1", res.Versions)
	}

	// The snapshot route returns that version's document.
	rec := getJSON(t, srv, "/api/policy/versions/1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET snapshot = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"version"`) {
		t.Errorf("snapshot body missing policy text: %s", rec.Body.String())
	}
}

func TestPolicy_GetMissingFileReturnsThinDefault(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4601")
	if err != nil {
		t.Fatal(err)
	}
	// no os.WriteFile — policy.json does not exist
	req := httptest.NewRequest(http.MethodGet, "/api/policy", nil)
	req.Host = "127.0.0.1:4601"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/policy: %d", rec.Code)
	}
	var res struct {
		JSON string `json:"json"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []any `json:"rules"`
	}
	if err := json.Unmarshal([]byte(res.JSON), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 0 {
		t.Errorf("missing-file default must be thin (0 rules), got %d", len(doc.Rules))
	}
}
