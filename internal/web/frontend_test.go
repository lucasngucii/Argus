package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getAsset(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1:4600"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestFrontend_ShellReferencesAssets(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	rec := getAsset(t, srv, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, ref := range []string{"/static/app.mjs", "/static/style.css"} {
		if !strings.Contains(body, ref) {
			t.Errorf("index.html does not reference %q", ref)
		}
	}
}

func TestFrontend_AssetsServedWithSaneTypes(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"/static/app.mjs":   "javascript",
		"/static/live.mjs":  "javascript",
		"/static/stats.mjs": "javascript",
		"/static/style.css": "css",
	}
	for path, wantCT := range cases {
		rec := getAsset(t, srv, path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
			continue
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET %s served empty body", path)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, wantCT) {
			t.Errorf("GET %s Content-Type = %q, want to contain %q", path, ct, wantCT)
		}
	}
}
