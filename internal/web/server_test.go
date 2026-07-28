package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucasngucii/argus/internal/store"
)

func testServer(t *testing.T, addr string) (*Server, error) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return New(s, filepath.Join(t.TempDir(), "policy.json"), addr)
}

func TestNew_AddrValidation(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		want    string // normalized Addr(); "" means expect error
		wantErr bool
	}{
		{"explicit loopback", "127.0.0.1:4600", "127.0.0.1:4600", false},
		{"ipv6 loopback", "[::1]:4600", "[::1]:4600", false},
		{"localhost", "localhost:4600", "localhost:4600", false},
		{"port-only rewrites to loopback", ":4600", "127.0.0.1:4600", false},
		{"ipv4 wildcard rejected", "0.0.0.0:4600", "", true},
		{"ipv6 wildcard rejected", "[::]:4600", "", true},
		{"non-loopback rejected", "1.2.3.4:80", "", true},
		{"unknown hostname rejected", "evil.example.com:4600", "", true},
		{"missing port rejected", "127.0.0.1", "", true},
		{"empty rejected", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := testServer(t, tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New(%q) = nil error, want error (got addr %q)", tt.addr, srv.Addr())
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q) unexpected error: %v", tt.addr, err)
			}
			if srv.Addr() != tt.want {
				t.Fatalf("Addr() = %q, want %q", srv.Addr(), tt.want)
			}
		})
	}
}

func TestHandler_ServesIndexAnd404(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// Requests go through the hostGuard chain, so use a loopback Host.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:4600"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<") {
		t.Errorf("GET / body has no markup:\n%s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/nope", nil)
	req.Host = "127.0.0.1:4600"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/nope = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("404 Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Errorf("404 body not JSON: %v (%s)", err, rec.Body.String())
	}
}

// TestListenAndServe_ShutsDownOnContextCancel proves the server returns
// promptly when its context is cancelled and closes srv.shutdown so SSE loops
// (Task 8) can unblock.
func TestListenAndServe_ShutsDownOnContextCancel(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()

	// Give the listener a moment, then cancel.
	select {
	case err := <-done:
		t.Fatalf("server exited before cancel: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned error on shutdown: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("ListenAndServe did not return within the bounded shutdown window")
	}

	select {
	case <-srv.shutdown:
	default:
		t.Fatal("srv.shutdown not closed after shutdown")
	}
}
