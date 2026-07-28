package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// okHandler is a trivial next-handler that records it was reached.
func okHandler() (http.Handler, *bool) {
	reached := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	return h, &reached
}

func TestHostGuard(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		wantOK bool
	}{
		{"loopback ipv4 with port", "127.0.0.1:4600", true},
		{"loopback ipv4 other port", "127.0.0.1:54321", true},
		{"localhost with port", "localhost:4600", true},
		{"ipv6 loopback with port", "[::1]:4600", true},
		{"bare localhost no port", "localhost", true},
		{"dns-rebind hostname", "evil.example.com", false},
		{"dns-rebind hostname with port", "evil.example.com:4600", false},
		{"routable ip", "10.0.0.5:4600", false},
		{"empty host", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next, reached := okHandler()
			h := hostGuard(next)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tt.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if tt.wantOK {
				if !*reached || rec.Code != http.StatusOK {
					t.Fatalf("Host %q: reached=%v code=%d, want reached+200", tt.host, *reached, rec.Code)
				}
				return
			}
			if *reached {
				t.Fatalf("Host %q reached handler, want blocked", tt.host)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("Host %q: code=%d, want 403", tt.host, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("Host %q: 403 Content-Type=%q, want application/json", tt.host, ct)
			}
		})
	}
}

func TestCSRFGuard(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		csrf        string
		contentType string
		wantOK      bool
	}{
		{"GET passes without header", http.MethodGet, "", "", true},
		{"HEAD passes", http.MethodHead, "", "", true},
		{"PUT with header+json passes", http.MethodPut, "1", "application/json", true},
		{"POST with header+json passes", http.MethodPost, "1", "application/json", true},
		{"PUT missing csrf header blocked", http.MethodPut, "", "application/json", false},
		{"PUT wrong content-type blocked", http.MethodPut, "1", "text/plain", false},
		{"POST no content-type blocked", http.MethodPost, "1", "", false},
		{"DELETE missing csrf blocked", http.MethodDelete, "", "application/json", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next, reached := okHandler()
			h := csrfGuard(next)
			req := httptest.NewRequest(tt.method, "/api/policy", nil)
			if tt.csrf != "" {
				req.Header.Set("X-Argus-CSRF", tt.csrf)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if tt.wantOK {
				if !*reached {
					t.Fatalf("%s csrf=%q ct=%q blocked, want passthrough", tt.method, tt.csrf, tt.contentType)
				}
				return
			}
			if *reached {
				t.Fatalf("%s csrf=%q ct=%q reached handler, want 403", tt.method, tt.csrf, tt.contentType)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: code=%d, want 403", tt.method, rec.Code)
			}
		})
	}
}

func TestLimitBody(t *testing.T) {
	// The wrapped body must reject reads beyond 1 MB.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "too big", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := limitBody(next)

	big := strings.NewReader(strings.Repeat("a", (1<<20)+1))
	req := httptest.NewRequest(http.MethodPost, "/api/policy", big)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: code=%d, want 413", rec.Code)
	}

	small := strings.NewReader(strings.Repeat("a", 1024))
	req = httptest.NewRequest(http.MethodPost, "/api/policy", small)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("small body: code=%d, want 200", rec.Code)
	}
}

// TestHandler_ChainRejectsSpoofedHost proves the middleware chain is actually
// wired into Handler(): a spoofed Host is rejected before reaching any route.
func TestHandler_ChainRejectsSpoofedHost(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "evil.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed Host through Handler() = %d, want 403", rec.Code)
	}
}
