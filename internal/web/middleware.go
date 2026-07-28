package web

import (
	"net"
	"net/http"
)

// maxBodyBytes caps every request body. The control-plane's largest legitimate
// body is a policy document; 1 MB is far above any real policy and below
// anything that could pressure memory.
const maxBodyBytes = 1 << 20

// hostGuard rejects any request whose Host header is not a loopback literal.
// This is the DNS-rebinding defense: a rebinding attacker's page resolves its
// hostname to 127.0.0.1 but the browser still sends the attacker's *hostname*
// in Host (e.g. "evil.example.com"), so validating the host portion is a
// loopback literal rejects it. The port is deliberately NOT matched — the
// browser must already be talking to our port to send anything, so the port
// carries no attacker-controlled signal, and pinning it would needlessly
// couple the guard to the bound port (and break ephemeral-port test servers).
func hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHostHeader(r.Host) {
			forbid(w, "host not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loopbackHostHeader reports whether a Host header names the local machine.
// It strips a port if present, then accepts only the loopback literals — never
// a resolvable hostname, which could point anywhere under DNS rebinding.
func loopbackHostHeader(hostHeader string) bool {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

// csrfGuard protects mutating routes. A cross-origin page can issue a simple
// GET/POST without a preflight, but it cannot set a custom request header nor
// force Content-Type: application/json without triggering a CORS preflight the
// browser will block. Requiring both on PUT/POST/DELETE therefore proves the
// request came from our own same-origin frontend. Safe methods pass untouched.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut, http.MethodPost, http.MethodDelete:
			if r.Header.Get("X-Argus-CSRF") != "1" || r.Header.Get("Content-Type") != "application/json" {
				forbid(w, "csrf check failed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody caps request bodies via http.MaxBytesReader, which enforces the
// limit on read: a handler decoding an oversized body gets an error (surfaced
// as 413), so no per-handler size check is needed.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// forbid writes a structured 403 so blocked requests get JSON like the rest of
// the API, never an HTML error page.
func forbid(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"` + reason + `"}`))
}
