// Package web is Argus's local observability + governance control-plane: a
// loopback-only HTTP server exposing a JSON+SSE API and the embedded no-build
// frontend. It reads the decision store and, for the editor/close-the-loop,
// validates-then-writes policy.json; it never re-implements the Plan-1 verdict
// path, only reuses classify/verdict/policy/replay.
//
// The server's only authentication is being bound to loopback, so it defends
// the two browser-reachable attack vectors explicitly (Task 6 middleware):
// a Host-header allowlist (defeats DNS-rebinding) and CSRF on mutating routes.
package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/lucasngucii/argus/internal/store"
)

// shutdownGrace bounds how long a graceful shutdown waits for in-flight
// requests to drain. It is deliberately short: the SSE loops (Task 8) select
// on srv.shutdown and return on their own, so shutdown must not hang waiting
// for a long-lived stream to close.
const shutdownGrace = 5 * time.Second

// Server is the control-plane HTTP server. It is constructed with a validated,
// loopback-normalized address and holds the store + policy path the handlers
// read. shutdown is closed once, in ListenAndServe, to signal per-connection
// SSE loops to stop so an open stream can never block shutdown.
type Server struct {
	store      *store.Store
	policyPath string
	addr       string
	shutdown   chan struct{}
}

// New validates addr down to a loopback bind and returns a Server. It refuses
// any non-loopback bind — the server has no auth beyond being unreachable from
// the network, so binding the wildcard or a routable address would expose an
// unauthenticated policy editor. A port-only addr (":4600") is rewritten to
// 127.0.0.1 rather than left as the wildcard the kernel would otherwise pick.
func New(s *store.Store, policyPath, addr string) (*Server, error) {
	norm, err := normalizeLoopbackAddr(addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		store:      s,
		policyPath: policyPath,
		addr:       norm,
		shutdown:   make(chan struct{}),
	}, nil
}

// Addr returns the normalized, loopback-guaranteed bind address (host:port).
func (srv *Server) Addr() string { return srv.addr }

// normalizeLoopbackAddr parses addr and returns a loopback host:port, or an
// error for any bind that would be reachable off-host. Rules: a missing port
// is an error; an empty host (the port-only ":4600" form) is rewritten to
// 127.0.0.1; every other host must resolve to a loopback literal or the name
// "localhost" — 0.0.0.0, ::, routable IPs, and arbitrary hostnames are all
// rejected.
func normalizeLoopbackAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid addr %q: %w", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("invalid addr %q: missing port", addr)
	}
	if host == "" {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	if !isLoopbackHost(host) {
		return "", fmt.Errorf("refusing non-loopback bind %q: host %q is not loopback", addr, host)
	}
	return net.JoinHostPort(host, port), nil
}

// isLoopbackHost reports whether host is safe to bind: the literal name
// "localhost", or an IP that IsLoopback. An unparseable, non-"localhost"
// hostname is rejected — resolving it could point anywhere, defeating the
// loopback guarantee.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Handler builds the request multiplexer wrapped in the security middleware
// chain: hostGuard (anti DNS-rebinding) -> csrfGuard (mutating routes) ->
// limitBody (1 MB cap) -> mux. Routes: GET / serves the embedded shell,
// /static/* serves embedded assets, and any unmatched /api/* returns a JSON
// 404 (so an unknown endpoint is a structured error, not the HTML shell).
// Concrete /api handlers register in Tasks 7-11.
func (srv *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/api/", notFoundJSON)
	mux.HandleFunc("/", srv.serveIndex)
	return hostGuard(csrfGuard(limitBody(mux)))
}

// serveIndex writes the embedded index.html shell. A read failure here means
// the binary was built without its assets — a build error, not a runtime
// condition — so it surfaces as a 500.
func (srv *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "index unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// notFoundJSON responds to unmatched /api/* routes with a structured 404 so
// API clients always get JSON, never the HTML shell.
func notFoundJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"not found"}`))
}

// ListenAndServe serves until ctx is cancelled, then shuts down gracefully
// within shutdownGrace. On cancel it first closes srv.shutdown so the SSE
// loops stop pushing and return, then calls http.Server.Shutdown with a
// bounded context — so an open stream can neither block the drain nor be left
// dangling. A normal shutdown returns nil; only a bind/serve failure or a
// drain that overruns the grace window returns an error.
func (srv *Server) ListenAndServe(ctx context.Context) error {
	hs := &http.Server{Addr: srv.addr, Handler: srv.Handler()}

	serveErr := make(chan error, 1)
	go func() {
		err := hs.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		close(srv.shutdown)
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return hs.Shutdown(sctx)
	}
}
