package web

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lucasngucii/argus/internal/store"
)

func TestDecisionsHandler_FilterAndPaginate(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	seed := []store.Row{
		{TS: "t1", Severity: "low", Verdict: "allow"},
		{TS: "t2", Severity: "high", Verdict: "deny"},
		{TS: "t3", Severity: "low", Verdict: "allow"},
	}
	for _, r := range seed {
		if err := srv.store.Insert(r); err != nil {
			t.Fatal(err)
		}
	}

	// severity filter: only the two low rows.
	var filtered struct {
		Rows       []store.Row `json:"rows"`
		NextBefore int         `json:"nextBefore"`
	}
	getJSON(t, srv, "/api/decisions?severity=low", &filtered)
	if len(filtered.Rows) != 2 {
		t.Fatalf("severity=low rows = %d, want 2", len(filtered.Rows))
	}
	for _, r := range filtered.Rows {
		if r.Severity != "low" {
			t.Errorf("row severity = %q, want low", r.Severity)
		}
	}

	// limit=1: one row, nextBefore points at its id for the next page.
	var page struct {
		Rows       []store.Row `json:"rows"`
		NextBefore int         `json:"nextBefore"`
	}
	getJSON(t, srv, "/api/decisions?limit=1", &page)
	if len(page.Rows) != 1 {
		t.Fatalf("limit=1 rows = %d, want 1", len(page.Rows))
	}
	if page.NextBefore != page.Rows[0].ID || page.NextBefore == 0 {
		t.Fatalf("nextBefore = %d, want the row id %d", page.NextBefore, page.Rows[0].ID)
	}
}

// TestStream_EmitsInsertedRow drives the SSE endpoint over a real httptest
// server, inserts a row, and reads the emitted event with a bounded timeout so
// the test can never hang.
func TestStream_EmitsInsertedRow(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	srv.sseInterval = 10 * time.Millisecond

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}

	if err := srv.store.Insert(store.Row{TS: "t1", Severity: "high", Verdict: "deny", Command: "sudo rm -rf /"}); err != nil {
		t.Fatal(err)
	}

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
		if !strings.Contains(l, "high") {
			t.Fatalf("emitted event missing severity: %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no SSE event within timeout")
	}
}

// TestStream_ReturnsOnContextCancel and _OnShutdown prove the loop unblocks on
// both stop signals — client disconnect and server shutdown — so an open
// stream can never wedge shutdown.
func TestStream_ReturnsOnContextCancel(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	srv.sseInterval = 10 * time.Millisecond
	assertStreamReturns(t, srv, func(cancel context.CancelFunc) { cancel() })
}

func TestStream_ReturnsOnShutdown(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	srv.sseInterval = 10 * time.Millisecond
	assertStreamReturns(t, srv, func(context.CancelFunc) { close(srv.shutdown) })
}

// assertStreamReturns runs handleStream in a goroutine and fires stop (either
// cancelling the request context or closing srv.shutdown), then asserts the
// handler returns promptly.
func assertStreamReturns(t *testing.T, srv *Server, stop func(context.CancelFunc)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.handleStream(rec, req)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond) // let the loop start
	stop(cancel)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleStream did not return after stop signal")
	}
}

// nonFlusher is an http.ResponseWriter that does NOT implement http.Flusher,
// to prove the stream handler rejects a writer it cannot flush.
type nonFlusher struct {
	hdr  http.Header
	code int
	buf  bytes.Buffer
}

func (n *nonFlusher) Header() http.Header         { return n.hdr }
func (n *nonFlusher) Write(b []byte) (int, error) { return n.buf.Write(b) }
func (n *nonFlusher) WriteHeader(code int)        { n.code = code }

func TestStream_500WhenNotFlusher(t *testing.T) {
	srv, err := testServer(t, "127.0.0.1:4600")
	if err != nil {
		t.Fatal(err)
	}
	w := &nonFlusher{hdr: http.Header{}}
	req := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
	srv.handleStream(w, req)
	if w.code != http.StatusInternalServerError {
		t.Fatalf("non-flusher writer: code = %d, want 500", w.code)
	}
}
