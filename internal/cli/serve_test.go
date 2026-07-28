package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/lucasngucii/argus/internal/store"
)

// argusHome creates a temp home with an initialized ~/.argus directory, the
// layout Serve expects (produced by `argus init` in production).
func argusHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".argus"), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// syncBuf is a concurrency-safe writer: Serve writes from its goroutine while
// the test reads to discover the bound URL.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestServe_BadAddrReturnsNonZero(t *testing.T) {
	home := argusHome(t)
	// Pre-create the store so the failure is the address, not the DB.
	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	if err != nil {
		t.Fatalf("seed store: %v (home layout?)", err)
	}
	st.Close()

	w := &bytes.Buffer{}
	if code := Serve(context.Background(), home, "0.0.0.0:4600", w); code == 0 {
		t.Fatalf("Serve(wildcard addr) = 0, want non-zero; out=%s", w.String())
	}
}

// TestServe_ServesThenShutsDownAndCloses proves the full wiring: it serves over
// an ephemeral loopback port, answers /api/stats while an SSE client is open,
// returns promptly on ctx-cancel (SSE does not block shutdown), and releases
// the DB so a fresh Open succeeds afterward (Close ran).
func TestServe_ServesThenShutsDownAndCloses(t *testing.T) {
	home := argusHome(t)
	dbPath := filepath.Join(home, ".argus", "argus.db")
	if st, err := store.Open(dbPath); err != nil {
		t.Fatalf("seed store: %v", err)
	} else {
		st.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := &syncBuf{}
	done := make(chan int, 1)
	go func() { done <- Serve(ctx, home, "127.0.0.1:0", w) }()

	base := waitForURL(t, w)

	// An open SSE client must not block the coming shutdown.
	sseReq, _ := http.NewRequest(http.MethodGet, base+"/api/stream", nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("open SSE: %v", err)
	}
	defer sseResp.Body.Close()

	statsResp, err := http.Get(base + "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	io.Copy(io.Discard, statsResp.Body)
	statsResp.Body.Close()
	if statsResp.StatusCode != http.StatusOK {
		t.Fatalf("/api/stats = %d, want 200", statsResp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("Serve returned %d on clean shutdown, want 0", code)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Serve did not return within the bounded shutdown window")
	}

	// Close ran: the DB handle is free, so a fresh Open succeeds.
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open after shutdown = %v, want success (Close didn't run?)", err)
	}
	st.Close()
}

var urlRE = regexp.MustCompile(`http://[0-9.]+:\d+`)

// waitForURL polls the writer until Serve prints its listen URL.
func waitForURL(t *testing.T, w *syncBuf) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m := urlRE.FindString(w.String()); m != "" {
			return m
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Serve never printed a listen URL; out=%s", w.String())
	return ""
}
