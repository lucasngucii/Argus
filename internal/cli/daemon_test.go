package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func daemonHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".argus"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

// reapedPID starts and reaps a trivial child, returning a pid that is now
// guaranteed dead — a deterministic stand-in for a stale pid file.
func reapedPID(t *testing.T) int {
	t.Helper()
	c := exec.Command("/bin/sh", "-c", "exit 0")
	if err := c.Start(); err != nil {
		t.Fatalf("start throwaway child: %v", err)
	}
	pid := c.Process.Pid
	_ = c.Wait()
	return pid
}

func TestProcessAlive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("processAlive(self) = false, want true")
	}
	if processAlive(reapedPID(t)) {
		t.Fatal("processAlive(reaped) = true, want false")
	}
}

// TestStartServeDaemon_SkipsWhenAlive proves idempotency: a live recorded pid
// means no second server is spawned. The bogus exe would error if we tried to
// launch it, so a nil return proves the launch was skipped.
func TestStartServeDaemon_SkipsWhenAlive(t *testing.T) {
	home := daemonHome(t)
	if err := writePID(home, os.Getpid()); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := startServeDaemon("/nonexistent/argus", home, "127.0.0.1:4600", &w); err != nil {
		t.Fatalf("startServeDaemon(alive pid) = %v, want nil (skip)", err)
	}
	if !strings.Contains(w.String(), "already running") {
		t.Fatalf("output = %q, want 'already running'", w.String())
	}
}

// TestStartServeDaemon_SpawnsWhenNoPID launches a detached child when nothing
// is recorded. /bin/echo stands in for the real binary: it exits immediately,
// so the test leaves no process behind.
func TestStartServeDaemon_SpawnsWhenNoPID(t *testing.T) {
	home := daemonHome(t)

	var w bytes.Buffer
	if err := startServeDaemon("/bin/echo", home, "127.0.0.1:4600", &w); err != nil {
		t.Fatalf("startServeDaemon(no pid) = %v, want nil", err)
	}
	if !strings.Contains(w.String(), "background") {
		t.Fatalf("output = %q, want 'background'", w.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".argus", "serve.log")); err != nil {
		t.Fatalf("serve.log not created: %v", err)
	}
}

// TestStartServeDaemon_SpawnsWhenStale launches when the recorded pid is dead.
func TestStartServeDaemon_SpawnsWhenStale(t *testing.T) {
	home := daemonHome(t)
	if err := writePID(home, reapedPID(t)); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := startServeDaemon("/bin/echo", home, "127.0.0.1:4600", &w); err != nil {
		t.Fatalf("startServeDaemon(stale pid) = %v, want nil", err)
	}
	if !strings.Contains(w.String(), "background") {
		t.Fatalf("output = %q, want 'background'", w.String())
	}
}
