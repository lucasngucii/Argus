package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestServeStatus_NotRunning(t *testing.T) {
	home := daemonHome(t)
	var w bytes.Buffer
	if code := ServeStatus(home, &w); code == 0 {
		t.Fatalf("ServeStatus(no pid) = 0, want non-zero")
	}
	if !strings.Contains(w.String(), "not running") {
		t.Fatalf("output = %q, want 'not running'", w.String())
	}
}

func TestServeStatus_Running(t *testing.T) {
	home := daemonHome(t)
	if err := writePID(home, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if code := ServeStatus(home, &w); code != 0 {
		t.Fatalf("ServeStatus(alive) = %d, want 0", code)
	}
	if !strings.Contains(w.String(), "running") {
		t.Fatalf("output = %q, want 'running'", w.String())
	}
}

func TestServeStop_NotRunning(t *testing.T) {
	home := daemonHome(t)
	var w bytes.Buffer
	if code := ServeStop(home, &w); code == 0 {
		t.Fatalf("ServeStop(no pid) = 0, want non-zero")
	}
	if !strings.Contains(w.String(), "not running") {
		t.Fatalf("output = %q, want 'not running'", w.String())
	}
}

// TestServeStop_TerminatesChild spawns a real long-lived child, records its
// pid, and proves ServeStop signals it dead.
func TestServeStop_TerminatesChild(t *testing.T) {
	home := daemonHome(t)
	child := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	if err := writePID(home, child.Process.Pid); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if code := ServeStop(home, &w); code != 0 {
		t.Fatalf("ServeStop(alive child) = %d, want 0; out=%s", code, w.String())
	}

	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-done:
		// terminated as expected
	case <-time.After(5 * time.Second):
		_ = child.Process.Kill()
		t.Fatal("child not terminated by ServeStop within 5s")
	}
	if processAlive(child.Process.Pid) {
		t.Fatal("child still alive after ServeStop")
	}
}
