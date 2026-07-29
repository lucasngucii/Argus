package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// StartServeDaemon launches `argus serve` as a detached background process
// (the docker -d model): it survives the parent's exit and the terminal
// closing. It is idempotent — an already-running instance is left alone — and
// it never blocks, so `argus init` returns immediately after the child starts.
func StartServeDaemon(home, addr string, w io.Writer) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate argus binary: %w", err)
	}
	return startServeDaemon(exe, home, addr, w)
}

// startServeDaemon is the testable core: exe is injected so a test can point
// the spawn at a harmless stand-in instead of a real server. The serving
// child, not this spawner, owns the pid file (see cli.Serve) — we only read it
// to decide whether a live instance already exists.
func startServeDaemon(exe, home, addr string, w io.Writer) error {
	if pid, err := readPID(home); err == nil && processAlive(pid) {
		fmt.Fprintf(w, "argus: serve already running (pid %d)\n", pid)
		return nil
	}

	if !daemonSupported {
		return fmt.Errorf("background serve is not supported on this platform; run `argus serve` manually")
	}

	logPath := filepath.Join(home, ".argus", "serve.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open serve log: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command(exe, "serve", "--addr", addr)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start background serve: %w", err)
	}

	fmt.Fprintf(w, "argus: serving in background (pid %d) on %s, logs at %s\n", cmd.Process.Pid, addr, logPath)
	return nil
}
