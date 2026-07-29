package cli

import (
	"fmt"
	"io"
	"os"
)

// ServeStatus reports whether a background serve is running, per the pid file.
// It returns 0 when a live server is recorded and non-zero otherwise, so shell
// callers can branch on `argus serve --status`.
func ServeStatus(home string, w io.Writer) int {
	pid, err := readPID(home)
	if err != nil || !processAlive(pid) {
		fmt.Fprintln(w, "argus: serve not running")
		return 1
	}
	fmt.Fprintf(w, "argus: serve running (pid %d)\n", pid)
	return 0
}

// ServeStop sends SIGTERM to the recorded background serve, triggering the same
// graceful shutdown as Ctrl-C. It returns non-zero when nothing is running so
// `argus serve --stop` fails loudly on a typo rather than silently no-op'ing.
func ServeStop(home string, w io.Writer) int {
	pid, err := readPID(home)
	if err != nil || !processAlive(pid) {
		fmt.Fprintln(w, "argus: serve not running")
		return 1
	}
	if err := terminate(pid); err != nil {
		fmt.Fprintf(w, "argus: serve stop: %v\n", err)
		return 1
	}
	fmt.Fprintf(w, "argus: serve stopped (pid %d)\n", pid)
	return 0
}

// terminate delivers SIGTERM to pid. It is a thin wrapper so the signal number
// stays on the unix side of the build split.
func terminate(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := proc.Signal(termSignal); err != nil {
		return fmt.Errorf("signal process %d: %w", pid, err)
	}
	return nil
}
