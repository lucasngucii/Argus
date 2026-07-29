package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// pidPath returns ~/.argus/argus.pid under home. It lives beside policy.json
// and argus.db so the classifier's existing .argus/ self-protection covers it.
func pidPath(home string) string {
	return filepath.Join(home, ".argus", "argus.pid")
}

// writePID records pid in the pid file, 0o600 so only the owner can read the
// serving process id.
func writePID(home string, pid int) error {
	if err := os.WriteFile(pidPath(home), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	return nil
}

// readPID returns the recorded pid. A missing file yields an os.IsNotExist
// error so callers can tell "not running" from a corrupt pid file.
func readPID(home string) (int, error) {
	b, err := os.ReadFile(pidPath(home))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("parse pid file: %w", err)
	}
	return pid, nil
}

// removePID deletes the pid file. A missing file is not an error, so a clean
// shutdown after an external delete still succeeds.
func removePID(home string) error {
	err := os.Remove(pidPath(home))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove pid file: %w", err)
	}
	return nil
}
