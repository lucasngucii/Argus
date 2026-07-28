//go:build unix

package cli

import (
	"os"
	"syscall"
)

// daemonSupported gates background serve to platforms where detachAttr can
// truly detach the child from the controlling terminal.
const daemonSupported = true

// termSignal is the signal ServeStop delivers — SIGTERM, which serve's
// signal.NotifyContext turns into a graceful shutdown.
const termSignal = syscall.SIGTERM

// detachAttr starts the child in its own session (setsid) so it outlives the
// parent process and the terminal that launched it — the essence of docker -d.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// processAlive reports whether pid names a live process. Signal 0 performs the
// kernel's existence/permission check without delivering a signal; EPERM means
// the process exists but is owned by another user, which still counts as alive.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || err == syscall.EPERM
}
