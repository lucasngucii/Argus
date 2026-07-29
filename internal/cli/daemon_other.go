//go:build !unix

package cli

import (
	"os"
	"syscall"
)

// daemonSupported is false off unix: without setsid we cannot promise a truly
// detached child, so StartServeDaemon refuses rather than leave a half-daemon.
const daemonSupported = false

// termSignal falls back to os.Interrupt off unix, where SIGTERM is unavailable.
var termSignal os.Signal = os.Interrupt

// detachAttr is a no-op stub; the !daemonSupported guard means it is never
// reached on these platforms.
func detachAttr() *syscall.SysProcAttr { return nil }

// processAlive conservatively reports not-running off unix (no signal-0
// probe), so callers treat any recorded pid as stale.
func processAlive(int) bool { return false }
