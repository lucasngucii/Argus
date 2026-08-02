package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucasngucii/argus/internal/adapter"
)

// RunUninstall is the `argus uninstall` command: the inverse of `argus init`.
// It unwires the PreToolUse hook from every installed harness, stops the
// background server, and — only with --purge — deletes ~/.argus (the policy and
// the decision history). Because npm v7+ runs no uninstall lifecycle scripts and
// Homebrew runs none either, removing the binary alone leaves the wired hook
// pointing at a now-missing `argus`; run this BEFORE removing the binary.
func RunUninstall(argv []string, home string, w io.Writer) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(w)
	purge := fs.Bool("purge", false, "also delete ~/.argus (policy + decision history) — irreversible")
	fs.Usage = func() {
		fmt.Fprint(w, "usage: argus uninstall [--purge]\n\n"+
			"Remove Argus's PreToolUse hook from every installed harness and stop the\n"+
			"background server. Run this BEFORE removing the binary (npm/brew uninstall\n"+
			"do not clean up hooks). --purge also deletes ~/.argus (policy + history).\n")
	}
	if err := fs.Parse(argv); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	rc := 0
	// Unwire each harness whose config dir exists (idempotent per harness).
	for _, h := range []struct{ name, dir string }{
		{"claude-code", filepath.Join(home, ".claude")},
		{"codex", filepath.Join(home, ".codex")},
	} {
		if !dirExists(h.dir) {
			continue
		}
		removed, err := Unwire(h.name, home)
		if err != nil {
			fmt.Fprintf(w, "argus: uninstall: %v\n", err)
			rc = 1
			continue
		}
		if removed {
			fmt.Fprintf(w, "argus: unwired the %s hook\n", h.name)
		}
	}

	// Stop the background server if one is running. A "not running" result is
	// expected during uninstall and is not a failure, so only call ServeStop
	// (which reports non-zero when nothing is running) when a live pid exists.
	if pid, err := readPID(home); err == nil && processAlive(pid) {
		ServeStop(home, w)
	}

	argusDir := filepath.Join(home, ".argus")
	if *purge {
		if err := os.RemoveAll(argusDir); err != nil {
			fmt.Fprintf(w, "argus: uninstall: purge: %v\n", err)
			rc = 1
		} else {
			fmt.Fprintln(w, "argus: purged ~/.argus")
		}
	} else if dirExists(argusDir) {
		fmt.Fprintln(w, "argus: kept ~/.argus (policy + decision history); re-run with --purge to remove it")
	}

	fmt.Fprintln(w, "argus: hooks removed. You can now remove the binary (npm uninstall -g / brew uninstall argus).")
	return rc
}

// Unwire removes the argus gate hook for the named harness, round-tripping
// everything else in the config. It reports whether a gate hook was actually
// present and removed (false = nothing was wired). An unknown harness errors.
func Unwire(name, home string) (bool, error) {
	canon, err := adapter.Canonical(name)
	if err != nil {
		return false, fmt.Errorf("unwire: %w", err)
	}
	switch canon {
	case "claude-code":
		return unwireHookFile(settingsPath(home))
	case "codex":
		return unwireHookFile(codexHooksPath(home))
	default:
		return false, fmt.Errorf("unwire: no config for harness %q", canon)
	}
}

// unwireHookFile drops every inner PreToolUse hook whose command runs argus gate
// (matched by the gateCommand substring, the same identity Wire/doctor use),
// removing an entry left with no inner hooks. Everything else — other events,
// other tools' hooks, unrelated top-level keys — round-trips byte-for-byte. A
// missing file or an absent gate hook is a no-op returning removed=false.
func unwireHookFile(path string) (bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false, nil
	}
	settings, err := readHookSettingsJSON(path)
	if err != nil {
		return false, fmt.Errorf("uninstall: %w", err)
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		return false, nil
	}
	preToolUse, _ := hooks["PreToolUse"].([]any)
	if preToolUse == nil {
		return false, nil
	}

	removed := false
	kept := make([]any, 0, len(preToolUse))
	for _, e := range preToolUse {
		m, ok := e.(map[string]any)
		if !ok {
			kept = append(kept, e)
			continue
		}
		inner, _ := m["hooks"].([]any)
		filtered := make([]any, 0, len(inner))
		for _, h := range inner {
			if hm, ok := h.(map[string]any); ok {
				if cmd, _ := hm["command"].(string); strings.Contains(cmd, gateCommand) {
					removed = true
					continue // drop the argus gate hook
				}
			}
			filtered = append(filtered, h)
		}
		// An entry that existed only to run argus gate is dropped entirely.
		if len(inner) > 0 && len(filtered) == 0 {
			continue
		}
		m["hooks"] = filtered
		kept = append(kept, m)
	}

	if !removed {
		return false, nil
	}
	hooks["PreToolUse"] = kept
	if err := writeHookSettingsJSON(path, settings); err != nil {
		return false, fmt.Errorf("uninstall: %w", err)
	}
	return true, nil
}
