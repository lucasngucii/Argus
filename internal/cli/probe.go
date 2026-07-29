package cli

import (
	"fmt"
	"regexp"

	"github.com/lucasngucii/argus/internal/adapter"
)

// harnessFlag matches the harness value in a wired command: `--harness=` followed
// by one run of non-whitespace. Only the `=` form (what fresh wiring writes) is
// recognized; the space-separated form reads as absent, so a hand-editor who uses
// it is treated as a bare (claude-code) install.
var harnessFlag = regexp.MustCompile(`--harness=(\S+)`)

// Probe verifies the named harness's install is intact for doctor. For
// claude-code it checks the PreToolUse hook is wired AND that the harness the
// wired command actually configures is one Argus knows: an unknown value would
// make every live call fail closed, so doctor must FAIL loudly and name it
// rather than silently PASS. Returns nil (→ doctor PASS) or an error (→ FAIL %v).
func Probe(name, home string) error {
	canon, err := adapter.Canonical(name)
	if err != nil {
		return err
	}
	switch canon {
	case "claude-code":
		if err := checkHook(home); err != nil {
			return err
		}
		return checkConfiguredHarness(home)
	default:
		return fmt.Errorf("no probe for harness %q", canon)
	}
}

// checkConfiguredHarness reads the wired command and rejects an unknown
// --harness value. Absent flag ⇒ "" ⇒ claude-code (bare install) ⇒ PASS.
func checkConfiguredHarness(home string) error {
	settings, err := readSettings(settingsPath(home))
	if err != nil {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	entry := gateEntry(preToolUse)
	if entry == nil {
		return nil // no gate entry; checkHook already reported that
	}
	cmd := gateCommandString(entry)
	configured := ""
	if m := harnessFlag.FindStringSubmatch(cmd); m != nil {
		configured = m[1]
	}
	if _, err := adapter.Canonical(configured); err != nil {
		return fmt.Errorf("hook configures %w", err)
	}
	return nil
}
