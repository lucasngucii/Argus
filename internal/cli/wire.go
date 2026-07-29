package cli

import (
	"fmt"

	"github.com/lucasngucii/argus/internal/adapter"
)

// Wire installs the PreToolUse hook for the named harness into its config. It
// dispatches by harness; the claude-code case wires ~/.claude/settings.json.
// An unknown harness errors (init fails loudly) rather than writing to an
// arbitrary path.
func Wire(name, home string) error {
	canon, err := adapter.Canonical(name)
	if err != nil {
		return fmt.Errorf("wire: %w", err)
	}
	switch canon {
	case "claude-code":
		return wireHook(home)
	default:
		return fmt.Errorf("wire: no wiring for harness %q", canon)
	}
}
