package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

// codexGateWireCommand is what fresh Codex wiring writes: the shared gate
// match constant plus the explicit harness flag. It MUST contain gateCommand
// as a substring so the idempotency check below recognizes an existing entry.
const codexGateWireCommand = gateCommand + " --harness=codex"

// codexWiredMatcher is the PreToolUse matcher wired for Codex: shell commands
// only, first cut. Codex's shell tool reports tool_name "Bash"; widen this if
// unified_exec is later confirmed to report a different tool_name.
const codexWiredMatcher = "Bash"

// wireCodexHook idempotently adds a PreToolUse hook that runs argus gate to
// ~/.codex/hooks.json, without disturbing anything else already there. It
// mirrors wireHook's shape: decode into a generic map so unknown keys and
// hook entries round-trip byte-for-byte, and only append when no existing
// entry already runs argus gate.
func wireCodexHook(home string) error {
	path := codexHooksPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("init: create %s: %w", filepath.Dir(path), err)
	}

	settings, err := claudeReadSettings(path)
	if err != nil {
		return err
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		settings["hooks"] = hooks
	}
	preToolUse, _ := hooks["PreToolUse"].([]any)

	if hasGateHook(preToolUse) {
		return nil
	}

	hooks["PreToolUse"] = append(preToolUse, map[string]any{
		"matcher": codexWiredMatcher,
		"hooks": []any{
			map[string]any{"type": "command", "command": codexGateWireCommand},
		},
	})
	return claudeWriteSettings(path, settings)
}

// codexHooksPath returns ~/.codex/hooks.json under home.
func codexHooksPath(home string) string {
	return filepath.Join(home, ".codex", "hooks.json")
}
