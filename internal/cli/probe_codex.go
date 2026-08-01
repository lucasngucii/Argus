package cli

import (
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// checkCodexHook verifies ~/.codex/hooks.json has an entry that runs the argus
// gate command, mirroring checkHook for Claude Code.
func checkCodexHook(home string) error {
	settings, err := readHookSettingsJSON(codexHooksPath(home))
	if err != nil {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	if !hasGateHook(preToolUse) {
		return fmt.Errorf("no PreToolUse entry runs %q", gateCommand)
	}
	return nil
}

// codexConfigPath returns ~/.codex/config.toml under home.
func codexConfigPath(home string) string {
	return filepath.Join(home, ".codex", "config.toml")
}

// codexHooksFlagEnabled reads ~/.codex/config.toml and reports whether the
// Codex hooks feature flag is confirmed enabled: the canonical key is
// [features].hooks; the deprecated alias is [features].codex_hooks (Task 3.E
// must confirm the alias still enables hooks on the pinned Codex version).
// Decoding uses a real TOML parser (github.com/BurntSushi/toml), so strings,
// comments, escapes, dotted keys, and arrays of tables are all handled
// correctly per the TOML spec — no hand-rolled lexing to get subtly wrong.
//
// This is intentionally fail-closed: it gates Probe (and thus Doctor), and a
// false PASS would tell an operator hooks are live when they are not. Any
// read error, parse error, or type mismatch (e.g. a quoted "true" instead of
// the boolean literal) decodes to the zero value / an error, both of which
// this treats as not enabled — never enabled.
func codexHooksFlagEnabled(home string) bool {
	var cfg struct {
		Features struct {
			Hooks      bool `toml:"hooks"`
			CodexHooks bool `toml:"codex_hooks"`
		} `toml:"features"`
	}
	if _, err := toml.DecodeFile(codexConfigPath(home), &cfg); err != nil {
		return false
	}
	return cfg.Features.Hooks || cfg.Features.CodexHooks
}
