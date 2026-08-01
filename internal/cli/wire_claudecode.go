package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// gateCommand is the shell command Claude Code's PreToolUse hook runs.
// `argus` is expected on PATH after install; wireHook and Doctor both
// recognize an existing entry by looking for this substring so a user's own
// wrapper around the same binary still counts as "already wired".
const gateCommand = "argus gate"

// gateWireCommand is what fresh wiring writes: the match constant plus the
// explicit harness flag. It MUST contain gateCommand as a substring so
// gateEntry/doctor recognize it and stay idempotent.
const gateWireCommand = gateCommand + " --harness=claude-code"

// wiredMatcher is the PreToolUse matcher wired by fresh init. It gates Bash,
// Write, and Edit commands, plus MCP tools (mcp__*).
const wiredMatcher = "Bash|Write|Edit|mcp__.*"

// wireHook idempotently adds a PreToolUse hook that runs argus gate to
// ~/.claude/settings.json, without disturbing anything else already there.
// It decodes the file into a generic map so keys and hook entries Argus
// doesn't know about (other events, other tools' matchers) round-trip
// byte-for-byte; the only mutation is an append to hooks.PreToolUse, and
// only when no existing entry there already runs argus gate.
func wireHook(home string) error {
	path := settingsPath(home)
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

	if e := gateEntry(preToolUse); e != nil {
		// Self-heal a stale matcher (an install from before MCP gating) by
		// APPENDING mcp coverage — never clobber a user's customized matcher.
		if m, _ := e["matcher"].(string); !strings.Contains(m, "mcp__") {
			if m == "" {
				e["matcher"] = wiredMatcher
			} else {
				e["matcher"] = m + "|mcp__.*"
			}
			return claudeWriteSettings(path, settings)
		}
		return nil
	}

	hooks["PreToolUse"] = append(preToolUse, map[string]any{
		"matcher": wiredMatcher,
		"hooks": []any{
			map[string]any{"type": "command", "command": gateWireCommand},
		},
	})
	return claudeWriteSettings(path, settings)
}

// settingsPath returns ~/.claude/settings.json under home.
func settingsPath(home string) string {
	return filepath.Join(home, ".claude", "settings.json")
}

// claudeReadSettings decodes an existing settings.json, or returns a fresh
// empty document if none exists yet.
func claudeReadSettings(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("init: read settings.json: %w", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(b, &settings); err != nil {
		return nil, fmt.Errorf("init: parse settings.json: %w", err)
	}
	return settings, nil
}

// claudeWriteSettings marshals settings and writes them to path.
func claudeWriteSettings(path string, settings map[string]any) error {
	b, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("init: marshal settings.json: %w", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("init: write settings.json: %w", err)
	}
	return nil
}

// matchedGateHook scans PreToolUse once for the entry whose inner hook runs
// the argus gate command, returning both that outer entry and the matched
// command string together — so callers needing either or both never rescan
// the same hook list twice with the same predicate. Returns (nil, "") if none
// exists.
func matchedGateHook(preToolUse []any) (entry map[string]any, command string) {
	for _, e := range preToolUse {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, gateCommand) {
				return m, cmd
			}
		}
	}
	return nil, ""
}

// gateEntry returns the PreToolUse entry map whose inner hook runs the argus
// gate command, or nil if none exists.
func gateEntry(preToolUse []any) map[string]any {
	entry, _ := matchedGateHook(preToolUse)
	return entry
}

// hasGateHook reports whether any PreToolUse entry already runs the argus
// gate command. This is the idempotency check that keeps a repeat Init (or
// Doctor's verification) from either duplicating the entry or missing one a
// user hand-edited.
func hasGateHook(preToolUse []any) bool { return gateEntry(preToolUse) != nil }
