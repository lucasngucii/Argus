package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/lucasngucii/argus/internal/adapter"
	"github.com/lucasngucii/argus/internal/shellast"
)

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
	case "codex":
		if err := checkCodexHook(home); err != nil {
			return err
		}
		if !codexHooksFlagEnabled(home) {
			return fmt.Errorf("codex [features].hooks (or the deprecated codex_hooks alias) is not confirmed enabled in ~/.codex/config.toml")
		}
		return nil
	default:
		return fmt.Errorf("no probe for harness %q", canon)
	}
}

// checkConfiguredHarness reads the wired command and rejects an unknown
// --harness value. Absent flag ⇒ "" ⇒ claude-code (bare install) ⇒ PASS.
// claude-specific: it reads the Claude settings.json wired by `argus init`.
func checkConfiguredHarness(home string) error {
	settings, err := claudeReadSettings(settingsPath(home))
	if err != nil {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	entry, cmd := matchedGateHook(preToolUse)
	if entry == nil {
		return nil // no gate entry; checkHook already reported that
	}

	configured, err := configuredHarness(cmd)
	if err != nil {
		// The runtime gate would os.Exit(2) on this same malformed flag set
		// and brick every call; doctor must FAIL just as loudly.
		return err
	}
	if _, err := adapter.Canonical(configured); err != nil {
		return fmt.Errorf("hook configures %w", err)
	}
	return nil
}

// configuredHarness extracts the --harness value the wired command actually
// configures at runtime. It tokenizes cmd with the real shell AST (shellast),
// finds the "gate" subcommand token, and parses everything after it with the
// exact same flag.FlagSet cmd/argus/main.go uses — so doctor can never
// disagree with what the live gate will do: both `--harness=x` and
// `--harness x` are accepted, a repeated flag has last-occurrence-wins, and
// shell quoting is already stripped by the tokenizer.
func configuredHarness(cmd string) (string, error) {
	facts := shellast.Extract(cmd)
	for _, c := range facts.Commands {
		for i, a := range c.Args {
			if a != "gate" {
				continue
			}
			fs := flag.NewFlagSet("gate", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			harness := fs.String("harness", "", "")
			if err := fs.Parse(c.Args[i+1:]); err != nil {
				return "", fmt.Errorf("hook command %q: %w", cmd, err)
			}
			return *harness, nil
		}
	}
	// No command surfaced a "gate" subcommand token at all — an exotic
	// wrapper (e.g. `sh -c '...'`) that shellast doesn't descend into. Known
	// residual: rare hand-edit, and the live gate still fails closed on
	// whatever it actually resolves to at runtime; treat as absent here so
	// doctor doesn't false-FAIL a wrapper it can't see into.
	return "", nil
}
