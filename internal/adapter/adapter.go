// Package adapter is the per-harness seam for the parts of the gate that are
// specific to the agent harness Argus is gating: parsing the hook payload and
// emitting the verdict. The pure classifier is harness-independent and lives
// elsewhere; only JSON-in and JSON-out belong here. It imports only hook and
// verdict so it stays a cycle-free leaf.
package adapter

import (
	"fmt"
	"io"

	"github.com/lucasngucii/argus/internal/hook"
)

// Outcome is what an adapter serializes: the verdict Gate decided to emit
// (post-shadow — shadow mode sets Verdict to "allow") and its reason. It
// deliberately carries no payload, so an adapter cannot re-derive or override
// the verdict it was handed (keeps the `high` floor enforced in the pure core).
type Outcome struct {
	Verdict string // "allow" | "ask" | "deny"
	Reason  string
}

// Canonical resolves a --harness flag value to its stored/dispatched identity.
// "" (an old install's bare `argus gate`) and "claude-code" both map to
// "claude-code"; any other value is an unknown harness and errors. Callers use
// the returned string for BOTH dispatch and the store row, so a raw flag string
// is never persisted (a mislabelled row would be filtered out of replay/close-loop).
func Canonical(name string) (string, error) {
	switch name {
	case "", "claude-code":
		return "claude-code", nil
	case "codex":
		return "codex", nil
	default:
		return "", fmt.Errorf("unknown harness %q", name)
	}
}

// Shape translates an Argus verdict ("allow"/"ask"/"deny") into the strongest
// verdict the named harness can actually honor. It may only ever return a
// verdict equal to or MORE restrictive than its input (allow < ask < deny),
// never looser. Claude Code honors all three (identity); a deny-only harness
// collapses "ask" to "deny", because emitting an "ask" the harness ignores
// would let a medium command run unprompted (a silent allow). Gate applies
// Shape BEFORE recording and emitting, so the stored verdict is the one the
// harness enforced.
func Shape(name, verdict string) string {
	switch name {
	case "claude-code":
		return verdict
	case "codex":
		if verdict == "allow" {
			return "allow"
		}
		return "deny"
	default:
		// The safe floor for anything a harness may not honor is deny; only a
		// plain "allow" passes through unchanged.
		if verdict == "allow" {
			return "allow"
		}
		return "deny"
	}
}

// registeredHarnesses is the list Shape's cross-adapter test iterates, so a new
// adapter cannot opt out of the more-restrictive-only assertion. Keep it in
// sync with Canonical. A future adapter also adds Canonical/Parse/Emit/Shape
// cases here and cli.Wire/Probe cases.
func registeredHarnesses() []string { return []string{"claude-code", "codex"} }

// Parse turns a harness's raw PreToolUse payload into the normalized
// hook.Payload the classifier consumes. Unknown name → fail-closed error.
func Parse(name string, r io.Reader) (hook.Payload, error) {
	switch name {
	case "claude-code":
		return claudecodeParse(r)
	case "codex":
		return codexParse(r)
	default:
		return hook.Payload{}, fmt.Errorf("parse: unknown harness %q", name)
	}
}

// Emit serializes o for the harness and returns the process exit code: 0 on a
// successful write, 2 when the write fails or the harness is unknown. Fail-closed
// via exit code 2 is the only portable "do not proceed" signal when we cannot
// write (or cannot speak) the harness's protocol — an unknown harness must not
// emit some other harness's format, which that harness would ignore while the
// tool runs. An adapter may only translate a verdict more-restrictive (allow →
// ask → deny), never looser.
func Emit(name string, w io.Writer, o Outcome) int {
	switch name {
	case "claude-code":
		return claudecodeEmit(w, o)
	case "codex":
		return codexEmit(w, o)
	default:
		return 2
	}
}
