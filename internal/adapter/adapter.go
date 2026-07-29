// Package adapter is the per-harness seam for the parts of the gate that are
// specific to the agent harness Argus is gating: parsing the hook payload and
// emitting the verdict. The pure classifier is harness-independent and lives
// elsewhere; only JSON-in and JSON-out belong here. It imports only hook and
// verdict so it stays a cycle-free leaf.
package adapter

import "fmt"

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
	default:
		return "", fmt.Errorf("unknown harness %q", name)
	}
}
