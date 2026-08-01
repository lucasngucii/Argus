package adapter

import "testing"

// rank is the verdict lattice allow < ask < deny. Shape may only move a verdict
// up this lattice (more restrictive), never down.
var rank = map[string]int{"allow": 0, "ask": 1, "deny": 2}

// TestShapeNeverLooser is the cross-adapter guarantee: for every registered
// harness and every verdict, Shape returns a verdict equal to or MORE
// restrictive than its input. A new adapter added to registeredHarnesses is
// covered automatically, so none can opt out of the more-restrictive-only rule.
func TestShapeNeverLooser(t *testing.T) {
	for _, name := range registeredHarnesses() {
		for _, v := range []string{"allow", "ask", "deny"} {
			if got := Shape(name, v); rank[got] < rank[v] {
				t.Errorf("Shape(%q, %q) = %q — LOOSER than input (fail-open)", name, v, got)
			}
		}
	}
}

// TestShapeClaudeIdentity pins that Claude Code, which honors all three
// verdicts, is a pass-through — the refactor must not change its behavior.
func TestShapeClaudeIdentity(t *testing.T) {
	for _, v := range []string{"allow", "ask", "deny"} {
		if got := Shape("claude-code", v); got != v {
			t.Errorf("Shape(claude-code, %q) = %q, want identity", v, got)
		}
	}
}
