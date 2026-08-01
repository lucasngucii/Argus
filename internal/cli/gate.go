// Package cli implements Argus's command-line subcommands.
package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lucasngucii/argus/internal/adapter"
	"github.com/lucasngucii/argus/internal/classify"
	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
	"github.com/lucasngucii/argus/internal/verdict"
)

// Gate is the synchronous PreToolUse hot path. It resolves the harness, parses,
// classifies, best-effort records, and emits through the per-harness adapter.
// Every terminal path funnels an explicit Outcome into a SINGLE adapter.Emit
// call; the deferred recover is the only other Emit caller and assigns its exit
// code to the named return. A top-level recover fail-closes to deny so a bug on
// this path can never silently allow a dangerous command (CLAUDE.md §2).
func Gate(stdin io.Reader, stdout io.Writer, home, harness string) (code int) {
	var name string // captured by the recover closure; "" → Emit default → exit 2
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "argus: gate: recovered panic: %v\n", r)
			code = adapter.Emit(name, stdout, adapter.Outcome{Verdict: "deny", Reason: "internal error (fail-closed)"})
		}
	}()

	name, err := adapter.Canonical(harness)
	if err != nil {
		// Unknown harness: we cannot speak its protocol, so emit nothing and
		// fail closed via a non-zero exit — the only portable "do not proceed".
		fmt.Fprintf(os.Stderr, "argus: gate: %v\n", err)
		return 2
	}

	return adapter.Emit(name, stdout, decide(stdin, home, name))
}

// decide runs the parse -> classify -> record pipeline and returns the Outcome
// to emit. A parse failure funnels an explicit deny (never a zero-value
// Outcome, which would serialize an empty verdict Claude Code treats as
// no-opinion). Shadow mode records the real verdict but emits allow.
func decide(stdin io.Reader, home, name string) adapter.Outcome {
	payload, err := adapter.Parse(name, stdin)
	if err != nil {
		// Unparseable payload is itself an anomaly, not a benign no-op.
		fmt.Fprintf(os.Stderr, "argus: gate: parse payload: %v\n", err)
		return adapter.Outcome{Verdict: "deny", Reason: "unparseable payload"}
	}

	pol, err := policy.Load(home + "/.argus/policy.json")
	if err != nil {
		// Fail-closed to a working ruleset (the built-in default plus the
		// floor the classifier always applies), not to no rules at all.
		fmt.Fprintf(os.Stderr, "argus: gate: load policy: %v (falling back to default)\n", err)
		pol = policy.Default()
	}

	decision := classify.Classify(payload, pol)
	mapped := verdict.Map(decision.Severity, payload.PermissionMode)
	// Collapse the verdict to what THIS harness can actually honor (a deny-only
	// harness turns "ask" into "deny"). Applied before record + emit so the
	// stored row reflects the verdict the harness enforced. Correctness of a
	// deny-only harness rides on this line — see adapter.Shape.
	mapped = adapter.Shape(name, mapped)

	if decision.Severity != "safe" {
		recordDecision(home, payload, pol, decision, mapped, name)
	}

	// Shadow mode observes without blocking: the DB keeps the real verdict
	// (mapped, above), but stdout always reports allow.
	if pol.Defaults.Shadow {
		return adapter.Outcome{Verdict: "allow", Reason: decision.Reason}
	}
	return adapter.Outcome{Verdict: mapped, Reason: decision.Reason}
}

// recordDecision persists a non-safe decision. It is best-effort: store
// errors are logged to stderr and otherwise ignored, and the whole call is
// wrapped in its own recover — a logging bug must never reach the caller or
// change the verdict already computed in Gate (CLAUDE.md §3).
func recordDecision(home string, p hook.Payload, pol policy.Policy, d classify.Decision, mappedVerdict, harness string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "argus: gate: recovered panic recording decision: %v\n", r)
		}
	}()

	st, err := store.Open(home + "/.argus/argus.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: open store: %v\n", err)
		return
	}

	row := store.Row{
		TS:             time.Now().UTC().Format(time.RFC3339),
		Session:        p.SessionID,
		CWD:            p.CWD,
		Tool:           p.ToolName,
		Command:        p.ToolInput.Command,
		File:           p.ToolInput.FilePath,
		Severity:       d.Severity,
		Verdict:        mappedVerdict,
		PermissionMode: p.PermissionMode,
		RuleID:         d.RuleID,
		Harness:        harness,
		PolicyVersion:  pol.Version,
		Obfuscation:    d.Obfuscated,
	}
	if p.IsMCP() {
		row.Command = p.Subject()
	}
	if err := st.Insert(row); err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: insert decision: %v\n", err)
	}
}
