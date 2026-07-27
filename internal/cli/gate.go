// Package cli implements Argus's command-line subcommands.
package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lucasngucii/argus/internal/classify"
	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
	"github.com/lucasngucii/argus/internal/verdict"
)

// Gate is the synchronous hot path Claude Code invokes as a PreToolUse
// hook: parse -> classify -> best-effort record -> emit. It always returns
// 0 — blocking happens via the emitted JSON's permissionDecision, not the
// process exit code — and a top-level recover fail-closes to "deny" so a
// bug anywhere in this path can never silently allow a dangerous command
// (CLAUDE.md §2).
func Gate(stdin io.Reader, stdout io.Writer, home string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "argus: gate: recovered panic: %v\n", r)
			_ = verdict.Emit(stdout, "deny", "internal error (fail-closed)")
			code = 0
		}
	}()

	payload, err := hook.Parse(stdin)
	if err != nil {
		// Unparseable payload is itself an anomaly, not a benign no-op.
		fmt.Fprintf(os.Stderr, "argus: gate: parse payload: %v\n", err)
		_ = verdict.Emit(stdout, "deny", "unparseable payload")
		return 0
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

	if decision.Severity != "safe" {
		recordDecision(home, payload, pol, decision, mapped)
	}

	// Shadow mode observes without blocking: the DB keeps the real verdict
	// (mapped, above), but stdout always reports allow.
	emitted := mapped
	if pol.Defaults.Shadow {
		emitted = "allow"
	}

	_ = verdict.Emit(stdout, emitted, decision.Reason)
	return 0
}

// recordDecision persists a non-safe decision. It is best-effort: store
// errors are logged to stderr and otherwise ignored, and the whole call is
// wrapped in its own recover — a logging bug must never reach the caller or
// change the verdict already computed in Gate (CLAUDE.md §3).
func recordDecision(home string, p hook.Payload, pol policy.Policy, d classify.Decision, mappedVerdict string) {
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
		Harness:        "claude-code",
		PolicyVersion:  pol.Version,
		Obfuscation:    d.Obfuscated,
	}
	if err := st.Insert(row); err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: insert decision: %v\n", err)
	}
}
