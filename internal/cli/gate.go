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
// hook: parse -> classify -> best-effort record -> emit. In the normal
// case blocking happens via the emitted JSON's permissionDecision, not the
// process exit code, so Gate returns 0. It returns 2 only when the stdout
// emit itself fails (broken pipe / closed fd): with no hookSpecificOutput
// on stdout, Claude Code would treat that as "no opinion" and run the tool
// unprompted in bypassPermissions, so a failed emit must fail-closed via
// the exit code instead (see emitOrBlock). A top-level recover fail-closes
// to "deny" so a bug anywhere in this path can never silently allow a
// dangerous command (CLAUDE.md §2).
func Gate(stdin io.Reader, stdout io.Writer, home string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "argus: gate: recovered panic: %v\n", r)
			if !emitOrBlock(stdout, "deny", "internal error (fail-closed)") {
				code = 2
				return
			}
			code = 0
		}
	}()

	payload, err := hook.Parse(stdin)
	if err != nil {
		// Unparseable payload is itself an anomaly, not a benign no-op.
		fmt.Fprintf(os.Stderr, "argus: gate: parse payload: %v\n", err)
		if !emitOrBlock(stdout, "deny", "unparseable payload") {
			return 2
		}
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

	if !emitOrBlock(stdout, emitted, decision.Reason) {
		return 2
	}
	return 0
}

// emitOrBlock writes v/reason to stdout via verdict.Emit and reports whether
// the write succeeded. A failed emit is the one I/O path that can produce an
// effective allow: Claude Code treats a hook with no hookSpecificOutput on
// stdout as "no opinion" and, in bypassPermissions, runs the tool
// unprompted. So the write failing must itself fail-closed — the caller
// returns exit code 2, which the Claude Code hooks contract blocks the tool
// call on (stderr is fed back instead of the now-unwritable stdout JSON),
// in every permission mode including bypass.
func emitOrBlock(stdout io.Writer, v, reason string) bool {
	if err := verdict.Emit(stdout, v, reason); err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: emit verdict: %v\n", err)
		return false
	}
	return true
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
