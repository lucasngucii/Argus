package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/lucasngucii/argus/internal/classify"
	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/shellast"
	"github.com/lucasngucii/argus/internal/verdict"
)

// Explain dry-runs a single command through the same parse -> classify ->
// map pipeline Gate uses, and prints why it classifies the way it does: the
// resolved AST facts (commands, pipe sinks, obfuscation), the firing rule,
// the severity, and the mapped verdict. It never touches the store or
// stdin/stdout beyond w, so it is safe to call outside a real hook
// invocation. It always returns 0 — there is no failure mode short of a
// classifier panic, which is Classify's contract not to have (CLAUDE.md §1).
func Explain(command, tool, cwd, mode string, pol policy.Policy, w io.Writer) int {
	payload := hook.Payload{
		ToolName:       tool,
		CWD:            cwd,
		PermissionMode: mode,
		ToolInput:      hook.ToolInput{Command: command},
	}

	facts := shellast.Extract(payload.Subject())
	decision := classify.Classify(payload, pol)
	mapped := verdict.Map(decision.Severity, mode)

	fmt.Fprintf(w, "command: %s\n", command)
	fmt.Fprintf(w, "commands: %s\n", formatCommands(facts.Commands))
	fmt.Fprintf(w, "pipe sinks: %s\n", formatList(facts.PipeSinks))
	fmt.Fprintf(w, "obfuscated: %t\n", facts.Obfuscated)
	fmt.Fprintf(w, "rule: %s\n", decision.RuleID)
	fmt.Fprintf(w, "severity: %s\n", decision.Severity)
	fmt.Fprintf(w, "reason: %s\n", decision.Reason)
	fmt.Fprintf(w, "verdict: %s\n", mapped)

	return 0
}

// formatCommands renders the resolved AST commands as `name arg1 arg2`
// entries, comma-separated, so a reader sees the same argv the classifier
// judged.
func formatCommands(cmds []shellast.Cmd) string {
	if len(cmds) == 0 {
		return "(none)"
	}
	parts := make([]string, len(cmds))
	for i, c := range cmds {
		parts[i] = strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
	}
	return strings.Join(parts, ", ")
}

// formatList renders a string slice for display, or "(none)" when empty.
func formatList(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
