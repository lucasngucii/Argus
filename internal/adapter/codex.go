package adapter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/lucasngucii/argus/internal/hook"
)

// codexParse decodes Codex's PreToolUse stdin JSON. Codex's shell-tool
// payload (tool_name "Bash") is a verified snake_case superset of the
// normalized hook.Payload shape, so this delegates straight to hook.Parse.
func codexParse(r io.Reader) (hook.Payload, error) {
	return hook.Parse(r)
}

// codexEmit writes Codex's PreToolUse response. Codex is deny-only: allow is an
// empty object {} + exit 0 (Codex ignores any allow payload). Deny writes the
// hookSpecificOutput JSON for a structured reason AND returns exit 2 — exit 2 is
// what actually blocks the tool, so a deny stays fail-closed even if Codex ever
// rejects/ignores the JSON body. "ask" must never reach here (Shape collapsed
// it); anything not "allow" is treated as deny (defense in depth). A write
// failure fails closed via exit 2. Deny JSON is written INLINE (not via
// verdict.Emit) so Codex is not coupled to the Claude-scoped encoder.
func codexEmit(w io.Writer, o Outcome) int {
	if o.Verdict == "allow" {
		if _, err := io.WriteString(w, "{}\n"); err != nil {
			fmt.Fprintf(os.Stderr, "argus: gate: emit allow: %v\n", err)
			return 2
		}
		return 0
	}
	body := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": "argus: " + o.Reason,
	}}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: emit deny: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "argus: deny: %s\n", o.Reason) // exit-2 reason channel
	return 2
}
