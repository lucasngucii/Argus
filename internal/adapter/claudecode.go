package adapter

import (
	"fmt"
	"io"
	"os"

	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/verdict"
)

// claudecodeParse decodes Claude Code's PreToolUse stdin JSON. Claude Code's
// payload IS the normalized shape, so this delegates straight to hook.Parse.
func claudecodeParse(r io.Reader) (hook.Payload, error) {
	return hook.Parse(r)
}

// claudecodeEmit writes Claude Code's hookSpecificOutput JSON. A failed write
// means Claude Code sees no stdout JSON and, in bypassPermissions, would run the
// tool unprompted — so a write failure fails closed via exit code 2.
func claudecodeEmit(w io.Writer, o Outcome) int {
	// Defense-in-depth choke point: Outcome is supposed to always carry
	// "allow"/"ask"/"deny" (Gate/verdict.Map only ever produce those), but if a
	// bug ever let something else through, serializing it verbatim would emit
	// an empty or unrecognized permissionDecision — which Claude Code treats
	// as no-opinion, i.e. fail-open. Coerce anything out of vocabulary to
	// "deny" here so a future bug upstream cannot silently allow a tool.
	v := o.Verdict
	if v != "allow" && v != "ask" && v != "deny" {
		v = "deny"
	}
	if err := verdict.Emit(w, v, o.Reason); err != nil {
		fmt.Fprintf(os.Stderr, "argus: gate: emit verdict: %v\n", err)
		return 2
	}
	return 0
}
