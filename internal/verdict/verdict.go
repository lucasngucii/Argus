// Package verdict maps a classifier severity and Claude Code permission
// mode to an allow/ask/deny decision, and emits it as the JSON
// hookSpecificOutput a PreToolUse hook must print on stdout.
package verdict

import (
	"encoding/json"
	"io"
)

// interactiveModes are the permission modes where Claude Code reliably
// prompts the user before running a tool. In every other mode a "medium"
// severity command would otherwise pass silently, so it is denied instead.
var interactiveModes = map[string]bool{
	"default": true,
	"plan":    true,
	"":        true,
}

// Map returns the verdict ("allow", "ask", or "deny") for a classifier
// severity under the given permission mode. "high" is always denied and
// "safe"/"low" are always allowed; "medium" is only downgraded to "ask"
// in interactive modes, since non-interactive modes don't reliably prompt.
func Map(severity, permissionMode string) string {
	switch severity {
	case "safe", "low":
		return "allow"
	case "high":
		return "deny"
	case "medium":
		if interactiveModes[permissionMode] {
			return "ask"
		}
		return "deny"
	default:
		return "deny"
	}
}

// hookOutput is the payload Claude Code expects from a PreToolUse hook.
type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
	SuppressOutput           bool   `json:"suppressOutput,omitempty"`
}

// Emit writes the hookSpecificOutput JSON for verdict and reason to w.
// Allowed verdicts also set suppressOutput so a silent allow stays silent.
func Emit(w io.Writer, verdict, reason string) error {
	out := hookOutput{
		HookSpecificOutput: hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       verdict,
			PermissionDecisionReason: "argus: " + reason,
			SuppressOutput:           verdict == "allow",
		},
	}
	return json.NewEncoder(w).Encode(out)
}
