package adapter

import (
	"io"

	"github.com/lucasngucii/argus/internal/hook"
)

// codexParse decodes Codex's PreToolUse stdin JSON. Codex's shell-tool
// payload (tool_name "Bash") is a verified snake_case superset of the
// normalized hook.Payload shape, so this delegates straight to hook.Parse.
func codexParse(r io.Reader) (hook.Payload, error) {
	return hook.Parse(r)
}
