package adapter

import (
	"io"

	"github.com/lucasngucii/argus/internal/hook"
)

// claudecodeParse decodes Claude Code's PreToolUse stdin JSON. Claude Code's
// payload IS the normalized shape, so this delegates straight to hook.Parse.
func claudecodeParse(r io.Reader) (hook.Payload, error) {
	return hook.Parse(r)
}
