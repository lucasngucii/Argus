// Package hook parses the JSON payload Claude Code sends on stdin for a
// PreToolUse hook invocation.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
)

// ToolInput holds the tool-specific arguments Claude Code passes for the
// invoked tool. Only the fields Argus classifies on are captured.
type ToolInput struct {
	Command  string `json:"command"`
	FilePath string `json:"file_path"`
}

// Payload is the PreToolUse hook event as sent by Claude Code on stdin.
type Payload struct {
	SessionID      string    `json:"session_id"`
	TranscriptPath string    `json:"transcript_path"`
	CWD            string    `json:"cwd"`
	PermissionMode string    `json:"permission_mode"`
	HookEventName  string    `json:"hook_event_name"`
	ToolName       string    `json:"tool_name"`
	ToolUseID      string    `json:"tool_use_id"`
	ToolInput      ToolInput `json:"tool_input"`
}

// Parse decodes a PreToolUse payload from r.
func Parse(r io.Reader) (Payload, error) {
	var p Payload
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("parse hook payload: %w", err)
	}
	return p, nil
}

// Subject returns the value the classifier judges: the shell command for
// Bash, otherwise the file path.
func (p Payload) Subject() string {
	if p.ToolName == "Bash" {
		return p.ToolInput.Command
	}
	return p.ToolInput.FilePath
}
