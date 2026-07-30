// Package hook parses the JSON payload Claude Code sends on stdin for a
// PreToolUse hook invocation.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ToolInput holds the tool-specific arguments Claude Code passes for the
// invoked tool. Only the fields Argus classifies on are captured.
type ToolInput struct {
	Command  string          `json:"command"`
	FilePath string          `json:"file_path"`
	Raw      json.RawMessage `json:"-"`
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

const mcpPrefix = "mcp__"

// SplitMCP parses an MCP tool_name (mcp__<server>__<tool>) into server and tool.
// The plugin form mcp__plugin_<p>_<server>__<tool> yields server="plugin_<p>_<server>".
func SplitMCP(name string) (server, tool string, ok bool) {
	rest, ok := strings.CutPrefix(name, mcpPrefix)
	if !ok {
		return "", "", false
	}
	server, tool, _ = strings.Cut(rest, "__")
	return server, tool, true
}

func (p Payload) IsMCP() bool       { return strings.HasPrefix(p.ToolName, mcpPrefix) }
func (p Payload) MCPServer() string { s, _, _ := SplitMCP(p.ToolName); return s }
func (p Payload) MCPTool() string   { _, t, _ := SplitMCP(p.ToolName); return t }

// Parse decodes a PreToolUse payload from r.
func Parse(r io.Reader) (Payload, error) {
	var p Payload
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("parse hook payload: %w", err)
	}
	return p, nil
}

// UnmarshalJSON captures the raw tool_input so the classifier can inspect MCP
// arguments, while keeping the Bash/Write path fail-closed: a wrong-typed
// command/file_path on a NON-MCP tool is a malformed payload and errors (→ the
// gate denies). MCP tool_input is arbitrary server JSON, so a non-string
// command/file_path there is tolerated — Raw carries the args.
func (p *Payload) UnmarshalJSON(b []byte) error {
	type alias Payload // no UnmarshalJSON → no recursion
	var a struct {
		alias
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return fmt.Errorf("parse hook payload: %w", err)
	}
	*p = Payload(a.alias)
	p.ToolInput.Raw = append(json.RawMessage(nil), a.ToolInput...)
	var typed struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(a.ToolInput, &typed); err != nil {
		if !strings.HasPrefix(p.ToolName, mcpPrefix) {
			return fmt.Errorf("parse tool_input: %w", err) // Bash/Write malformed → fail-closed
		}
		return nil // MCP: tolerate; Raw carries the args
	}
	p.ToolInput.Command, p.ToolInput.FilePath = typed.Command, typed.FilePath
	return nil
}

// Subject returns the value the classifier judges: the shell command when
// one is present, otherwise the file path. Judging on Command's presence
// (rather than an exact "Bash" tool_name match) keeps this fail-closed: a
// missing or mis-cased tool_name must not hide a real command behind an
// empty subject.
func (p Payload) Subject() string {
	switch {
	case p.IsMCP():
		return string(p.ToolInput.Raw)
	case p.ToolInput.Command != "":
		return p.ToolInput.Command
	default:
		return p.ToolInput.FilePath
	}
}
