# E2E-discovered hardening fixes (pre-existing, found while testing harness-adapter-seam)

**Date:** 2026-07-30
**Status:** approved
**Context:** 10-agent end-to-end functional testing of `feat/harness-adapter-seam` (running
the real binary, not reading code) surfaced two pre-existing gaps. Neither is caused by the
harness-adapter seam — `internal/hook` and `internal/policy/defaults.go` are untouched by that
branch — but the user chose to fix both before merging, since they touch the pure core.

## Fix 1 — `Payload.Subject()` fail-open on a non-exact `tool_name`

**Found by:** adversarial E2E test feeding `{"tool_input":{"command":"rm -rf /"}}` (missing
`tool_name`) and `{"tool_name":"bash", ...}` (lowercase) through the real gate binary. Both
returned `allow`.

**Root cause** (`internal/hook/payload.go`):
```go
func (p Payload) Subject() string {
	switch {
	case p.ToolName == "Bash":       // exact-match, case-sensitive
		return p.ToolInput.Command
	case p.IsMCP():
		return string(p.ToolInput.Raw)
	default:
		return p.ToolInput.FilePath  // missing/mis-cased tool_name lands here, empty
	}
}
```
An empty subject reaches `classify.Classify` via `shellast.Extract("")`, which produces no
commands, so severity defaults to `safe` — the command text is never inspected. This violates
CLAUDE.md §2 (hot path never fails open on a dangerous verb).

**Fix:** judge on the observable signal that a shell command is present (`ToolInput.Command !=
""`), not on an exact string match of the tool's label:
```go
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
```
No behavior change for legitimate Write/Edit payloads (no `Command` field → still falls to
`FilePath`) or MCP payloads (still routed to `Raw` first). Only changes the missing/mis-cased
`tool_name`-with-a-`Command` case, from empty-subject-allow to actual-command-classified.

**Not exploitable via real Claude Code wiring** — `tool_name` is set by the harness, not the
gated model — but is a genuine fail-open for any other invocation shape (a differently-cased
proxy, a malformed/partial payload that still parses). Fix it anyway per §2's fail-closed
posture.

## Fix 2 — MCP read-sensitive-path rule doesn't cover `/etc/shadow`

**Found by:** E2E test `mcp__filesystem__read_file` on `/etc/passwd` → `allow`.

**Scope decision:** add `/etc/shadow` (real credential material — password hashes) to
`mcp-read-sensitive-path`'s `Raw` pattern. Deliberately **NOT** `/etc/passwd` — it holds only
username/uid mappings, not secrets, and reading it is a common benign operation; flagging it
would lower the ruleset's signal-to-noise for no real security benefit. This keeps the existing
"only flag genuinely sensitive targets" philosophy (CLAUDE.md's roadmap note: policy
completeness is ongoing, hardened deliberately over time, not via blanket pattern-matching).

**Fix** (`internal/policy/defaults.go`, `mcp-read-sensitive-path`'s `Raw` field): append
`` `|/etc/shadow\b` `` alongside the existing `` `|/etc/sudoers\b` `` alternative.

## Testing
- Fix 1: a `hook` package test asserting `Subject()` returns the command for `ToolName: ""` and
  `ToolName: "bash"` (lowercase) when `Command` is set, and unchanged behavior for Write/Edit
  (file_path, no command) and MCP. A `classify`/`gate`-level regression asserting `rm -rf /`
  with a missing/mis-cased `tool_name` now denies.
- Fix 2: a golden case for `mcp-read-sensitive-path` matching `/etc/shadow` via a read-verb MCP
  tool, and a negative case confirming `/etc/passwd` still does NOT match (locks in the
  deliberate scope decision so it isn't "fixed" again by accident later).

Both fixes land on `feat/harness-adapter-seam` (same branch, since the user chose to block the
merge on them) as their own commits, TDD, full suite green before merge.
