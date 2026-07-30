# Changelog

## v0.1.8

### Security fixes

- **Fixed a `tool_name` fail-open**: a missing or mis-cased tool name (e.g. `"bash"` instead of
  `"Bash"`) made a dangerous command's subject resolve empty, classifying it `safe` instead of
  inspecting it. `rm -rf /` is now correctly denied regardless of `tool_name` casing.
- **Fixed a case-insensitive-filesystem bypass** on every self-protect and credential rule
  (`self-protect-claude-settings`, `self-protect-argus`, `credential-system-write`,
  `mcp-read-sensitive-path`, `mcp-fileop-sensitive-path`, `rc-file-inject`): on macOS (APFS) and
  Windows, `~/.claude` and `~/.CLAUDE` name the same directory, but the rules were case-sensitive
  and a single case variation bypassed them entirely.
- **Fixed a false-positive**: writing to Claude Code's own memory/project files
  (`~/.claude/projects/*/memory/*.md`) was incorrectly floored as a self-protect violation. The
  self-protect rule now only fires on the hook-wiring file itself, the whole `.claude` directory
  (or an obfuscated/dot-alias reference to it), or the `projects/` directory as a whole — not on
  ordinary files inside it.
- MCP reads of `/etc/shadow` are now correctly flagged (`mcp-read-sensitive-path`); `/etc/passwd`
  remains deliberately unflagged (not a real secret, a common benign read).

### Internal

- Introduced a harness-adapter seam (`internal/adapter`) so the gate's payload parsing and
  verdict emission are no longer hardcoded to Claude Code — groundwork for future support of
  other agent harnesses (Codex, Gemini). No user-visible change yet: `argus gate` still defaults
  to the Claude Code adapter, and `init`/`doctor` behavior is unchanged for existing installs.
- `doctor` now validates that a hand-edited hook command names a harness Argus actually knows,
  parsed the same way the live gate parses it (shell-tokenized, not a regex guess) — catches a
  misconfigured install that would otherwise silently deny every tool call.

## v0.1.7 and earlier

See [GitHub Releases](https://github.com/lucasngucii/Argus/releases).
