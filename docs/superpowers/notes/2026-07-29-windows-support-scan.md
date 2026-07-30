# Windows support — source scan + phased plan (2026-07-29)

Status: **unsupported** as of v0.1.7. macOS + Linux only. Below is a deep source
scan of what breaks on Windows and a phased plan. Not yet brainstormed into a
formal spec — this is the raw finding note.

## Blockers (function / security)

1. **No Windows build/publish.** `scripts/build-dist.sh` matrix + npm
   `optionalDependencies` list only darwin/linux. `npm install` fails on
   Windows even though `npm/argus/bin/argus.js` already has a dead
   `win32`/`argus.exe` branch waiting.
2. **Self-protect regex is `/`-only.** `internal/policy/defaults.go`
   `leadBoundary`/`trailBoundary` + the literal binary path hardcode a
   forward-slash, so a backslash path can evade self-protection — violates
   CLAUDE.md invariant 5. **Fix first.**
3. **All 21 baseline rules are POSIX-verb only** (`sudo`/`dd`/`mkfs`/`rm`/
   `useradd`/`chmod`...). Blind to PowerShell equivalents (`Remove-Item
   -Recurse -Force`, `Stop-Service`, `New-LocalUser`, `Format-Volume`,
   `icacls`/`Set-Acl`).
4. **Hook matcher misses PowerShell.** `wiredMatcher="Bash|Write|Edit|mcp__.*"`
   (init_hook.go) does not cover Claude Code's PowerShell tool → Argus is
   silently off on that path.
5. **Background serve disabled on Windows.** `internal/cli/daemon_other.go`
   (`!unix`): `daemonSupported=false`, `processAlive` always returns false,
   `terminate` uses os.Interrupt. Regresses the v0.1.7 auto-daemonize init UX.

## Non-blocking

6. `pathHasSegment` (classify.go) splits path on `/` only — Windows `cwd`
   context-escalation may not match. Verify the real `cwd` shape first.
7. `os.Executable()` + re-exec: works in principle, untested alongside #5.
8. `terminate`/`processAlive` off-unix are stubs, not real Windows-API impls.

## Fine as-is
- `modernc.org/sqlite` (pure Go), `net/http`, `store.go`, `version.go`.
- `mvdan/sh` parser — only breaks under PowerShell tool; Git Bash sends the
  same bash syntax as macOS/Linux.
- Unix file-mode bits — ignored on Windows, no error (weaker ACL protection).

## Key architecture finding

Windows has TWO exec paths in Claude Code:
- **Git Bash** (default with Git for Windows) — bash syntax, tool_name "Bash".
  Engine works nearly as-is.
- **PowerShell tool** (opt-in preview since v2.1.84) — Argus fully blind, both
  matcher and rule corpus.

This split defines the phasing.

## Plan

### Phase 0 — build + self-protection (do first)
- Add `windows amd64`/`windows arm64` to build-dist.sh (keep CGO_ENABLED=0).
- Add `@agrus/argus-win32-x64`/`-win32-arm64` to package.json + set-versions.mjs.
- Fix self-protect separators to `[/\\]`; golden tests for backslash paths.
- Split `pathHasSegment` on both `/` and `\`.

### Phase 1 — Git-Bash path (MVP, ~2-3 days)
- Real Windows `processAlive`/`terminate`/`detachAttr` via
  `golang.org/x/sys/windows` (OpenProcess/TerminateProcess) or `taskkill` via
  exec — no CGO. `x/sys` dep needs the CLAUDE.md one-line justification.
- `detachAttr`: `CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`; re-enable
  `daemonSupported=true` on windows build tag.
- Verify on a REAL Windows VM (not by reading code): init hook wiring under
  `%USERPROFILE%\.claude\settings.json`, background serve start/stop/status,
  pidfile, and the actual `cwd` payload shape Git Bash sends (`/c/...` vs
  `C:\...`) — that decides whether scorers/system-dirs need Windows paths.
- Doctor: daemon-aware message on Windows.

### Phase 2 — PowerShell-native (separate spec, larger)
- Add PowerShell tool_name to the matcher.
- Parallel rule corpus mapping each POSIX baseline → PowerShell equivalent.
- A small PowerShell tokenizer (do NOT reuse mvdan/sh). YAGNI-gate: the
  PowerShell tool is still preview — may not be worth it yet.

## Testing
- New golden cases per changed rule (CLAUDE.md: every rule has a golden case).
- CI: add `GOOS=windows` build to catch compile breaks (no Windows host needed
  for build). Runtime behavior MUST be tested on a real Windows host/VM.

Effort: Phase 0+1 is the core; Phase 2 is a separate project.
