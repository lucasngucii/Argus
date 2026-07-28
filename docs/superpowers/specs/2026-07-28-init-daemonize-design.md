# Design: `argus init --help` + auto-daemonize serve

Date: 2026-07-28
Status: approved-for-implementation (autonomous — no reviewer in loop)

## Problem

`argus init` today only sets up `~/.argus` and wires the PreToolUse hook, then
exits. The user must separately run `argus serve` (foreground, blocking) to get
the control-plane UI. Two gaps:

1. `argus init` (and the CLI generally) has **no `--help`/flag handling** — it
   ignores argv beyond `init`.
2. There is no "start it and forget it" path. The user wants `init` to leave a
   background server running, like `docker run -d`.

## Goals

- `argus init --help` / `argus init -h` prints what init does + its flags.
- `argus init` **by default** runs setup, then spawns `argus serve` **detached**
  (background, survives terminal close), then returns.
- Idempotent: if a live server is already recorded, do **not** start a second.
- `--no-serve` opts out of the auto-start; `--addr` overrides the bind address
  (default `127.0.0.1:4600`, matching `argus serve`).
- `argus serve --status` / `--stop` to observe and stop the background process.

## Non-goals (YAGNI)

- No separate `internal/daemon` package (~40 lines, belongs to the CLI's dirty
  shell).
- No auto-restart, port health-probe, or log rotation. v1 liveness is a PID
  check only. Known limitation: **PID alive ≠ port bound** — a process that
  died between bind and the check window is not distinguished; acceptable for v1.
- No Windows runtime support — only keep the cross-compile build from breaking.

## Mechanism: daemonize in pure Go (CGO_ENABLED=0)

Go's stdlib has no `daemon()`. We **re-exec the binary**:

1. `os.Executable()` → `exec.Command(exe, "serve", "--addr", addr)`.
2. `SysProcAttr{Setsid: true}` detaches the child from the controlling terminal
   / session (unix).
3. Redirect child stdout+stderr → `~/.argus/serve.log` (append, 0o600).
4. `cmd.Start()` — **never `Wait`**. Parent returns; child lives on.

The detached child is an ordinary foreground `argus serve`. `serve` never
re-execs, so there is **no spawn loop**.

## PID file ownership

The **serving process** owns the PID file, not the spawner:

- `cli.Serve` writes `~/.argus/argus.pid = os.Getpid()` after a successful bind,
  and removes it on return (best-effort; documented).
- `StartServeDaemon` only *reads* the PID and checks liveness (`Signal(0)`) to
  decide whether to skip. This reflects the true serving PID even when the user
  runs `argus serve` directly.

## File layout (one file, one job)

| File | Responsibility |
|---|---|
| `internal/cli/daemon.go` | `StartServeDaemon(home, addr string, w io.Writer) error` — liveness-check, open log, spawn detached, report the URL/pid it launched. |
| `internal/cli/daemon_unix.go` (`//go:build unix`) | `detachAttr() *syscall.SysProcAttr` = `{Setsid:true}`; `processAlive(pid int) bool` via `Signal(0)`. |
| `internal/cli/daemon_other.go` (`//go:build !unix`) | Stubs returning a "background serve unsupported on this platform" error; keeps CGO=0 cross-compile matrix building. |
| `internal/cli/pidfile.go` | `writePID(home)`, `readPID(home)`, `removePID(home)`. |
| `internal/cli/serve.go` | `Serve` writes/removes the PID file around the bound lifetime; add `ServeStatus(home, w) int` and `ServeStop(home, w) int`. |
| `cmd/argus/main.go` | `runInit(argv)` with a `flag.FlagSet` (`--no-serve`, `--addr`) and a rich `fs.Usage` for `--help`; `runServe` grows `--status`/`--stop`. |

`cli.Init(home) error` stays as-is (filesystem/hook setup). The auto-serve step
is a **separate** call in `runInit` after `Init` succeeds — setup and process
spawning are distinct jobs.

## Architecture invariants (CLAUDE.md)

- **1 — Pure core, dirty shell:** `classify()` is untouched. All new code is in
  `internal/cli` (dirty shell). ✓
- **5 — Self-protection stays high:** `argus.pid` and `serve.log` live under
  `~/.argus/`, which the classifier already protects (any path containing
  `.argus/` scores high — see `selfprotect_test.go`). A new golden case locks
  `~/.argus/argus.pid`. ✓
- Invariants 2–4 (fail-closed hot path, log/db failures don't change verdict,
  `high` floor) are not touched — no `gate`/`classify` change.

## CLI behavior

```
argus init                 # setup + spawn detached serve on 127.0.0.1:4600
argus init --addr :4700    # setup + spawn on the given addr
argus init --no-serve      # setup only (old behavior)
argus init --help          # describe init + flags, no side effects
argus serve                # foreground (unchanged), now also writes the pid file
argus serve --status       # "running (pid N) on ADDR" | "not running"
argus serve --stop         # SIGTERM the recorded pid, or "not running"
```

On auto-start, init prints e.g.:
`argus: serving in background (pid 1234), logs at ~/.argus/serve.log`
On already-running: `argus: serve already running (pid 1234)`.

## Testing (TDD, table-driven, deterministic)

- `pidfile_test.go`: write→read→remove round-trip; read of a missing file.
- `daemon_test.go`:
  - double-start is skipped when the recorded PID is alive (use the current test
    process's own PID as a guaranteed-alive stand-in);
  - a stale/dead PID leads to a spawn;
  - `--no-serve` never spawns.
  - Unit tests inject the spawn target (a harmless echo-like exe) so no real
    server is left running; **one** integration test spawns a real `argus serve`
    and stops it via `ServeStop`.
- `serve_test.go`: `Serve` creates the pid file after bind and removes it on
  clean shutdown; `ServeStatus`/`ServeStop` against a running instance.
- `init_test.go`: `--help` output contains the flag names and the "background"
  wording; `--no-serve` performs setup without a pid file appearing.
- `selfprotect_test.go`: golden case — `Write ~/.argus/argus.pid` classifies
  high.

## Commit plan (conventional, one logical change each)

1. `feat(cli): argus init --help and init/serve flag parsing`
2. `feat(cli): pid file + detached background serve on init`
3. `feat(cli): argus serve --status/--stop lifecycle`
4. `test(classify): self-protect ~/.argus/argus.pid` (folded into 2 if small)
