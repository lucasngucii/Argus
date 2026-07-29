package cli

import (
	"flag"
	"fmt"
	"io"
)

// RunInit is the `argus init` command: it parses flags, sets up ~/.argus and
// the PreToolUse hook (Init), then — unless --no-serve — starts the control
// plane as a detached background process (the docker -d model). It returns a
// process exit code so main stays a thin dispatcher.
func RunInit(argv []string, home string, w io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(w)
	noServe := fs.Bool("no-serve", false, "set up ~/.argus without starting the background server")
	addr := fs.String("addr", "127.0.0.1:4600", "loopback address for the background server")
	fs.Usage = func() { initUsage(w, fs) }

	if err := fs.Parse(argv); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if err := Init(home); err != nil {
		fmt.Fprintf(w, "argus: init: %v\n", err)
		return 1
	}
	fmt.Fprintln(w, "argus: initialized ~/.argus and wired the PreToolUse hook in ~/.claude/settings.json")

	if *noServe {
		fmt.Fprintln(w, "argus: --no-serve set; start it later with `argus serve`")
		return 0
	}

	if err := StartServeDaemon(home, *addr, w); err != nil {
		fmt.Fprintf(w, "argus: init: %v\n", err)
		return 1
	}
	return 0
}

// initUsage documents what init does and its flags — the body of
// `argus init --help`.
func initUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `usage: argus init [flags]

Set up Argus and start guarding this machine.

What it does:
  - creates ~/.argus (seed policy.json + SQLite decision store), leaving an
    existing policy.json untouched so your edits are never overwritten
  - wires the Claude Code PreToolUse hook (argus gate) into
    ~/.claude/settings.json, without disturbing anything already there
  - unless --no-serve, starts the control plane in the background (like
    docker run -d): detached, surviving this terminal, logging to
    ~/.argus/serve.log. An already-running server is left alone. Use --addr
    to bind somewhere other than 127.0.0.1:4600.

Manage the background server with:
  argus serve --status    is it running?
  argus serve --stop      stop it

Flags:
`)
	fs.PrintDefaults()
}
