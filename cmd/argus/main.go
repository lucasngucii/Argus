// Command argus is the Claude Code permission gate CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/lucasngucii/argus/internal/cli"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
	"github.com/lucasngucii/argus/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gate":
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "argus: user home dir: %v\n", err)
		}
		os.Exit(cli.Gate(os.Stdin, os.Stdout, home))
	case "init":
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "argus: user home dir: %v\n", err)
			os.Exit(1)
		}
		os.Exit(cli.RunInit(os.Args[2:], home, os.Stdout))
	case "doctor":
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "argus: user home dir: %v\n", err)
			os.Exit(1)
		}
		os.Exit(cli.Doctor(home, os.Stdout))
	case "test":
		paths := os.Args[2:]
		if len(paths) == 0 {
			fmt.Fprintln(os.Stderr, "usage: argus test <corpus.jsonl> [corpus.jsonl ...]")
			os.Exit(2)
		}
		os.Exit(cli.RunHarness(paths, policy.Default(), os.Stdout))
	case "explain":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: argus explain <command>")
			os.Exit(2)
		}
		command := os.Args[2]
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "argus: cwd: %v\n", err)
			os.Exit(1)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "argus: user home dir: %v\n", err)
			os.Exit(1)
		}
		pol, err := policy.Load(home + "/.argus/policy.json")
		if err != nil {
			pol = policy.Default()
		}
		os.Exit(cli.Explain(command, "Bash", cwd, "default", pol, os.Stdout))
	case "stats":
		fs := flag.NewFlagSet("stats", flag.ExitOnError)
		jsonl := fs.Bool("jsonl", false, "stream every decision as one JSON object per line")
		fs.Parse(os.Args[2:])
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "argus: user home dir: %v\n", err)
			os.Exit(1)
		}
		st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "argus: stats: open store: %v\n", err)
			os.Exit(1)
		}
		os.Exit(cli.Stats(st, os.Stdout, *jsonl))
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "replay":
		os.Exit(runReplay(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("argus", version.String())
	default:
		usage()
		os.Exit(2)
	}
}

// runServe wires `argus serve`: it runs the loopback control-plane until the
// process receives SIGINT/SIGTERM, at which point signal.NotifyContext cancels
// the context and cli.Serve shuts down gracefully and closes the store.
func runServe(argv []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:4600", "loopback address to bind")
	status := fs.Bool("status", false, "report whether a background server is running, then exit")
	stopFlag := fs.Bool("stop", false, "stop the background server, then exit")
	fs.Parse(argv)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: user home dir: %v\n", err)
		return 1
	}
	switch {
	case *status:
		return cli.ServeStatus(home, os.Stdout)
	case *stopFlag:
		return cli.ServeStop(home, os.Stdout)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cli.Serve(ctx, home, *addr, os.Stdout)
}

// runReplay resolves the candidate policy (a file via --policy, default
// ~/.argus/policy.json, or a recorded snapshot via --version N) and re-scores
// the logged history against it. --version reads the exact JSON that was
// active for that version so a replay lines up with real decisions'
// policy_version; the file path is the "what would this edit do" case.
func runReplay(argv []string) int {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	policyPath := fs.String("policy", "", "candidate policy file (default ~/.argus/policy.json)")
	ver := fs.Int("version", 0, "re-score against recorded policy version N instead of a file")
	fs.Parse(argv)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: user home dir: %v\n", err)
		return 1
	}
	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: replay: open store: %v\n", err)
		return 1
	}
	defer st.Close()

	candidate, err := replayCandidate(st, home, *policyPath, *ver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "argus: replay: %v\n", err)
		return 1
	}
	return cli.Replay(st, candidate, os.Stdout)
}

// replayCandidate returns the policy to re-score against: a recorded snapshot
// when ver > 0 (validated then decoded so a corrupt snapshot fails loudly), or
// the policy file otherwise (path, or ~/.argus/policy.json by default).
func replayCandidate(st *store.Store, home, policyPath string, ver int) (policy.Policy, error) {
	if ver > 0 {
		raw, err := st.PolicyVersionJSON(ver)
		if err != nil {
			return policy.Policy{}, fmt.Errorf("policy version %d: %w", ver, err)
		}
		return policy.EffectiveFromBytes([]byte(raw)) // validates + normalizes + assembles
	}
	if policyPath == "" {
		policyPath = filepath.Join(home, ".argus", "policy.json")
	}
	return policy.Load(policyPath)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: argus <gate|init|doctor|test|explain|stats|serve|replay|version>")
}
