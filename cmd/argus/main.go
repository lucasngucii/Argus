// Command argus is the Claude Code permission gate CLI.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

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
		if err := cli.Init(home); err != nil {
			fmt.Fprintf(os.Stderr, "argus: init: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("argus: initialized ~/.argus and wired the PreToolUse hook in ~/.claude/settings.json")
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
	case "version", "--version", "-v":
		fmt.Println("argus", version.String())
	default:
		usage()
		os.Exit(2)
	}
}

func usage() { fmt.Fprintln(os.Stderr, "usage: argus <gate|init|doctor|test|explain|stats|version>") }
