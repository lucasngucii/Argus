// Command argus is the Claude Code permission gate CLI.
package main

import (
	"fmt"
	"os"

	"github.com/lucasngucii/argus/internal/cli"
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
	// test|explain|stats wired in later tasks
	case "version", "--version", "-v":
		fmt.Println("argus", version.String())
	default:
		usage()
		os.Exit(2)
	}
}

func usage() { fmt.Fprintln(os.Stderr, "usage: argus <gate|init|doctor|test|explain|stats|version>") }
