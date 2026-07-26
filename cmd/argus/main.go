// Command argus is the Claude Code permission gate CLI.
package main

import (
	"fmt"
	"os"

	"github.com/lucasngucii/argus/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	// gate|init|doctor|test|explain|stats wired in later tasks
	case "version", "--version", "-v":
		fmt.Println("argus", version.String())
	default:
		usage()
		os.Exit(2)
	}
}

func usage() { fmt.Fprintln(os.Stderr, "usage: argus <gate|init|doctor|test|explain|stats|version>") }
