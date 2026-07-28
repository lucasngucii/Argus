package classify

import (
	"path"
	"regexp"
	"strings"

	"github.com/lucasngucii/argus/internal/shellast"
)

// systemDirs are top-level directories no project ever legitimately owns;
// removing them (or anything under them) is catastrophic regardless of the
// flags used, so they always score high.
var systemDirs = map[string]bool{
	"/etc": true, "/usr": true, "/bin": true, "/sbin": true, "/var": true,
	"/lib": true, "/opt": true, "/boot": true, "/dev": true, "/proc": true,
	"/sys": true, "/root": true, "/System": true, "/Library": true,
}

// scratchBases are path basenames that mark a target as disposable build
// output rather than source, so it scores low even under `rm -rf`.
var scratchBases = map[string]bool{
	"node_modules": true, "build": true, "dist": true, "coverage": true,
}

// bareHomeDir matches a home directory with no subpath (`/Users/alice`,
// `/home/bob`) — deleting an entire account's home, not a project inside it.
var bareHomeDir = regexp.MustCompile(`^/(Users|home)/[^/]+/?$`)

// severityRank orders rm-target severities so ScoreRmTarget can take the
// worst across every target it inspects.
var severityRank = map[string]int{"low": 0, "medium": 1, "high": 2}

// ScoreRmTarget scores the danger of every `rm` command's targets, including
// an `rm` unwrapped from a prefix wrapper (`sudo`, `timeout`, ...) — shellast
// surfaces that as its own Cmd, so scanning every Cmd named "rm" is enough to
// see it. A command the AST couldn't fully resolve, or a target that resolved
// to empty or was never supplied, can't be proven safe: both score high, the
// floor for anything left unverifiable.
func ScoreRmTarget(f shellast.Facts) string {
	worst := "low"
	for _, c := range f.Commands {
		if c.Name != "rm" {
			continue
		}
		if !c.Resolved {
			return "high"
		}
		targets := nonFlagArgs(c.Args)
		if len(targets) == 0 {
			return "high"
		}
		for _, tgt := range targets {
			sev := scoreRmArg(tgt)
			if severityRank[sev] > severityRank[worst] {
				worst = sev
			}
			if worst == "high" {
				return "high"
			}
		}
	}
	return worst
}

// scoreRmArg classifies a single resolved rm target: high for anything that
// could delete outside a project (root, home, system dirs, `..` traversal,
// or an empty target), low for known-disposable scratch/build output, and
// medium — the default — for an ordinary project-relative path we cannot
// otherwise vouch for.
func scoreRmArg(target string) string {
	if target == "" {
		return "high"
	}
	if hasDotDotSegment(target) {
		return "high"
	}
	if target == "/" || target == "~" || target == "$HOME" {
		return "high"
	}
	if isTopLevelGlob(target) {
		return "high"
	}
	if isSystemPath(target) {
		return "high"
	}
	if bareHomeDir.MatchString(target) {
		return "high"
	}
	if isScratchPath(target) {
		return "low"
	}
	return "medium"
}

// isTopLevelGlob reports whether target is a shell glob at the root or home
// level (`/*`, `~/*`, `$HOME/*`) — it expands to every top-level entry, so
// deleting it is operationally identical to deleting root/home.
func isTopLevelGlob(target string) bool {
	switch target {
	case "/*", "/*/", "~/*", "$HOME/*":
		return true
	}
	return false
}

// hasDotDotSegment reports whether target contains a literal `..` path
// component — parent-directory traversal, which can walk outside any
// scope the caller intended.
func hasDotDotSegment(target string) bool {
	for _, seg := range strings.Split(target, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// isSystemPath reports whether target is, or is nested under, one of
// systemDirs.
func isSystemPath(target string) bool {
	for dir := range systemDirs {
		if target == dir || strings.HasPrefix(target, dir+"/") {
			return true
		}
	}
	return false
}

// isScratchPath reports whether target is disposable: under /tmp, an
// explicitly relative `./...` path, or named after a known build-output
// directory.
func isScratchPath(target string) bool {
	if target == "/tmp" || strings.HasPrefix(target, "/tmp/") {
		return true
	}
	if strings.HasPrefix(target, "./") {
		return true
	}
	return scratchBases[path.Base(target)]
}

// nonFlagArgs is the subset of args that are positional (rm targets) rather
// than option flags.
func nonFlagArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// ScoreGitDanger flags only the git invocations that are irreversibly
// destructive to history or the working tree — a force push, a hard reset,
// or a force clean. Every other git usage, including plain push/reset/clean,
// scores safe: those are the ordinary, recoverable cases.
func ScoreGitDanger(f shellast.Facts) string {
	for _, c := range f.Commands {
		if c.Name != "git" {
			continue
		}
		sub, rest := gitSubcommand(c.Args)
		switch sub {
		case "push":
			if containsAny(rest, []string{"--force", "-f", "--force-with-lease"}) {
				return "medium"
			}
		case "reset":
			if containsAny(rest, []string{"--hard"}) {
				return "medium"
			}
		case "clean":
			if hasForceFlag(rest) {
				return "medium"
			}
		case "checkout":
			// A pathspec checkout (`.` or after `--`) overwrites uncommitted work,
			// which — unlike a reset --hard commit — is not recoverable from the
			// reflog. A branch switch/create carries neither token, so it stays safe.
			if containsAny(rest, []string{".", "--"}) {
				return "medium"
			}
		}
	}
	return "safe"
}

// gitSubcommand returns git's subcommand and the args after it, skipping any
// leading global options (`--no-pager`, `--git-dir=…`, `-c k=v`, `-C dir`, …).
// The scorer used to read args[0] literally, so a single global flag before the
// subcommand hid a force-push/hard-reset entirely. The short options -c/-C and
// the separated long options consume the following token as their value.
func gitSubcommand(args []string) (string, []string) {
	valueFlags := map[string]bool{
		"-c": true, "-C": true, "--git-dir": true, "--work-tree": true,
		"--namespace": true, "--exec-path": true, "--super-prefix": true,
	}
	skip := false
	for i, a := range args {
		if skip {
			skip = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			if valueFlags[a] {
				skip = true // the next token is this flag's value, not the subcommand
			}
			continue
		}
		return a, args[i+1:]
	}
	return "", nil
}

// hasForceFlag reports whether any arg is `--force` or a short-flag cluster
// containing `f` (`-f`, `-fd`, `-xf`, ...) — `git clean`'s force flag.
func hasForceFlag(args []string) bool {
	for _, a := range args {
		if a == "--force" || shortFlagCluster(a)['f'] {
			return true
		}
	}
	return false
}

// Scorers is the registry of built-in procedural scorers a policy rule's
// TargetScorer field names, keyed by the name it references.
var Scorers = map[string]func(shellast.Facts) string{
	"rm_target":  ScoreRmTarget,
	"git_danger": ScoreGitDanger,
}
