// Package classify tests a shell command's AST facts against policy rules.
package classify

import (
	"regexp"
	"strings"

	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/shellast"
)

// Matches reports whether a single rule fires for a tool invocation, ANDing
// every populated field of r.Match (an empty field is ignored). regexErr is
// true when a policy-authored regex (ArgMatches or Raw) fails to compile —
// the caller must fail closed on that, never silently skip the rule. We use
// regexp.Compile, never MustCompile: a bad policy regex must not panic the
// gate. TargetScorer is not evaluated here (Task 6).
func Matches(tool, subject string, f shellast.Facts, r policy.Rule) (matched bool, regexErr bool) {
	if !toolIn(r.Tool, tool) {
		return false, false
	}

	mt := r.Match
	// Shell-AST facts only mean something for Bash: Subject is the shell
	// command there, but a file path for every other tool (hook.Subject).
	// A rule that uses AST fields cannot fire outside Bash even if its Tool
	// list happens to name that tool.
	matched = !(usesShellFacts(mt) && tool != "Bash")

	cmds := matchedCommands(mt.Cmd, f.Commands)
	if len(mt.Cmd) > 0 && len(cmds) == 0 {
		matched = false
	}
	if len(mt.Flags) > 0 && !hasAllFlags(cmds, mt.Flags) {
		matched = false
	}
	if len(mt.ArgsContain) > 0 && !argsContainAny(cmds, mt.ArgsContain) {
		matched = false
	}
	if mt.ArgMatches != "" {
		re, err := regexp.Compile(mt.ArgMatches)
		if err != nil {
			return false, true
		}
		if !re.MatchString(joinArgs(cmds)) {
			matched = false
		}
	}
	if len(mt.PipesInto) > 0 && !containsAny(f.PipeSinks, mt.PipesInto) {
		matched = false
	}
	if mt.RedirectsTo != "" && !contains(f.Redirects, mt.RedirectsTo) {
		matched = false
	}
	if mt.Raw != "" {
		re, err := regexp.Compile(mt.Raw)
		if err != nil {
			return false, true
		}
		// Match the raw subject AND the resolved-argv view. The path floors
		// (self-protect / credential) express a protected path as a Raw regex, but
		// the shell normalizes away quotes and variables the raw text still shows —
		// `cat ~/."ssh"/id_rsa` and `s=ssh; cat ~/.$s/id_rsa` both resolve to
		// ~/.ssh/id_rsa yet hide `.ssh` from a subject-text match. Matching the
		// resolved command names, args, and redirect targets too closes that
		// bypass; it only ever adds matches (fail-safe), never removes one.
		if !re.MatchString(subject) && !re.MatchString(resolvedSubject(f)) {
			matched = false
		}
	}
	if len(mt.McpServer) > 0 || mt.McpTool != "" {
		server, mtool, isMCP := hook.SplitMCP(tool)
		if !isMCP {
			matched = false
		} else {
			if len(mt.McpServer) > 0 && !contains(mt.McpServer, server) {
				matched = false
			}
			if mt.McpTool != "" {
				re, err := regexp.Compile(mt.McpTool)
				if err != nil {
					return false, true
				}
				if !re.MatchString(mtool) {
					matched = false
				}
			}
		}
	}
	return matched, false
}

// usesShellFacts reports whether mt has any field that only makes sense
// against a shell command's AST (as opposed to Raw, a subject-text escape
// hatch, or TargetScorer, evaluated elsewhere).
func usesShellFacts(mt policy.Match) bool {
	return len(mt.Cmd) > 0 || len(mt.Flags) > 0 || len(mt.ArgsContain) > 0 ||
		mt.ArgMatches != "" || len(mt.PipesInto) > 0 || mt.RedirectsTo != ""
}

// toolIn reports whether tool is present in tools.
func toolIn(tools []string, tool string) bool {
	isMCP := strings.HasPrefix(tool, "mcp__")
	for _, t := range tools {
		if t == tool || (t == "mcp" && isMCP) {
			return true
		}
	}
	return false
}

// matchedCommands is the subset of cmds relevant to the rest of the match:
// every command named in names, or every command when names is empty (no
// Cmd filter was specified, so Flags/ArgsContain/ArgMatches apply broadly).
func matchedCommands(names []string, cmds []shellast.Cmd) []shellast.Cmd {
	if len(names) == 0 {
		return cmds
	}
	var out []shellast.Cmd
	for _, c := range cmds {
		base := commandBasename(c.Name)
		for _, n := range names {
			// Exact name, its basename (so a path-qualified `/bin/rm` or `./argus`
			// matches `rm`/`argus` — a command is that command however it's spelled),
			// or a `<name>.<suffix>` family variant — the Unix convention where
			// `tool.type` is a build of `tool` (mkfs.ext4, mkfs.xfs). A trailing "."
			// only, never "-", so this never conflates distinct binaries like docker
			// vs docker-compose.
			if base == n || strings.HasPrefix(base, n+".") {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// commandBasename strips a leading path from a resolved command name so a
// path-qualified invocation (`/bin/rm`, `./argus`, `dist/argus`) matches the
// same rules as the bare name. A trailing slash (unusual) leaves the name as-is.
func commandBasename(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 && i+1 < len(name) {
		return name[i+1:]
	}
	return name
}

// resolvedSubject is a space-joined view of the resolved command names, args,
// and redirect targets — the true argv the shell would run, with quotes and
// variables already resolved. Raw path-floor regexes match against this in
// addition to the subject text so a quote/variable-obscured protected path
// (`~/."ssh"/id_rsa`) is still caught. Empty for non-Bash tools (no shell AST).
func resolvedSubject(f shellast.Facts) string {
	if len(f.Commands) == 0 && len(f.Redirects) == 0 {
		return ""
	}
	// Separate each command and redirect with " ; ". A path floor scans for a
	// segment and doesn't care, but a structural rule whose regex is anchored to
	// NOT cross a `;`/`|`/`&` (opaque-exec: `bash\s+[^-|;&]+\.sh`) would otherwise
	// falsely match across two flattened statements (`bash ; cat deploy.sh`).
	parts := make([]string, 0, len(f.Commands)+len(f.Redirects))
	for _, c := range f.Commands {
		parts = append(parts, c.Name+" "+strings.Join(c.Args, " "))
	}
	parts = append(parts, f.Redirects...)
	return strings.Join(parts, " ; ")
}

// hasAllFlags reports whether every required flag letter appears among cmds'
// flags. Matching is case-insensitive — a security gate treats `-R` and `-r`
// alike, since tools spell recursion both ways (notably rm/cp) — and the GNU
// long form `--recursive` also credits `r`. Required letters are compared
// lower-cased, so callers pass `"r"`, never `"R"`.
func hasAllFlags(cmds []shellast.Cmd, letters []string) bool {
	present := map[byte]bool{}
	for _, c := range cmds {
		for _, arg := range c.Args {
			for ch := range flagLetters(arg) {
				present[ch] = true
			}
		}
	}
	for _, l := range letters {
		if l == "" || !present[lowerASCII(l[0])] {
			return false
		}
	}
	return true
}

// flagLetters returns the option letters an arg contributes, lower-cased so
// flag matching is case-insensitive. A short cluster (`-rf`, `-Rf`) yields its
// letters; the long option `--recursive` yields `r` — the same recursive flag
// spelled out, which `shortFlagCluster` alone would drop. Anything else yields
// nothing.
func flagLetters(arg string) map[byte]bool {
	if arg == "--recursive" {
		return map[byte]bool{'r': true}
	}
	cluster := shortFlagCluster(arg)
	if len(cluster) == 0 {
		return cluster
	}
	out := make(map[byte]bool, len(cluster))
	for ch := range cluster {
		out[lowerASCII(ch)] = true
	}
	return out
}

// lowerASCII lower-cases an ASCII letter byte; other bytes pass through.
func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// shortFlagCluster returns the set of letters in a single short-flag arg
// (`-rf` -> {r, f}). Anything else — a long option (`--force`), a bare `-`,
// or a non-flag word — yields an empty set.
func shortFlagCluster(arg string) map[byte]bool {
	set := map[byte]bool{}
	if len(arg) < 2 || arg[0] != '-' || arg[1] == '-' {
		return set
	}
	for i := 1; i < len(arg); i++ {
		set[arg[i]] = true
	}
	return set
}

// argsContainAny reports whether any needle equals a resolved arg of cmds
// (ANY-of).
func argsContainAny(cmds []shellast.Cmd, needles []string) bool {
	for _, c := range cmds {
		for _, a := range c.Args {
			for _, n := range needles {
				if a == n {
					return true
				}
			}
		}
	}
	return false
}

// joinArgs concatenates every arg of cmds, space-separated, as the text
// ArgMatches runs its regexp against.
func joinArgs(cmds []shellast.Cmd) string {
	var parts []string
	for _, c := range cmds {
		parts = append(parts, c.Args...)
	}
	return strings.Join(parts, " ")
}

// containsAny reports whether any needle is present in list (ANY-of).
func containsAny(list []string, needles []string) bool {
	for _, v := range list {
		for _, n := range needles {
			if v == n {
				return true
			}
		}
	}
	return false
}

// contains reports whether needle is present in list.
func contains(list []string, needle string) bool {
	for _, v := range list {
		if v == needle {
			return true
		}
	}
	return false
}
