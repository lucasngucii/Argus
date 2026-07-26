// Package shellast turns a shell command string into structured, security-relevant
// facts using a real shell AST (mvdan.cc/sh) rather than regex. Regex loses to
// evasion — $IFS splitting, variable indirection, prefix wrappers, decoder pipes —
// so the whole trust story of the gate rests on seeing the true argv here.
package shellast

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Cmd is one resolved simple command. Resolved is false when the name or any
// argument could not be pinned to a literal (an unresolved variable, a command
// substitution, or a mixed literal/expansion word) — the caller must treat an
// unresolved command as suspicious, never as clean.
type Cmd struct {
	Name     string
	Args     []string
	Resolved bool
}

// Facts is the structured view of a command that the classifier consumes.
// Obfuscated flags any evasion signal (mixed-part words, unresolved expansions,
// eval, decoder-into-shell pipes, or a parse failure). On a parse failure ParseOK
// is false and RawTokens holds a whitespace split so the gate can still fail closed.
type Facts struct {
	Commands   []Cmd
	PipeSinks  []string
	Redirects  []string
	RawTokens  []string
	Obfuscated bool
	ParseOK    bool
}

// wrappers are commands that run another command passed as their arguments. The
// wrapped command must surface as its own Cmd so `sudo rm -rf /` cannot hide `rm`.
var wrappers = map[string]bool{
	"sudo": true, "env": true, "doas": true, "nohup": true,
	"nice": true, "time": true, "timeout": true, "xargs": true,
}

// decoders emit bytes that a downstream shell would execute; decoder|shell is a
// classic payload-smuggling pattern and is always obfuscation.
var decoders = map[string]bool{
	"base64": true, "base32": true, "xxd": true, "openssl": true, "uudecode": true,
}

// shells are interpreters that execute piped-in bytes as code.
var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
}

var assignToken = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// Extract never errors: any failure is folded into Facts as a fail-closed signal.
func Extract(command string) Facts {
	var f Facts
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		// Parse failure: we cannot see argv, so fail closed. RawTokens lets the
		// caller still substring-scan for dangerous verbs.
		f.ParseOK = false
		f.Obfuscated = true
		f.RawTokens = strings.Fields(command)
		return f
	}
	f.ParseOK = true
	vars := map[string]string{}
	for _, stmt := range file.Stmts {
		processStmt(stmt, vars, &f)
	}
	return f
}

// processStmt records redirects then dispatches on the command shape, threading
// vars in source order so assignments seen earlier resolve later expansions.
func processStmt(stmt *syntax.Stmt, vars map[string]string, f *Facts) {
	if stmt == nil {
		return
	}
	for _, r := range stmt.Redirs {
		if r.Word != nil {
			text, _ := resolveWord(r.Word, vars)
			f.Redirects = append(f.Redirects, text)
		}
	}
	switch c := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		processCall(c, vars, f)
	case *syntax.BinaryCmd:
		processStmt(c.X, vars, f)
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			if name := leadingName(c.Y, vars); name != "" {
				f.PipeSinks = append(f.PipeSinks, name)
			}
			if decoderIntoShell(pipelineNames(stmt, vars)) {
				f.Obfuscated = true
			}
		}
		processStmt(c.Y, vars, f)
	case *syntax.Block:
		for _, s := range c.Stmts {
			processStmt(s, vars, f)
		}
	case *syntax.Subshell:
		for _, s := range c.Stmts {
			processStmt(s, vars, f)
		}
	}
}

// processCall records assignments, emits the command as a Cmd, and — when the
// command is a wrapper — surfaces the wrapped command as its own Cmd.
func processCall(c *syntax.CallExpr, vars map[string]string, f *Facts) {
	for _, a := range c.Assigns {
		if a.Name == nil {
			continue
		}
		val := ""
		if a.Value != nil {
			val, _ = resolveWord(a.Value, vars)
		}
		vars[a.Name.Value] = val
	}
	if len(c.Args) == 0 {
		return // pure assignment, e.g. `X=rm`
	}
	name, resolved := resolveWord(c.Args[0], vars)
	appendCmd(name, resolved, c.Args[1:], vars, f)
	if resolved && wrappers[name] {
		emitInner(c.Args[1:], vars, f)
	}
}

// appendCmd builds and records a Cmd from a resolved name and its argument words,
// flagging obfuscation whenever any part fails to resolve or the name is eval.
func appendCmd(name string, nameResolved bool, argWords []*syntax.Word, vars map[string]string, f *Facts) {
	if !nameResolved {
		f.Obfuscated = true
	}
	cmd := Cmd{Name: name, Resolved: nameResolved}
	for _, w := range argWords {
		text, ok := resolveWord(w, vars)
		if !ok {
			f.Obfuscated = true
			cmd.Resolved = false
		}
		cmd.Args = append(cmd.Args, text)
	}
	f.Commands = append(f.Commands, cmd)
	if name == "eval" {
		f.Obfuscated = true
	}
}

// emitInner surfaces the command wrapped by a prefix wrapper as its own Cmd,
// skipping the wrapper's leading option flags and NAME=VALUE tokens. One level:
// a wrapped wrapper is not re-unwrapped (the brief's scope).
func emitInner(rest []*syntax.Word, vars map[string]string, f *Facts) {
	i := 0
	for i < len(rest) {
		text, ok := resolveWord(rest[i], vars)
		if ok && (strings.HasPrefix(text, "-") || assignToken.MatchString(text)) {
			i++
			continue
		}
		break
	}
	if i >= len(rest) {
		return
	}
	name, resolved := resolveWord(rest[i], vars)
	appendCmd(name, resolved, rest[i+1:], vars, f)
}

// resolveWord returns the literal text of a word and whether it resolved fully.
// It concatenates literal and resolvable-variable parts, but any unresolved
// expansion (unknown $VAR, command substitution, or a mixed word carrying one)
// yields resolved=false so the caller never mistakes a partial join for the truth.
func resolveWord(w *syntax.Word, vars map[string]string) (string, bool) {
	if w == nil {
		return "", true
	}
	return resolveParts(w.Parts, vars)
}

func resolveParts(parts []syntax.WordPart, vars map[string]string) (string, bool) {
	var b strings.Builder
	resolved := true
	for _, p := range parts {
		switch pp := p.(type) {
		case *syntax.Lit:
			b.WriteString(pp.Value)
		case *syntax.SglQuoted:
			b.WriteString(pp.Value)
		case *syntax.DblQuoted:
			text, ok := resolveParts(pp.Parts, vars)
			b.WriteString(text)
			if !ok {
				resolved = false
			}
		case *syntax.ParamExp:
			if pp.Param != nil {
				if v, ok := vars[pp.Param.Value]; ok {
					b.WriteString(v)
					continue
				}
			}
			resolved = false
		default:
			// CmdSubst, ArithmExp, ProcSubst, ExtGlob — not statically resolvable.
			resolved = false
		}
	}
	return b.String(), resolved
}

// leadingName is the resolved name of the first simple command in a statement,
// used to label pipe sinks. It never mutates Facts.
func leadingName(stmt *syntax.Stmt, vars map[string]string) string {
	if stmt == nil {
		return ""
	}
	switch c := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) == 0 {
			return ""
		}
		text, _ := resolveWord(c.Args[0], vars)
		return text
	case *syntax.BinaryCmd:
		return leadingName(c.X, vars)
	}
	return ""
}

// pipelineNames returns the leading command name of every stage in a pipe chain,
// in left-to-right order, so decoder-into-shell ordering can be detected.
func pipelineNames(stmt *syntax.Stmt, vars map[string]string) []string {
	if stmt == nil {
		return nil
	}
	if c, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && (c.Op == syntax.Pipe || c.Op == syntax.PipeAll) {
		return append(pipelineNames(c.X, vars), pipelineNames(c.Y, vars)...)
	}
	return []string{leadingName(stmt, vars)}
}

// decoderIntoShell reports whether a decoder stage is followed by a shell stage.
func decoderIntoShell(names []string) bool {
	seenDecoder := false
	for _, n := range names {
		if decoders[n] {
			seenDecoder = true
		}
		if seenDecoder && shells[n] {
			return true
		}
	}
	return false
}

// hasCmd reports whether any extracted command has the given name — a convenience
// query used by the classifier and tests.
func hasCmd(f Facts, name string) bool {
	for _, c := range f.Commands {
		if c.Name == name {
			return true
		}
	}
	return false
}
