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

	// loopBudget bounds how many times a resolved for-loop body may be walked in
	// one Extract, so nested literal loops (whose cost is the product of the list
	// lengths) cannot blow the hot-path budget. When it is exhausted the remaining
	// iterations are not expanded and the loop is flagged obfuscated — fail closed.
	loopBudget int
}

// maxLoopBodyWalks caps total resolved for-loop body walks per Extract. A flat
// literal loop of up to this many items still expands fully (real scripts sit far
// below it); only pathological nesting (20^4 = 160k walks, ~46ms) is truncated.
const maxLoopBodyWalks = 1024

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
	f.loopBudget = maxLoopBodyWalks
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
			text, ok := resolveWord(r.Word, vars)
			if !ok {
				f.Obfuscated = true // e.g. `cat < $(cmd)` — the sub executes
			}
			f.Redirects = append(f.Redirects, text)
		}
		if r.Hdoc != nil {
			if _, ok := resolveWord(r.Hdoc, vars); !ok {
				f.Obfuscated = true // `$(cmd)` in a heredoc body executes
			}
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
	case *syntax.IfClause:
		// Both branches and the condition run; walk the elif/else chain.
		for cur := c; cur != nil; cur = cur.Else {
			for _, s := range cur.Cond {
				processStmt(s, vars, f)
			}
			for _, s := range cur.Then {
				processStmt(s, vars, f)
			}
		}
	case *syntax.WhileClause:
		for _, s := range c.Cond {
			processStmt(s, vars, f)
		}
		for _, s := range c.Do {
			processStmt(s, vars, f)
		}
	case *syntax.ForClause:
		processForLoop(c, vars, f)
	case *syntax.CaseClause:
		// The subject word and every pattern undergo expansion (including a
		// command substitution that executes) before matching; resolve them.
		if _, ok := resolveWord(c.Word, vars); !ok {
			f.Obfuscated = true
		}
		for _, item := range c.Items {
			for _, pat := range item.Patterns {
				if _, ok := resolveWord(pat, vars); !ok {
					f.Obfuscated = true
				}
			}
			for _, s := range item.Stmts {
				processStmt(s, vars, f)
			}
		}
	case *syntax.FuncDecl:
		// Defining a function with a dangerous body escalates even before it is
		// called — a gate cannot know a later call won't happen (spec: accepted).
		processStmt(c.Body, vars, f)
	case *syntax.TimeClause:
		processStmt(c.Stmt, vars, f)
	case *syntax.CoprocClause:
		processStmt(c.Stmt, vars, f)
	case *syntax.ArithmCmd, *syntax.LetClause, *syntax.TestClause:
		// No nested *Stmt to recurse, but a command substitution inside the
		// expression executes. Scan the rendered source (see hasCmdSubst); pass
		// the whole stmt so the full construct is rendered.
		if hasCmdSubst(stmt) {
			f.Obfuscated = true
		}
	}
}

// processForLoop walks a `for` loop, binding its variable so the body is seen
// with real values. When the in-list resolves to literals, it binds the loop
// variable to each value and walks the body per value — so a body that uses the
// variable (`head "$f"`) resolves instead of reading as an unresolved evasion
// signal, and a concrete dangerous target (`rm -rf /`) surfaces for the floor.
// When any list word is unresolved (a command substitution or unknown
// expansion), the loop's values are unknown: it flags obfuscation and walks the
// body once with the variable UNBOUND, so a body reference stays fail-closed. A
// C-style `for ((;;))` carries no value list — its body is walked once and its
// header is scanned for a command substitution that would execute. The prior
// binding of the variable's name is saved and restored so a same-named variable
// outside the loop is unaffected. Total resolved body walks are capped
// (maxLoopBodyWalks) so nested literal loops cannot blow the hot-path budget.
func processForLoop(c *syntax.ForClause, vars map[string]string, f *Facts) {
	wi, ok := c.Loop.(*syntax.WordIter)
	if !ok || wi.Name == nil {
		// C-style `for ((init; cond; post))` (or an unnamed iterator): no value
		// list to bind. A command substitution in the header executes, so scan the
		// rendered loop for one (see hasCmdSubst) and fail closed if present — the
		// body's own substitutions surface independently when we walk c.Do.
		if hasCmdSubst(c) {
			f.Obfuscated = true
		}
		for _, s := range c.Do {
			processStmt(s, vars, f)
		}
		return
	}

	name := wi.Name.Value
	values := make([]string, 0, len(wi.Items))
	allResolved := true
	for _, w := range wi.Items {
		v, ok := resolveWord(w, vars)
		if !ok {
			f.Obfuscated = true
			allResolved = false
		}
		values = append(values, v)
	}

	saved, had := vars[name]
	defer func() {
		if had {
			vars[name] = saved
		} else {
			delete(vars, name)
		}
	}()

	if allResolved && len(values) > 0 {
		for _, v := range values {
			if f.loopBudget <= 0 {
				// Body-walk budget exhausted (deeply nested literal loops): stop
				// expanding and flag obfuscation so the untested remainder escalates
				// rather than being silently dropped.
				f.Obfuscated = true
				return
			}
			f.loopBudget--
			vars[name] = v
			for _, s := range c.Do {
				processStmt(s, vars, f)
			}
		}
		return
	}
	// Unresolved (or empty) list: the values are unknown, so walk the body once
	// with the variable unbound — any reference to it stays unresolved and the
	// loop is already flagged obfuscated above.
	delete(vars, name)
	for _, s := range c.Do {
		processStmt(s, vars, f)
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

// emitInner surfaces the command wrapped by a prefix wrapper as its own Cmd(s).
// A wrapper's option grammar varies (`sudo -u root cmd`, `timeout 5 cmd`,
// `nice -n 10 cmd`), so guessing the single inner word is unsafe: picking the
// option value (`root`/`5`) instead of the real command would hide a dangerous
// verb and clear obfuscation. Instead we emit EVERY non-flag, non-NAME=VALUE
// token as a candidate command — each with the tokens after it as its args, so a
// target scorer still sees `rm`'s `/`. Over-emitting a harmless phantom (`5`) is
// the fail-safe direction; under-emitting the real `rm` is the dangerous one.
// One level: a wrapped wrapper is not re-unwrapped (the brief's scope).
func emitInner(rest []*syntax.Word, vars map[string]string, f *Facts) {
	emitted := false
	for j, w := range rest {
		text, ok := resolveWord(w, vars)
		if ok && (strings.HasPrefix(text, "-") || assignToken.MatchString(text)) {
			continue // an option flag or NAME=VALUE assignment, not a command
		}
		appendCmd(text, ok, rest[j+1:], vars, f)
		emitted = true
	}
	if !emitted {
		// No plausible inner command surfaced — fail closed.
		f.Obfuscated = true
	}
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

// hasCmdSubst reports whether a node's source text carries a command
// substitution (`$(...)` or backticks). Used for arithmetic/test/let
// constructs whose expression trees (ArithmExpr/TestExpr) are not a flat word
// list: rendering the node back to source and substring-scanning is coarse but
// fail-closed — a `$(...)` inside `(( … ))` / `[[ … ]]` / `let …` executes when
// the shell evaluates it, so it must flag obfuscation. A render error fails
// closed (treated as containing one).
func hasCmdSubst(node syntax.Node) bool {
	var b strings.Builder
	if err := syntax.NewPrinter().Print(&b, node); err != nil {
		return true
	}
	s := b.String()
	return strings.Contains(s, "$(") || strings.Contains(s, "`")
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
