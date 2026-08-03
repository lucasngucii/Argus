// Package shellast turns a shell command string into structured, security-relevant
// facts using a real shell AST (mvdan.cc/sh) rather than regex. Regex loses to
// evasion — $IFS splitting, variable indirection, prefix wrappers, decoder pipes —
// so the whole trust story of the gate rests on seeing the true argv here.
package shellast

import (
	"regexp"
	"strconv"
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
	// Other common "run this other command" prefixes — each execs its argument
	// command, so the wrapped verb (and a piped-in shell) must surface through it.
	"command": true, "setsid": true, "stdbuf": true, "ionice": true,
	"chrt": true, "taskset": true, "flock": true, "nsenter": true,
	"unbuffer": true, "caffeinate": true,
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
	if shellReadsRedirectedCode(stmt, vars) {
		// `bash <<< "rm -rf /"` / `sh <<EOF … EOF` — a shell executing code read
		// from a here-string/here-doc is argv-invisible smuggling, like decoder|sh.
		f.Obfuscated = true
	}
	switch c := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		processCall(c, vars, f)
	case *syntax.BinaryCmd:
		processStmt(c.X, vars, f)
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			f.PipeSinks = append(f.PipeSinks, sinkNames(c.Y, vars)...)
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
// header is scanned for a command substitution that would execute. The body is
// walked in a copy of the variable scope so neither the loop variable nor any
// other assignment the body makes leaks into later resolution (a loop may run
// zero times). Total resolved body walks are capped (maxLoopBodyWalks) so nested
// literal loops cannot blow the hot-path budget.
func processForLoop(c *syntax.ForClause, vars map[string]string, f *Facts) {
	// Walk the body in a CHILD scope (a copy of vars). A loop may run zero times,
	// so any assignment its body makes is uncertain — letting it leak into the
	// outer scope could rebind a later `$X` to a benign value and mask a real
	// verb (`X=rm; for f in; do X=ls; done; $X -rf /`). The child inherits the
	// outer bindings so the body still resolves outer vars and the loop var.
	child := cloneVars(vars)

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
			processStmt(s, child, f)
		}
		// Iteration count is unknown; assume it runs so a body reassignment is
		// visible to later commands (over-surfacing if it doesn't is fail-safe).
		propagateVars(child, vars)
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
			child[name] = v
			for _, s := range c.Do {
				processStmt(s, child, f)
			}
		}
		// A resolved non-empty list runs at least once, so in a real shell the
		// body's final assignments (and the loop var = last value) persist.
		// Propagate them so a later `$X` sees what the loop actually left, not a
		// stale pre-loop value that could mask a verb (`X=ls; for f in a; do X=rm;
		// done; $X -rf /`). An EMPTY or unresolved list (below) may run zero times,
		// so its body assignments must NOT leak — that stays isolated.
		propagateVars(child, vars)
		return
	}
	// Unresolved (or empty) list: the values are unknown (may run zero times), so
	// walk the body once with the variable unbound and DO NOT propagate — a body
	// reference stays unresolved and the unresolved case is already obfuscated.
	delete(child, name)
	for _, s := range c.Do {
		processStmt(s, child, f)
	}
}

// propagateVars copies a loop body's child scope back into the parent, so an
// assignment a loop that runs makes is visible to later resolution. Only called
// for loops that execute at least once (or a C-style loop, conservatively).
func propagateVars(child, vars map[string]string) {
	for k, v := range child {
		vars[k] = v
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
	return resolvePartsCtx(parts, vars, false)
}

// resolvePartsCtx resolves a word's parts. quoted is true when these parts sit
// inside double quotes, where a backslash is (mostly) literal; in the unquoted
// context a backslash escapes the next character (`.s\sh` → `.ssh`), so it must
// be stripped or an escaped protected path would slip every floor.
func resolvePartsCtx(parts []syntax.WordPart, vars map[string]string, quoted bool) (string, bool) {
	var b strings.Builder
	resolved := true
	for _, p := range parts {
		switch pp := p.(type) {
		case *syntax.Lit:
			if quoted {
				b.WriteString(pp.Value)
			} else {
				b.WriteString(stripUnquotedBackslashes(pp.Value))
			}
		case *syntax.SglQuoted:
			if pp.Dollar {
				// ANSI-C $'...': the shell decodes \xNN, \NNN, \uNNNN, \n, … before
				// use. Emit the DECODED bytes so an escaped verb (`$'\x72\x6d'` = rm)
				// surfaces instead of reading as a benign literal that no rule matches.
				b.WriteString(decodeANSIC(pp.Value))
			} else {
				b.WriteString(pp.Value)
			}
		case *syntax.DblQuoted:
			text, ok := resolvePartsCtx(pp.Parts, vars, true)
			b.WriteString(text)
			if !ok {
				resolved = false
			}
		case *syntax.ParamExp:
			if v, ok := resolveParamExp(pp, vars); ok {
				b.WriteString(v)
				continue
			}
			resolved = false
		default:
			// CmdSubst, ArithmExp, ProcSubst, ExtGlob — not statically resolvable.
			resolved = false
		}
	}
	return b.String(), resolved
}

// stripUnquotedBackslashes removes an unquoted backslash and keeps the next
// character literally, as the shell does (`.s\sh` → `.ssh`, `a\ b` → `a b`). A
// trailing backslash is kept. Without this, a backslash-escaped protected path
// resolves with the backslash still in it and no floor matches.
func stripUnquotedBackslashes(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// resolveParamExp resolves a parameter expansion to its literal value when that
// value is statically knowable. A plain $name/${name} resolves from vars. A
// SELECT-style expansion whose base variable IS known — ${x:-w}/${x:=w}/${x:?}
// (value is the known var) or ${x:+w} (value is the literal word) — also
// resolves, so benign default-value idioms don't read as obfuscation while a
// literal dangerous word stays visible. Every TRANSFORMING form (strip #/%,
// replace /, slice :o:l, case ,,/^^, indirect !, length #, index) stays
// unresolved: it can synthesize a verb from the variable's own bytes, which is
// the evasion this guards. A select form on an UNKNOWN base var also stays
// unresolved — guessing the unset branch could hide an env-provided value.
func resolveParamExp(pp *syntax.ParamExp, vars map[string]string) (string, bool) {
	if pp.Param == nil {
		return "", false
	}
	if isPlainParam(pp) {
		v, ok := vars[pp.Param.Value]
		return v, ok
	}
	// A select-style expansion carries only an Exp op and nothing else.
	if pp.Exp == nil || pp.Excl || pp.Length || pp.Width || pp.IsSet ||
		pp.NestedParam != nil || pp.Index != nil || len(pp.Modifiers) != 0 ||
		pp.Slice != nil || pp.Repl != nil || pp.Names != 0 || pp.Flags != nil {
		return "", false
	}
	val, set := vars[pp.Param.Value]
	if !set {
		return "", false // unknown base var: the branch taken isn't statically known
	}
	switch pp.Exp.Op {
	case syntax.DefaultUnset, syntax.DefaultUnsetOrNull,
		syntax.AssignUnset, syntax.AssignUnsetOrNull,
		syntax.ErrorUnset, syntax.ErrorUnsetOrNull:
		return val, true // base var is set → its value
	case syntax.AlternateUnset, syntax.AlternateUnsetOrNull:
		return resolveWord(pp.Exp.Word, vars) // base var is set → the word
	default:
		return "", false // strip/replace/etc. — can synthesize a verb
	}
}

// isPlainParam reports whether a parameter expansion is a bare $name / ${name}
// with no transforming modifier — the only form whose value is a direct variable
// lookup. Mirrors syntax.ParamExp.simple() (unexported): any indirection, length,
// index, slice, replace, case-mod, or ${...}-expansion means the emitted text
// would differ from the stored value, so the caller must treat it as unresolved.
func isPlainParam(p *syntax.ParamExp) bool {
	return p.Param != nil && p.Flags == nil &&
		!p.Excl && !p.Length && !p.Width && !p.IsSet &&
		p.NestedParam == nil && p.Index == nil &&
		len(p.Modifiers) == 0 && p.Slice == nil &&
		p.Repl == nil && p.Names == 0 && p.Exp == nil
}

// decodeANSIC decodes the escape sequences of a Bash ANSI-C $'...' string the
// same way the shell does, so an escaped command verb is seen as its real bytes.
// An unrecognized `\x` is kept literally (backslash + char), matching bash.
func decodeANSIC(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch e := s[i]; e {
		case 'a':
			b.WriteByte(0x07)
		case 'b':
			b.WriteByte(0x08)
		case 'e', 'E':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte(0x0c)
		case 'n':
			b.WriteByte(0x0a)
		case 'r':
			b.WriteByte(0x0d)
		case 't':
			b.WriteByte(0x09)
		case 'v':
			b.WriteByte(0x0b)
		case '\\', '\'', '"', '?':
			b.WriteByte(e)
		case 'x':
			j := i + 1
			for j < len(s) && j <= i+2 && isHexDigit(s[j]) {
				j++
			}
			if j > i+1 {
				v, _ := strconv.ParseUint(s[i+1:j], 16, 32)
				b.WriteByte(byte(v))
				i = j - 1
			} else {
				b.WriteByte('\\')
				b.WriteByte('x')
			}
		case 'u', 'U':
			width := 4
			if e == 'U' {
				width = 8
			}
			j := i + 1
			for j < len(s) && j <= i+width && isHexDigit(s[j]) {
				j++
			}
			if j > i+1 {
				v, _ := strconv.ParseUint(s[i+1:j], 16, 32)
				b.WriteRune(rune(v))
				i = j - 1
			} else {
				b.WriteByte('\\')
				b.WriteByte(e)
			}
		case 'c':
			if i+1 < len(s) {
				b.WriteByte(s[i+1] & 0x1f)
				i++
			} else {
				b.WriteByte('\\')
				b.WriteByte('c')
			}
		default:
			if e >= '0' && e <= '7' {
				j := i
				for j < len(s) && j <= i+2 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
				v, _ := strconv.ParseUint(s[i:j], 8, 32)
				b.WriteByte(byte(v))
				i = j - 1
			} else {
				// Unrecognized escape: bash keeps the backslash and the char.
				b.WriteByte('\\')
				b.WriteByte(e)
			}
		}
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// cloneVars returns a shallow copy of a variable scope, used to give a loop body
// a child scope whose assignments cannot leak into later resolution.
func cloneVars(vars map[string]string) map[string]string {
	out := make(map[string]string, len(vars))
	for k, v := range vars {
		out[k] = v
	}
	return out
}

// sinkNames returns the command names a single (non-pipe) stage runs: the
// leading command, and — when that command is a prefix wrapper (sudo/env/
// timeout/nice/…) — the ONE command it wraps, unwrapped one level at a time.
// Unlike emitInner (which over-emits every token, fail-safe for SCORING), this
// feeds the AlwaysHigh pipe-to-shell floor, so it must pick the actual wrapped
// interpreter precisely: over-emitting would hard-deny a benign `… | xargs grep
// bash`. The wrapped command is the first argument that is not a flag, a
// NAME=VALUE assignment, or a bare number (a wrapper's duration/nice value), so
// `timeout 5 bash` and `nice -n 10 bash` both resolve to `bash`. It never
// mutates Facts.
func sinkNames(stmt *syntax.Stmt, vars map[string]string) []string {
	if stmt == nil {
		return nil
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil
	}
	name, ok := resolveWord(call.Args[0], vars)
	if !ok {
		return nil
	}
	out := []string{name}
	args := call.Args[1:]
	for wrappers[name] {
		wrapped, rest, found := firstCommandToken(args, vars)
		if !found {
			break
		}
		out = append(out, wrapped)
		name, args = wrapped, rest
	}
	return out
}

// firstCommandToken returns the first argument that reads as the wrapped command
// — skipping option flags, NAME=VALUE assignments, and bare numbers (a wrapper's
// duration/priority value) — with the arguments that follow it. An unresolved
// token stops the scan (the wrapped command can't be pinned).
func firstCommandToken(args []*syntax.Word, vars map[string]string) (string, []*syntax.Word, bool) {
	for j, w := range args {
		text, ok := resolveWord(w, vars)
		if !ok {
			return "", nil, false
		}
		if strings.HasPrefix(text, "-") || assignToken.MatchString(text) || isAllDigits(text) {
			continue
		}
		return text, args[j+1:], true
	}
	return "", nil, false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// pipelineNames returns the command names of every stage in a pipe chain, in
// left-to-right order (wrappers unwrapped), so decoder-into-shell ordering can
// be detected even when a wrapper sits between the decoder and the shell.
func pipelineNames(stmt *syntax.Stmt, vars map[string]string) []string {
	if stmt == nil {
		return nil
	}
	if c, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && (c.Op == syntax.Pipe || c.Op == syntax.PipeAll) {
		return append(pipelineNames(c.X, vars), pipelineNames(c.Y, vars)...)
	}
	return sinkNames(stmt, vars)
}

// shellReadsRedirectedCode reports whether stmt is a shell interpreter reading
// its program from a here-string/here-doc redirect (`bash <<< "…"`, `sh <<EOF`).
// The shell executes that body as code, so it must be treated as obfuscation —
// the equivalent of a decoder piped into a shell, but via a redirect.
func shellReadsRedirectedCode(stmt *syntax.Stmt, vars map[string]string) bool {
	isShell := false
	for _, n := range sinkNames(stmt, vars) { // unwrap wrappers (`timeout 5 bash <<<…`)
		if shells[n] {
			isShell = true
			break
		}
	}
	if !isShell {
		return false
	}
	for _, r := range stmt.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			return true
		}
	}
	return false
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
