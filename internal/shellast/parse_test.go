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
