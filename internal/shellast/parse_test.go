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
