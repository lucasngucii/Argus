package classify

import (
	"testing"

	"github.com/lucasngucii/argus/internal/shellast"
)

func TestIsReadOnlyChain(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"single listing", "ls /x", true},
		{"stat", "stat /x", true},
		{"multi listing", "ls /x && stat /y", true},
		{"listing pipe listing", "ls /x", true},
		{"content read", "cat /x", false},
		{"grep", "grep foo /x", false},
		{"write verb", "rm -rf /x", false},
		{"mixed chain", "ls /x && rm -rf /x", false},
		{"redirect", "ls /x > /y", false},
		{"pipe to writer", "ls /x | tee /y", false},
		{"obfuscated", "ls $(evil) /x", false},
		{"empty commands", "X=$(rm -rf /x)", false},
		{"find is not a listing verb", "find /x -delete", false},
		{"sort is not a listing verb", "sort -o /y /x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isReadOnlyChain(shellast.Extract(tc.cmd)); got != tc.want {
				t.Fatalf("%q: isReadOnlyChain = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestIsReadOnlyChainConditionNegatives(t *testing.T) {
	// One negative per fail-closed condition, constructed as Facts directly so
	// each condition is isolated.
	ls := shellast.Cmd{Name: "ls", Resolved: true}
	base := shellast.Facts{ParseOK: true, Commands: []shellast.Cmd{ls}}
	if !isReadOnlyChain(base) {
		t.Fatal("baseline clean listing must be read-only")
	}
	parseFail := base
	parseFail.ParseOK = false
	if isReadOnlyChain(parseFail) {
		t.Fatal("!ParseOK must not be read-only")
	}
	obf := base
	obf.Obfuscated = true
	if isReadOnlyChain(obf) {
		t.Fatal("Obfuscated must not be read-only")
	}
	empty := shellast.Facts{ParseOK: true}
	if isReadOnlyChain(empty) {
		t.Fatal("empty Commands must not be read-only")
	}
	redir := base
	redir.Redirects = []string{"/y"}
	if isReadOnlyChain(redir) {
		t.Fatal("a redirect must not be read-only")
	}
	unresolved := shellast.Facts{ParseOK: true, Commands: []shellast.Cmd{{Name: "ls", Resolved: false}}}
	if isReadOnlyChain(unresolved) {
		t.Fatal("an unresolved command must not be read-only")
	}
	nonListing := shellast.Facts{ParseOK: true, Commands: []shellast.Cmd{{Name: "cat", Resolved: true}}}
	if isReadOnlyChain(nonListing) {
		t.Fatal("a non-listing command must not be read-only")
	}
	sink := shellast.Facts{ParseOK: true, Commands: []shellast.Cmd{ls}, PipeSinks: []string{"tee"}}
	if isReadOnlyChain(sink) {
		t.Fatal("a non-listing pipe sink must not be read-only")
	}
}

func TestIsSelfProtectOrCredential(t *testing.T) {
	for _, id := range []string{"self-protect-claude-settings", "self-protect-argus", "credential-system-write"} {
		if !isSelfProtectOrCredential(id) {
			t.Fatalf("%q must be recognized", id)
		}
	}
	for _, id := range []string{"rm-catastrophic", "disk-format", "sudo", ""} {
		if isSelfProtectOrCredential(id) {
			t.Fatalf("%q must NOT be recognized", id)
		}
	}
}
