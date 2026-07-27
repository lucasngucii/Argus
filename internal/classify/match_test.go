package classify

import (
	"testing"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/shellast"
)

func m(tool, subj string, mt policy.Match) bool {
	ok, _ := Matches(tool, subj, shellast.Extract(subj), policy.Rule{Tool: []string{tool}, Match: mt})
	return ok
}

func TestMatchCmdIncludesUnwrapped(t *testing.T) {
	if !m("Bash", "sudo rm -rf /", policy.Match{Cmd: []string{"rm"}, Flags: []string{"r"}}) {
		t.Fatal("must see rm inside sudo")
	}
}

func TestFlagIgnoresLongOptions(t *testing.T) {
	if m("Bash", "curl --retry x", policy.Match{Cmd: []string{"curl"}, Flags: []string{"r"}}) {
		t.Fatal("--retry must not satisfy flag r")
	}
}

func TestArgsContainAnyOf(t *testing.T) {
	if !m("Bash", "docker service ls", policy.Match{Cmd: []string{"docker"}, ArgsContain: []string{"service", "down"}}) {
		t.Fatal("any-of")
	}
}

func TestBadRegexReportsError(t *testing.T) {
	_, rerr := Matches("Bash", "x", shellast.Extract("x"), policy.Rule{Tool: []string{"Bash"}, Match: policy.Match{ArgMatches: "("}})
	if !rerr {
		t.Fatal("invalid regex must report regexErr, not panic")
	}
}

func TestToolScoping(t *testing.T) {
	if m("Write", "rm", policy.Match{Cmd: []string{"rm"}}) {
		t.Fatal("Bash-only must not match Write")
	}
}
