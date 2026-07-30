package classify

import "github.com/lucasngucii/argus/internal/shellast"

// listingVerbs are the commands that reveal only names/metadata (never file
// content) and have no output-flag, in-place, delete, or exec mode in ANY
// argument form — audited against GNU and BSD/macOS variants. This set is
// closed and load-bearing: adding a verb with any write/content/exec mode would
// let that operation masquerade as a listing and suppress a self-protect or
// credential floor. Deliberately excluded: content readers (cat/grep/head/…),
// find (-delete/-exec), sort/uniq/tree (output flag/positional), xxd/rg/less
// (write or exec), and git (repo-local config can exec with no argv signal).
var listingVerbs = map[string]bool{
	"ls": true, "stat": true, "du": true, "realpath": true,
	"basename": true, "dirname": true, "readlink": true,
}

// isReadOnlyChain reports whether f is a pure metadata-listing chain: every
// command lists names/metadata and none reads content, writes, or executes.
// Fail-closed — any parse failure, obfuscation, empty command list, redirect,
// or non-listing command/pipe-sink returns false. The universal quantifier over
// Commands plus the non-empty guard is the security core: a mixed chain
// (`ls x && rm -rf x`) fails on the write verb, and an empty-command shell
// (`X=$(rm …)`) fails the non-empty guard. Depends on shellast surfacing every
// executed command (including inside if/for/while/case/…); without that this
// quantifier would be unsound.
func isReadOnlyChain(f shellast.Facts) bool {
	if !f.ParseOK || f.Obfuscated || len(f.Commands) == 0 || len(f.Redirects) != 0 {
		return false
	}
	for _, c := range f.Commands {
		if !c.Resolved || !listingVerbs[c.Name] {
			return false
		}
	}
	// Every pipe RHS also surfaces as a Command (so the loop above already
	// covers it); this is cheap fail-closed defense-in-depth.
	for _, s := range f.PipeSinks {
		if !listingVerbs[s] {
			return false
		}
	}
	return true
}

// isSelfProtectOrCredential reports whether ruleID is one of the three built-in
// floor rules whose protected paths are non-secret enough that a pure metadata
// listing is not a violation. Keyed by ID (only these three need it — no
// policy.Match field, per YAGNI). INVARIANT: these rules' regexes in
// internal/policy/defaults.go must never be broadened to cover secret file
// CONTENT — a listing reveals no content, so the exemption stays safe only
// while listingVerbs stays metadata-only. See the doc comments on those rules.
func isSelfProtectOrCredential(ruleID string) bool {
	switch ruleID {
	case "self-protect-claude-settings", "self-protect-argus", "credential-system-write":
		return true
	}
	return false
}
