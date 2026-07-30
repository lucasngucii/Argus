package classify

import (
	"testing"

	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
)

// TestCannotDisarm asserts an agent cannot lower its own leash: touching the
// Claude Code hook wiring or Argus's own policy/db, from any home directory,
// always classifies high — regardless of what the loaded policy says.
func TestCannotDisarm(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/Users/x/.claude/settings.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -f /home/y/.argus/policy.json"}},
		{ToolName: "Edit", ToolInput: hook.ToolInput{FilePath: "/root/.argus/argus.db"}},
		// The background-serve pid file lives under .argus/, so faking it dead
		// to spawn a rogue server must not be a low-severity write.
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/home/y/.argus/argus.pid"}},
	}
	for _, p := range cases {
		if Classify(p, pol).Severity != "high" {
			t.Fatalf("self-protection breach: %+v", p.ToolInput)
		}
	}
}

// TestCannotDisarmHomeIndependent re-runs the settings.json/policy.json/db
// cases under a second, unrelated home layout (relative path, Windows-style
// drive, container path) to confirm the rules key off path suffix, never an
// absolute home prefix.
func TestCannotDisarmHomeIndependent(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: ".claude/settings.local.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat /var/lib/svc/.argus/policy.json"}},
		{ToolName: "Edit", ToolInput: hook.ToolInput{FilePath: "/opt/agent/.argus/argus.db"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "chmod +x /srv/build/bin/argus"}},
	}
	for _, p := range cases {
		if Classify(p, pol).Severity != "high" {
			t.Fatalf("self-protection breach: %+v", p.ToolInput)
		}
	}
}

// TestCredentialAndSystemWriteAlwaysHigh closes the cross-task gap: the old
// agent-review gate treated credential files and system-config writes as
// high, and the Floor() rewrite lost that. An SSH private key write and a
// shell redirect into /etc/ must both classify high.
func TestCredentialAndSystemWriteAlwaysHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/home/y/.ssh/id_rsa"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/root/.ssh/id_ed25519"}},
		{ToolName: "Edit", ToolInput: hook.ToolInput{FilePath: "/home/y/.ssh/authorized_keys"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat /home/y/.aws/credentials"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "echo x > /etc/hosts"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "echo 'evil ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/etc/sudoers"}},
	}
	for _, p := range cases {
		if Classify(p, pol).Severity != "high" {
			t.Fatalf("credential/system-write breach: %+v", p.ToolInput)
		}
	}
}

// TestCredentialRulesStayFailSafe asserts the credential/system-write floor
// doesn't over-match benign paths that merely mention "aws"/"ssh"/"etc" —
// the fail-safe requirement is over-block real secrets, not any file that
// shares a substring with one.
func TestCredentialRulesStayFailSafe(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/repo/internal/aws/client.go"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "grep aws README.md"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat /etc/hosts"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/repo/docs/ssh-notes.md"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "app/settings.json"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "docs/aws-guide.md"}},
	}
	for _, p := range cases {
		if got := Classify(p, pol).Severity; got == "high" {
			t.Fatalf("false positive: %+v classified high", p.ToolInput)
		}
	}
}

// TestBareDirectoryDeleteIsHigh covers the review-flagged Critical 1: the
// original patterns anchored on a trailing "/" (…/.argus/…), so deleting the
// directory itself — which never has a trailing "/" or further path after
// it — matched nothing and fell through to the generic rm-recursive medium
// rule. `rm -rf ~/.argus` (etc.) must classify high exactly like deleting a
// file inside it.
func TestBareDirectoryDeleteIsHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.argus"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.ssh"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.aws"}},
		// Same gap, relative form: no "~" means no leading "/" either, which
		// (^|/) alone (the pre-fix anchor) also missed.
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf .argus"}},
	}
	for _, p := range cases {
		if got := Classify(p, pol).Severity; got != "high" {
			t.Fatalf("bare directory delete not caught (got %s): %+v", got, p.ToolInput)
		}
	}
}

// TestMetacharAdjacentBinaryDeleteIsHigh covers the review-flagged Critical
// 2: the original bin/argus pattern anchored its trailing boundary on
// whitespace-or-end, so ordinary shell chaining with no space before the
// metacharacter (`rm bin/argus&&echo done`) matched nothing and the whole
// command classified safe.
func TestMetacharAdjacentBinaryDeleteIsHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm bin/argus&&echo done"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -f bin/argus;echo x"}},
	}
	for _, p := range cases {
		if got := Classify(p, pol).Severity; got != "high" {
			t.Fatalf("metachar-adjacent binary delete escaped (got %s): %+v", got, p.ToolInput)
		}
	}
}

// TestClaudeSettingsAndBareDirAlwaysHigh pins the verification table from
// docs/superpowers/specs/2026-07-30-self-protect-claude-scope-fix.md rows 1-6:
// the settings.json path (plain and `./`-obfuscated), the bare .claude dir,
// and its double-slash/dot-alias/parent-traversal variants must all classify
// high via self-protect-claude-settings. The `./`-obfuscated settings.json
// case and the double-slash/dot-alias/parent-traversal bare-dir cases are the
// reopened-gap regressions the fix closes: they must have failed against the
// pre-fix Raw pattern (bareDirBoundary didn't exist; nhánh 1 had no `(\./)*`
// tolerance) and must pass now.
func TestClaudeSettingsAndBareDirAlwaysHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/Users/x/.claude/settings.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat ~/.claude/./././settings.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude//"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude/."}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cp -r ~/.claude/.. /tmp/x"}},
	}
	for _, p := range cases {
		d := Classify(p, pol)
		if d.Severity != "high" {
			t.Fatalf("self-protection breach (got %s): %+v", d.Severity, p.ToolInput)
		}
	}
}

// TestClaudeProjectsWholeDirAlwaysHigh pins verification table rows 7-8: the
// new nhánh 3. `.claude/projects` is now protected as its own whole-directory
// reference (spec design decision 4), same reasoning as bare `.claude`.
func TestClaudeProjectsWholeDirAlwaysHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude/projects"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cp -r ~/.claude/projects /tmp/exfil"}},
	}
	for _, p := range cases {
		d := Classify(p, pol)
		if d.Severity != "high" {
			t.Fatalf("self-protection breach (got %s): %+v", d.Severity, p.ToolInput)
		}
	}
}

// TestClaudeProjectsSubpathNotSelfProtected pins verification table rows 9-10
// — the reported bug and its fix. Narrowing the bare-dir alternative to a
// real whole-directory boundary (bareDirBoundary) means a genuinely distinct
// subpath under .claude/projects (an individual project's memory file, or one
// specific project's directory) is no longer floored by self-protect. This is
// the false positive the spec exists to close: before the fix, the old
// trailBoundary matched `.claude` followed directly by "/", with no further
// look-ahead, so ANY subpath — including these two — was caught and floored
// to high via self-protect-claude-settings.
func TestClaudeProjectsSubpathNotSelfProtected(t *testing.T) {
	pol := policy.Default()

	// A read of an individual project's own memory file must not be floored
	// by self-protect at all — it's an everyday, legitimate operation.
	readCases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat ~/.claude/projects/x/memory/foo.md"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/Users/x/.claude/projects/x/memory/foo.md"}},
	}
	for _, p := range readCases {
		d := Classify(p, pol)
		if d.RuleID == "self-protect-claude-settings" {
			t.Fatalf("false positive: self-protect-claude-settings fired on a legitimate project-memory path: %+v (severity %s)", p.ToolInput, d.Severity)
		}
	}

	// Deleting ONE specific project's directory is a genuinely distinct
	// subpath, not a dot-alias of .claude/projects itself — self-protect must
	// not floor it. It may still be scored (medium) by the general
	// rm-recursive rule independently; assert what it actually scores rather
	// than assuming.
	rmCase := hook.Payload{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude/projects/x"}}
	d := Classify(rmCase, pol)
	if d.RuleID == "self-protect-claude-settings" {
		t.Fatalf("false positive: self-protect-claude-settings fired on a single project's subdirectory: %+v (severity %s)", rmCase.ToolInput, d.Severity)
	}
	if d.Severity != "medium" {
		t.Fatalf("rm -rf of a single project subdir: got severity %q, want %q (via rm-recursive)", d.Severity, "medium")
	}
}
