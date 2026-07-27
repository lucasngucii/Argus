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
	}
	for _, p := range cases {
		if got := Classify(p, pol).Severity; got == "high" {
			t.Fatalf("false positive: %+v classified high", p.ToolInput)
		}
	}
}
