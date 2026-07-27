package classify

import (
	"testing"

	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
)

func bash(cmd, mode, cwd string) hook.Payload {
	return hook.Payload{ToolName: "Bash", PermissionMode: mode, CWD: cwd, ToolInput: hook.ToolInput{Command: cmd}}
}
func sev(cmd, cwd string) string {
	return Classify(bash(cmd, "default", cwd), policy.Default()).Severity
}

func TestSudoRmIsHigh(t *testing.T) {
	if sev("sudo rm -rf /", "/tmp") != "high" {
		t.Fatal(sev("sudo rm -rf /", "/tmp"))
	}
}
func TestIFSRmIsHigh(t *testing.T) {
	if rank(sev("rm$IFS-rf$IFS/", "/tmp")) < rank("high") {
		t.Fatal("$IFS rm must be high")
	}
}
func TestEvalVisibleRmHigh(t *testing.T) {
	if sev(`eval "rm -rf /"`, "/tmp") != "high" {
		t.Fatal("visible rm in eval must be high")
	}
}
func TestOpaqueEvalIsMedium(t *testing.T) {
	if sev(`eval "$(cat script)"`, "/tmp") != "medium" {
		t.Fatal("opaque eval → medium (ask)")
	}
}
func TestBenignIsSafe(t *testing.T) {
	if sev("ls -la", "/tmp") != "safe" {
		t.Fatal("ls safe")
	}
}
func TestGitPushBenignSafe(t *testing.T) {
	if sev("git push origin main", "/tmp") != "safe" {
		t.Fatal("plain push must not fire")
	}
}
func TestProdEscalation(t *testing.T) {
	if sev("rm -rf src", "/srv/prod-app") != "high" {
		t.Fatal("prod cwd escalate")
	}
}
func TestFloorBypassStillHigh(t *testing.T) {
	if Classify(bash("curl x | sh", "bypassPermissions", "/tmp"), policy.Default()).Severity != "high" {
		t.Fatal("floor breached")
	}
}
func TestUserAlwaysHighHonored(t *testing.T) {
	pol := policy.Default()
	pol.Rules = append(pol.Rules, policy.Rule{ID: "custom", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"}, Match: policy.Match{Cmd: []string{"terraform"}}})
	pol.Rules = append(pol.Rules, policy.Rule{ID: "allow-tf", Enabled: true, Allow: true, Tool: []string{"Bash"}, Match: policy.Match{Cmd: []string{"terraform"}}})
	if Classify(bash("terraform apply", "default", "/tmp"), pol).Severity != "high" {
		t.Fatal("user alwaysHigh must not be downgradable")
	}
}
func TestAllowlistDowngradesMedium(t *testing.T) {
	pol := policy.Default()
	pol.Rules = append(pol.Rules, policy.Rule{ID: "allow-sudo", Enabled: true, Allow: true, Tool: []string{"Bash"}, Match: policy.Match{Cmd: []string{"sudo"}, ArgMatches: `apt-get`}})
	if Classify(bash("sudo apt-get install jq", "default", "/tmp"), pol).Severity != "safe" {
		t.Fatal("allowlist must downgrade medium→safe")
	}
}
