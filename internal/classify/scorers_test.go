package classify

import (
	"testing"

	"github.com/lucasngucii/argus/internal/shellast"
)

func TestRmTarget(t *testing.T) {
	for cmd, want := range map[string]string{
		"rm -rf /": "high", "rm -rf ~": "high", "rm -rf /etc/x": "high", "rm -rf ..": "high",
		"rm -rf ./build": "low", "rm -rf /tmp/scratch": "low", "rm -rf node_modules": "low",
		"rm -rf src/components": "medium",
	} {
		if g := ScoreRmTarget(shellast.Extract(cmd)); g != want {
			t.Errorf("%s: %s!=%s", cmd, g, want)
		}
	}
}
func TestRmUnresolvedTargetHigh(t *testing.T) {
	if ScoreRmTarget(shellast.Extract("rm -rf $TARGET")) != "high" {
		t.Fatal("unresolved target must be high")
	}
}
func TestGitDanger(t *testing.T) {
	for cmd, want := range map[string]string{
		"git push --force": "medium", "git reset --hard HEAD~1": "medium", "git clean -fd": "medium",
		"git push origin main": "safe", "git reset HEAD file": "safe", "git clean -n": "safe",
	} {
		if g := ScoreGitDanger(shellast.Extract(cmd)); g != want {
			t.Errorf("%s: %s!=%s", cmd, g, want)
		}
	}
}
