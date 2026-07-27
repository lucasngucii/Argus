package cli

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

// Doctor verifies an `argus init` install is intact: the Claude Code hook
// is wired, policy.json loads and schema-validates, the SQLite store opens
// (and so is writable — Open runs a CREATE TABLE IF NOT EXISTS against it),
// and the policy_versions audit trail was seeded. It prints one PASS/FAIL
// line per check to w and returns 0 only if every check passed, so it can
// be used directly as a shell/CI exit-code gate.
func Doctor(home string, w io.Writer) int {
	ok := true

	report := func(label string, err error) {
		if err != nil {
			fmt.Fprintf(w, "FAIL %s: %v\n", label, err)
			ok = false
			return
		}
		fmt.Fprintf(w, "PASS %s\n", label)
	}

	report("hook: PreToolUse -> argus gate wired in ~/.claude/settings.json", checkHook(home))
	report("policy: policy.json loads and schema-validates", checkPolicy(home))

	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	report("store: argus.db opens and is writable", err)

	report("policy_versions: audit trail seeded", checkPolicyVersions(st))

	if !ok {
		return 1
	}
	return 0
}

func checkHook(home string) error {
	settings, err := readSettings(settingsPath(home))
	if err != nil {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	if !hasGateHook(preToolUse) {
		return fmt.Errorf("no PreToolUse entry runs %q", gateCommand)
	}
	return nil
}

func checkPolicy(home string) error {
	_, err := policy.Load(filepath.Join(home, ".argus", "policy.json"))
	return err
}

func checkPolicyVersions(st *store.Store) error {
	if st == nil {
		return fmt.Errorf("store unavailable")
	}
	n, err := st.PolicyVersionCount()
	if err != nil {
		return err
	}
	if n < 1 {
		return fmt.Errorf("0 rows recorded")
	}
	return nil
}
