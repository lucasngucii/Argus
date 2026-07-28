package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

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
	warnMissingSeedRules(home, w)
	warnMissingMCPMatcher(home, w)

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

// warnMissingSeedRules prints a non-fatal WARN when the loaded policy is
// missing any baseline seed rule — a user-edited policy silently losing its
// default `medium` coverage. It does NOT change the exit code: the hard checks
// still govern 0/non-0. A policy that fails to load is left to the policy check
// above; there is nothing to compare here.
func warnMissingSeedRules(home string, w io.Writer) {
	pol, err := policy.Load(filepath.Join(home, ".argus", "policy.json"))
	if err != nil {
		return
	}
	present := make(map[string]bool, len(pol.Rules))
	for _, r := range pol.Rules {
		present[r.ID] = true
	}
	var missing []string
	for _, id := range policy.SeedRuleIDs() {
		if !present[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(w, "WARN policy: missing baseline seed rules: %s\n", strings.Join(missing, ", "))
	}
}

// warnMissingMCPMatcher prints a non-fatal WARN when the wired PreToolUse
// matcher does not gate MCP tools (mcp__*) — an install from before MCP gating.
// A re-run of `argus init` self-heals it. Does NOT change the exit code.
func warnMissingMCPMatcher(home string, w io.Writer) {
	settings, err := readSettings(settingsPath(home))
	if err != nil {
		return
	}
	hooks, _ := settings["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	e := gateEntry(preToolUse)
	if e == nil {
		return // the hook check above already FAILs on a missing gate entry
	}
	if m, _ := e["matcher"].(string); !strings.Contains(m, "mcp__") {
		fmt.Fprintln(w, "WARN hook: PreToolUse matcher does not gate MCP tools (mcp__*) — re-run 'argus init' to update it")
	}
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
