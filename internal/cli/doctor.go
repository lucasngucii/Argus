package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

// Doctor verifies an `argus init` install is intact. It probes whichever
// harness config directories are present (~/.claude, ~/.codex — both, if
// both were wired) via Probe, prints a WARN when Codex's hook trust can't be
// confirmed from disk and another naming the Codex matcher's Bash-only
// coverage scope, and checks that policy.json loads and schema-validates,
// the SQLite store opens (and so is writable — Open runs a CREATE TABLE IF
// NOT EXISTS against it), and the policy_versions audit trail was seeded. It
// prints one PASS/FAIL line per check to w and returns 0 only if every check
// passed, so it can be used directly as a shell/CI exit-code gate.
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

	claudeInstalled := dirExists(filepath.Join(home, ".claude"))
	codexInstalled := dirExists(filepath.Join(home, ".codex"))
	if claudeInstalled {
		report("hook (claude-code): argus gate wired in ~/.claude/settings.json", Probe("claude-code", home))
	}
	if codexInstalled {
		report("hook (codex): argus gate wired + [features].hooks enabled", Probe("codex", home))
		// Trust is not disk-verifiable — surface it as a WARN so a PASS above is
		// never read as "definitely active" when the hook may be untrusted-inert.
		fmt.Fprintln(w, "WARN hook (codex): the hook must be trusted (run /hooks in Codex) — Argus can't verify trust from disk")
		// The Codex matcher is Bash-only today — surface the coverage gap so a
		// PASS above is never read as "everything Codex can gate is gated".
		fmt.Fprintln(w, "WARN hook (codex): only Bash commands are gated on Codex; MCP / apply_patch / unified_exec tool calls are NOT yet gated")
	}
	if !claudeInstalled && !codexInstalled {
		// fresh box: no harness detected yet, still surface an actionable FAIL
		report("hook: PreToolUse -> argus gate wired in ~/.claude/settings.json", Probe("claude-code", home))
	}
	warnShadowedArgus(w)
	report("policy: policy.json loads and schema-validates", checkPolicy(home))
	warnMissingMCPMatcher(home, w)
	warnUnknownOverride(home, w)
	warnBaselineDrift(home, w)

	st, err := store.Open(filepath.Join(home, ".argus", "argus.db"))
	report("store: argus.db opens and is writable", err)

	report("policy_versions: audit trail seeded", checkPolicyVersions(st))

	if !ok {
		return 1
	}
	return 0
}

// dirExists reports whether p exists and is a directory.
func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func checkHook(home string) error {
	settings, err := readHookSettingsJSON(settingsPath(home))
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

// warnShadowedArgus warns when the `argus` the wired hook will actually exec is
// missing or is a DIFFERENT program than this Argus. The hook runs the bare
// command `argus gate`, so it resolves `argus` via PATH at fire time — an
// unrelated `argus` package (there is one on npm, unaffiliated) that wins PATH
// would silently shadow the gate, which then never fires. This is a non-fatal
// WARN and never changes the exit code: PATH is the user's to fix, and doctor's
// job here is to make a silent shadow visible, not to fail CI over it.
func warnShadowedArgus(w io.Writer) {
	path, err := exec.LookPath("argus")
	if err != nil {
		fmt.Fprintln(w, "WARN argus: not found on PATH — the wired hook runs `argus gate`, which will fail to launch; put argus on your PATH")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, path, "version").Output()
	if msg, warn := shadowVerdict(path, string(out), runErr); warn {
		fmt.Fprintln(w, msg)
	}
}

// shadowVerdict is the pure core of warnShadowedArgus: given the PATH-resolved
// argus and its `version` output/error, decide whether it looks like a foreign
// binary shadowing ours. Our binary answers with `argus <semver>` (version-
// agnostic on purpose — a mismatched version is still our gate); anything else,
// or an error, means the hook may exec a different program.
func shadowVerdict(path, versionOut string, runErr error) (string, bool) {
	if runErr == nil && strings.HasPrefix(strings.TrimSpace(versionOut), "argus ") {
		return "", false
	}
	return fmt.Sprintf("WARN argus: the `argus` on PATH (%s) does not identify as this Argus — "+
		"the hook execs `argus gate` via PATH, so the gate may run a different program; "+
		"install the scoped package @lucasngucii/argus and ensure it wins PATH", path), true
}

func checkPolicy(home string) error {
	_, err := policy.Load(filepath.Join(home, ".argus", "policy.json"))
	return err
}

// warnMissingMCPMatcher prints a non-fatal WARN when the wired PreToolUse
// matcher does not gate MCP tools (mcp__*) — an install from before MCP gating.
// A re-run of `argus init` self-heals it. Does NOT change the exit code.
func warnMissingMCPMatcher(home string, w io.Writer) {
	settings, err := readHookSettingsJSON(settingsPath(home))
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

// warnUnknownOverride prints a non-fatal WARN for any override that names a
// rule id no current Baseline() carries — a stale override left after a rule was
// renamed or removed. Baselines can no longer be "missing" (they come from the
// binary), so this is the correctly-oriented drift check. Does NOT change exit.
func warnUnknownOverride(home string, w io.Writer) {
	f, err := policy.LoadFile(filepath.Join(home, ".argus", "policy.json"))
	if err != nil {
		return
	}
	known := map[string]bool{}
	for _, id := range policy.SeedRuleIDs() {
		known[id] = true
	}
	var unknown []string
	for id := range f.Overrides {
		if !known[id] {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown) // deterministic output
	if len(unknown) > 0 {
		fmt.Fprintf(w, "WARN policy: override references unknown baseline rule: %s\n", strings.Join(unknown, ", "))
	}
}

// warnBaselineDrift prints a non-fatal WARN when the raw policy file carries an
// inline baseline copy customized in a field normalize cannot migrate (match /
// reason / tool / contextEscalation) — surfacing the intended discard so an
// operator's superseded hand-edit is visible. Does NOT change exit.
func warnBaselineDrift(home string, w io.Writer) {
	b, err := os.ReadFile(filepath.Join(home, ".argus", "policy.json"))
	if err != nil {
		return
	}
	if ids := policy.BaselineDriftIDs(b); len(ids) > 0 {
		fmt.Fprintf(w, "WARN policy: baseline customization not migrated (binary definition now applies): %s\n", strings.Join(ids, ", "))
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
