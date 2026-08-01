package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// checkCodexHook verifies ~/.codex/hooks.json has an entry that runs the argus
// gate command, mirroring checkHook for Claude Code.
func checkCodexHook(home string) error {
	settings, err := readHookSettingsJSON(codexHooksPath(home))
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

// codexFeaturesFlagRe matches the [features] section body: hooks or its
// deprecated alias codex_hooks set to true, with an optional trailing comment.
var codexFeaturesFlagRe = regexp.MustCompile(`^(hooks|codex_hooks)\s*=\s*true\s*(#.*)?$`)
var codexFeaturesFlagFalseRe = regexp.MustCompile(`^(hooks|codex_hooks)\s*=\s*false\s*(#.*)?$`)

// codexHooksFlagEnabled reads ~/.codex/config.toml and reports whether the
// Codex hooks feature flag is confirmed enabled, per Task 3.E: the canonical
// key is [features].hooks; the deprecated alias is [features].codex_hooks.
// This scan is intentionally fail-closed — it is used to gate Probe (and thus
// Doctor), and a false PASS would tell an operator hooks are live when they
// are not. The whole file is scanned (not just the first match) so a later
// `hooks = false` under [features] overrides an earlier `true`.
//
// Table-header parsing requires HasPrefix("[") + HasSuffix("]") and slices
// EXACTLY ONE bracket pair (line[1:len(line)-1]); the inner trimmed string
// must equal exactly "features". This deliberately rejects:
//   - dotted sub-tables, e.g. "[features.experimental]" (inner is
//     "features.experimental", not "features")
//   - arrays of tables, e.g. "[[features]]" (inner is "[features]" — still
//     has brackets, so it is not equal to "features")
//
// A naive strings.Trim(line, "[] ") would strip ALL leading/trailing bracket
// characters and wrongly accept "[[features]]" as the features table --
// exactly the false-PASS this scan must never produce.
//
// A single known theoretical false-PASS residual remains (accepted as safe
// enough per Task 7 brief, since it only widens acceptance, never narrows a
// correctly-configured user's flag): the deprecated codex_hooks alias is
// accepted forward-looking; Task 3.E must confirm codex_hooks still enables
// hooks on the pinned Codex version, and this alias should be dropped from
// codexFeaturesFlagRe if a future Codex release removes it.
//
// Multiline TOML strings (""" ... """ and ''' ... ''') are tracked via
// inString: a line whose remainder contains an odd number of the triple
// delimiter toggles the state, and every line while inString is skipped
// entirely (no header/key parsing) — so a "[features]" or "hooks = true"
// that only appears inside a string's body can neither open a fake table
// nor set the flag, and inFeatures never leaks past a string that happens
// to contain a line that looks like a table header.
//
// Any read error, absent key, quoted/inline-table value, or a key found
// outside [features] returns false.
func codexHooksFlagEnabled(home string) bool {
	f, err := os.Open(filepath.Join(home, ".codex", "config.toml"))
	if err != nil {
		return false
	}
	defer f.Close()

	enabled := false
	inFeatures := false
	inString := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if inString {
			if oddTripleQuoteCount(line) {
				inString = false
			}
			continue
		}
		if oddTripleQuoteCount(line) {
			inString = true
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inner := strings.TrimSpace(line[1 : len(line)-1])
			inFeatures = inner == "features"
			continue
		}
		if !inFeatures {
			continue
		}
		if codexFeaturesFlagRe.MatchString(line) {
			enabled = true
			continue
		}
		if codexFeaturesFlagFalseRe.MatchString(line) {
			enabled = false
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return false
	}
	return enabled
}

// oddTripleQuoteCount reports whether line contains an odd number of TOML
// multiline-string delimiters (""" or '''), i.e. it opens or closes a
// multiline string an odd number of times. A line that both opens and
// closes the same string (e.g. a one-line `x = """abc"""`) nets even and so
// does not toggle state, which is correct: it never leaves a multiline
// string open.
func oddTripleQuoteCount(line string) bool {
	return (strings.Count(line, `"""`)+strings.Count(line, `'''`))%2 == 1
}
