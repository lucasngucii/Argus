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
// Two known false-* residuals remain:
//  1. [safe direction — a nag, never a false-PASS] A "#" comment line whose
//     text happens to contain an odd count of a triple-quote delimiter (or a
//     real string followed by such a trailing comment) is misread as
//     opening/closing a multiline string, since this scanner does not strip
//     comments before the delimiter check. This can only cause a real
//     hooks = true to be wrongly skipped (fail-CLOSED), never accepted.
//  2. [accepted forward-looking] The deprecated codex_hooks alias; Task 3.E
//     must confirm codex_hooks still enables hooks on the pinned Codex
//     version, and this alias should be dropped from codexFeaturesFlagRe if
//     a future Codex release removes it.
//
// Multiline TOML strings (three double quotes or three single quotes) are
// tracked via stringDelim, the delimiter that opened the current string
// (three double quotes or three single quotes, empty when not in a
// string). A line's remainder is skipped entirely (no header/key parsing)
// while stringDelim is set. Tracking is delimiter-TYPE-aware: only an odd
// count of the SAME delimiter that opened the string closes it — a stray
// triple-single-quote substring inside a triple-double-quote-opened string
// must not close it (and vice versa), or the string's
// body would be misread as live TOML past a delimiter that never actually
// terminated it. inFeatures never leaks past a string that happens to
// contain a line that looks like a table header.
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
	stringDelim := "" // "" | `"""` | `'''`

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if stringDelim != "" {
			if oddDelimCount(line, stringDelim) {
				stringDelim = ""
			}
			continue
		}
		if oddDelimCount(line, `"""`) {
			stringDelim = `"""`
			continue
		}
		if oddDelimCount(line, `'''`) {
			stringDelim = `'''`
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

// oddDelimCount reports whether line contains an odd number of the given
// TOML multiline-string delimiter (three double quotes or three single
// quotes), i.e. it opens or closes a string of that delimiter type an odd
// number of times. A line that both
// opens and closes the same string (e.g. a one-line `x = """abc"""`) nets
// even and so does not toggle state, which is correct: it never leaves a
// multiline string open.
func oddDelimCount(line, delim string) bool {
	return strings.Count(line, delim)%2 == 1
}
