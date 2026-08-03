package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUnwireRemovesClaudeGateHookPreservingOthers(t *testing.T) {
	home := t.TempDir()
	if err := Wire("claude-code", home); err != nil {
		t.Fatal(err)
	}
	// Add an unrelated PreToolUse entry and an unrelated top-level key.
	settings, err := readHookSettingsJSON(settingsPath(home))
	if err != nil {
		t.Fatal(err)
	}
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	hooks["PreToolUse"] = append(pre, map[string]any{
		"matcher": "Read",
		"hooks":   []any{map[string]any{"type": "command", "command": "my-linter"}},
	})
	settings["theme"] = "dark"
	if err := writeHookSettingsJSON(settingsPath(home), settings); err != nil {
		t.Fatal(err)
	}

	removed, err := Unwire("claude-code", home)
	if err != nil || !removed {
		t.Fatalf("Unwire = (%v, %v), want (true, nil)", removed, err)
	}

	got, err := readHookSettingsJSON(settingsPath(home))
	if err != nil {
		t.Fatal(err)
	}
	gotHooks, _ := got["hooks"].(map[string]any)
	gotPre, _ := gotHooks["PreToolUse"].([]any)
	if hasGateHook(gotPre) {
		t.Errorf("gate hook must be gone after Unwire; got %v", gotPre)
	}
	if got["theme"] != "dark" {
		t.Errorf("unrelated top-level key must round-trip; got %v", got["theme"])
	}
	// The unrelated linter hook must survive.
	if !strings.Contains(jsonOf(t, got), "my-linter") {
		t.Errorf("unrelated hook must be preserved; got %s", jsonOf(t, got))
	}
}

func TestUnwireIsIdempotentWhenNotWired(t *testing.T) {
	home := t.TempDir()
	removed, err := Unwire("claude-code", home)
	if err != nil {
		t.Fatalf("Unwire on unwired home errored: %v", err)
	}
	if removed {
		t.Error("Unwire reported removed=true when nothing was wired")
	}
	if _, err := os.Stat(settingsPath(home)); !os.IsNotExist(err) {
		t.Error("Unwire must not create a settings file when none existed")
	}
}

func TestUnwireCodex(t *testing.T) {
	home := t.TempDir()
	if err := Wire("codex", home); err != nil {
		t.Fatal(err)
	}
	removed, err := Unwire("codex", home)
	if err != nil || !removed {
		t.Fatalf("Unwire(codex) = (%v, %v), want (true, nil)", removed, err)
	}
	got, _ := readHookSettingsJSON(codexHooksPath(home))
	gotHooks, _ := got["hooks"].(map[string]any)
	gotPre, _ := gotHooks["PreToolUse"].([]any)
	if hasGateHook(gotPre) {
		t.Errorf("codex gate hook must be gone; got %v", gotPre)
	}
}

func TestRunUninstallKeepsArgusByDefault(t *testing.T) {
	home := t.TempDir()
	if err := Wire("claude-code", home); err != nil {
		t.Fatal(err)
	}
	argusDir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if code := RunUninstall(nil, home, &w); code != 0 {
		t.Fatalf("RunUninstall = %d, want 0; out=%s", code, w.String())
	}
	// hook removed
	got, _ := readHookSettingsJSON(settingsPath(home))
	gotHooks, _ := got["hooks"].(map[string]any)
	gotPre, _ := gotHooks["PreToolUse"].([]any)
	if hasGateHook(gotPre) {
		t.Error("hook must be removed by uninstall")
	}
	// ~/.argus kept
	if _, err := os.Stat(argusDir); err != nil {
		t.Errorf("~/.argus must be kept without --purge; stat err=%v", err)
	}
	if !strings.Contains(w.String(), "kept") {
		t.Errorf("output should mention keeping ~/.argus; got %s", w.String())
	}
}

func TestRunUninstallPurgeRemovesArgus(t *testing.T) {
	home := t.TempDir()
	if err := Wire("claude-code", home); err != nil {
		t.Fatal(err)
	}
	argusDir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if code := RunUninstall([]string{"--purge"}, home, &w); code != 0 {
		t.Fatalf("RunUninstall --purge = %d, want 0; out=%s", code, w.String())
	}
	if _, err := os.Stat(argusDir); !os.IsNotExist(err) {
		t.Error("~/.argus must be removed with --purge")
	}
}

// A stray positional argument must be rejected (rc=2), not silently swallowed
// into a full uninstall.
func TestRunUninstallRejectsUnexpectedArg(t *testing.T) {
	home := t.TempDir()
	var w bytes.Buffer
	if code := RunUninstall([]string{"garbage"}, home, &w); code != 2 {
		t.Fatalf("RunUninstall with a stray arg = %d, want 2; out=%s", code, w.String())
	}
	if !strings.Contains(w.String(), "unexpected argument") {
		t.Errorf("expected an unexpected-argument message, got %s", w.String())
	}
}

func TestUnwireUnknownHarnessErrors(t *testing.T) {
	if _, err := Unwire("bogus", t.TempDir()); err == nil {
		t.Error("Unwire(unknown harness) must error")
	}
}

// Unwire must round-trip a sibling event (PostToolUse) and a kept entry that
// carries a non-array `hooks` value byte-for-byte, never materializing "hooks":[]
// or dropping unrelated data.
func TestUnwirePreservesSiblingEventAndMalformedEntry(t *testing.T) {
	home := t.TempDir()
	if err := Wire("claude-code", home); err != nil {
		t.Fatal(err)
	}
	settings, err := readHookSettingsJSON(settingsPath(home))
	if err != nil {
		t.Fatal(err)
	}
	hooks := settings["hooks"].(map[string]any)
	// A sibling event that must survive untouched.
	hooks["PostToolUse"] = []any{map[string]any{
		"matcher": "Write",
		"hooks":   []any{map[string]any{"type": "command", "command": "notify"}},
	}}
	// A PreToolUse entry whose `hooks` value is an object, not an array.
	pre := hooks["PreToolUse"].([]any)
	hooks["PreToolUse"] = append(pre, map[string]any{"matcher": "Read", "hooks": map[string]any{"weird": true}})
	if err := writeHookSettingsJSON(settingsPath(home), settings); err != nil {
		t.Fatal(err)
	}

	if _, err := Unwire("claude-code", home); err != nil {
		t.Fatal(err)
	}
	got, err := readHookSettingsJSON(settingsPath(home))
	if err != nil {
		t.Fatal(err)
	}
	blob := jsonOf(t, got)
	if !strings.Contains(blob, "PostToolUse") || !strings.Contains(blob, "notify") {
		t.Errorf("sibling PostToolUse event must round-trip; got %s", blob)
	}
	if strings.Contains(blob, `"hooks":[]`) {
		t.Errorf("must not materialize an empty hooks array; got %s", blob)
	}
	if !strings.Contains(blob, "weird") {
		t.Errorf("malformed non-array hooks entry must be preserved; got %s", blob)
	}
}

// A settings file without a hooks key, or with hooks but no PreToolUse, must be a
// clean no-op: removed=false, no rewrite.
func TestUnwireNoHooksOrNoPreToolUseIsNoop(t *testing.T) {
	for _, tc := range []struct {
		name string
		blob string
	}{
		{"no-hooks-key", `{"theme":"dark"}`},
		{"no-pretooluse", `{"hooks":{"PostToolUse":[]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := settingsPath(home)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.blob), 0o644); err != nil {
				t.Fatal(err)
			}
			removed, err := Unwire("claude-code", home)
			if err != nil || removed {
				t.Fatalf("Unwire = (%v, %v), want (false, nil)", removed, err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.blob {
				t.Errorf("file must be untouched; got %s want %s", got, tc.blob)
			}
		})
	}
}

// A malformed (unparseable) settings file makes Unwire error; RunUninstall must
// surface that as rc=1 while still attempting the rest and printing a
// remove-the-binary-later warning rather than the all-clear line.
func TestRunUninstallReportsUnwireFailure(t *testing.T) {
	home := t.TempDir()
	path := settingsPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if code := RunUninstall(nil, home, &w); code != 1 {
		t.Fatalf("RunUninstall on malformed settings = %d, want 1; out=%s", code, w.String())
	}
	if strings.Contains(w.String(), "You can now remove the binary") {
		t.Errorf("must not print the all-clear line on failure; got %s", w.String())
	}
}

// Codex unwire on a home that was never wired is a clean no-op and creates
// nothing (the claude-code idempotency case, for the codex path).
func TestUnwireCodexIdempotentWhenNotWired(t *testing.T) {
	home := t.TempDir()
	removed, err := Unwire("codex", home)
	if err != nil || removed {
		t.Fatalf("Unwire(codex) unwired = (%v, %v), want (false, nil)", removed, err)
	}
	if _, err := os.Stat(codexHooksPath(home)); !os.IsNotExist(err) {
		t.Error("Unwire(codex) must not create a hooks file when none existed")
	}
}

// RunUninstall with no harness dir present still succeeds, creates nothing, and
// prints the all-clear line.
func TestRunUninstallNoHarnessInstalled(t *testing.T) {
	home := t.TempDir()
	var w bytes.Buffer
	if code := RunUninstall(nil, home, &w); code != 0 {
		t.Fatalf("RunUninstall with nothing installed = %d, want 0; out=%s", code, w.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); !os.IsNotExist(err) {
		t.Error("uninstall must not create a harness dir")
	}
	if !strings.Contains(w.String(), "remove the binary") {
		t.Errorf("expected the all-clear line; got %s", w.String())
	}
}

// --purge when ~/.argus is already absent must succeed (RemoveAll of a missing
// path is not an error), not report a failure.
func TestRunUninstallPurgeWhenArgusAbsent(t *testing.T) {
	home := t.TempDir()
	var w bytes.Buffer
	if code := RunUninstall([]string{"--purge"}, home, &w); code != 0 {
		t.Fatalf("RunUninstall --purge with no ~/.argus = %d, want 0; out=%s", code, w.String())
	}
}
