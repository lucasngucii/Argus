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

func TestUnwireUnknownHarnessErrors(t *testing.T) {
	if _, err := Unwire("bogus", t.TempDir()); err == nil {
		t.Error("Unwire(unknown harness) must error")
	}
}
