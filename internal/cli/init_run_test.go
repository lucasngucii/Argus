package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestRunInit_Help prints usage describing init and its flags, and performs no
// setup — `argus init --help` must be side-effect free.
func TestRunInit_Help(t *testing.T) {
	home := t.TempDir()
	var w bytes.Buffer
	if code := RunInit([]string{"--help"}, home, &w); code != 0 {
		t.Fatalf("RunInit(--help) = %d, want 0", code)
	}
	out := w.String()
	for _, want := range []string{"--no-serve", "--addr", "background"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help output missing %q; got:\n%s", want, out)
		}
	}
	if _, err := os.Stat(home + "/.argus"); !os.IsNotExist(err) {
		t.Fatalf("--help created ~/.argus (side effect); err=%v", err)
	}
}

// TestRunInit_NoServe runs setup but does not start a background server, so no
// pid file or serve log appears.
func TestRunInit_NoServe(t *testing.T) {
	home := t.TempDir()
	var w bytes.Buffer
	if code := RunInit([]string{"--no-serve"}, home, &w); code != 0 {
		t.Fatalf("RunInit(--no-serve) = %d, want 0; out=%s", code, w.String())
	}
	if !strings.Contains(w.String(), "initialized") {
		t.Fatalf("output = %q, want 'initialized'", w.String())
	}
	if _, err := readPID(home); !os.IsNotExist(err) {
		t.Fatalf("--no-serve wrote a pid file: %v", err)
	}
	if _, err := os.Stat(home + "/.argus/serve.log"); !os.IsNotExist(err) {
		t.Fatalf("--no-serve created serve.log: %v", err)
	}
	// setup really ran
	if _, err := os.Stat(home + "/.argus/policy.json"); err != nil {
		t.Fatalf("--no-serve skipped setup: %v", err)
	}
}
