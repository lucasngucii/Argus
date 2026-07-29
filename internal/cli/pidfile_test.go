package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPIDFile_RoundTrip proves the write/read/remove cycle against ~/.argus.
func TestPIDFile_RoundTrip(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".argus"), 0o700); err != nil {
		t.Fatal(err)
	}

	want := 4242
	if err := writePID(home, want); err != nil {
		t.Fatalf("writePID: %v", err)
	}

	got, err := readPID(home)
	if err != nil {
		t.Fatalf("readPID: %v", err)
	}
	if got != want {
		t.Fatalf("readPID = %d, want %d", got, want)
	}

	if err := removePID(home); err != nil {
		t.Fatalf("removePID: %v", err)
	}
	if _, err := readPID(home); !os.IsNotExist(err) {
		t.Fatalf("readPID after remove = %v, want IsNotExist", err)
	}
}

// TestReadPID_Missing reports a not-exist error when no pid file is present,
// so callers can treat "not running" distinctly from a corrupt file.
func TestReadPID_Missing(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".argus"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readPID(home); !os.IsNotExist(err) {
		t.Fatalf("readPID(missing) = %v, want IsNotExist", err)
	}
}
