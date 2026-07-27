package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lucasngucii/argus/internal/classify"
	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
)

// corpusCase is one JSONL line of a rule corpus: a tool invocation plus the
// severity the classifier must return for it. It is the on-disk contract for
// both the golden (precision) and evasion (must-catch) corpora.
type corpusCase struct {
	Command string `json:"command"`
	Tool    string `json:"tool"`
	CWD     string `json:"cwd"`
	Mode    string `json:"mode"`
	Expect  string `json:"expect"`
}

// RunHarness replays every corpus line in paths through Classify against pol
// and reports each case whose severity differs from its expected value. It is
// the permanent regression guard for the gate's evasion resistance: it prints
// one FAIL line (expected vs got) per mismatch and a final summary, and returns
// non-zero if ANY line mismatched or any file/line could not be read — 0 only
// when every line passed. A read or parse error is a failure, never a silent
// skip, so a corrupt corpus can never masquerade as a clean run.
func RunHarness(paths []string, pol policy.Policy, w io.Writer) int {
	cases, failures := 0, 0

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(w, "ERROR open %s: %v\n", path, err)
			failures++
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		line := 0
		for sc.Scan() {
			line++
			text := strings.TrimSpace(sc.Text())
			if text == "" || strings.HasPrefix(text, "//") {
				continue // blank line or comment
			}
			var c corpusCase
			if err := json.Unmarshal([]byte(text), &c); err != nil {
				fmt.Fprintf(w, "ERROR %s:%d parse: %v\n", path, line, err)
				failures++
				continue
			}
			cases++
			got := classify.Classify(payloadFor(c), pol).Severity
			if got != c.Expect {
				failures++
				fmt.Fprintf(w, "FAIL %s:%d %q\n  expected %s, got %s\n", path, line, c.Command, c.Expect, got)
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			fmt.Fprintf(w, "ERROR read %s: %v\n", path, err)
			failures++
		}
	}

	fmt.Fprintf(w, "harness: %d cases, %d passed, %d failed\n", cases, cases-failures, failures)
	if failures > 0 {
		return 1
	}
	return 0
}

// payloadFor builds the hook.Payload the classifier judges from one corpus
// case. For Bash the command text is the subject; for every other tool the
// subject is a file path (hook.Subject), so the command field is placed there.
func payloadFor(c corpusCase) hook.Payload {
	p := hook.Payload{ToolName: c.Tool, CWD: c.CWD, PermissionMode: c.Mode}
	if c.Tool == "Bash" {
		p.ToolInput.Command = c.Command
	} else {
		p.ToolInput.FilePath = c.Command
	}
	return p
}
