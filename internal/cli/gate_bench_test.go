package cli

import (
	"io"
	"strings"
	"testing"
)

func BenchmarkGate(b *testing.B) {
	in := `{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"sudo rm -rf /tmp/x"}}`
	for i := 0; i < b.N; i++ {
		Gate(strings.NewReader(in), io.Discard, b.TempDir(), "claude-code")
	}
}
