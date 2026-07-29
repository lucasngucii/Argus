package adapter

import "testing"

func TestCanonical(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "claude-code", false},          // bare `argus gate`, old install
		{"claude-code", "claude-code", false},
		{"codex", "", true},                 // not yet a known harness
		{"CLAUDE-CODE", "", true},           // case-sensitive; unknown
		{"claude", "", true},
	}
	for _, tt := range tests {
		got, err := Canonical(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("Canonical(%q) err=%v wantErr=%v", tt.in, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("Canonical(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
