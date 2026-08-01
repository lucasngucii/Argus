package adapter

import "testing"

func TestCanonical(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "claude-code", false}, // bare `argus gate`, old install
		{"claude-code", "claude-code", false},
		{"codex", "codex", false},
		{"CLAUDE-CODE", "", true}, // case-sensitive; unknown
		{"claude", "", true},
		{"bogus", "", true}, // permanent-unknown fixture
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
