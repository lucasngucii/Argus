package version

import "testing"

func TestStringIsSemver(t *testing.T) {
	if g := String(); g == "" || g[0] < '0' || g[0] > '9' {
		t.Fatalf("version %q not semver-looking", g)
	}
}

func TestDefaultVersionIsDevPlaceholder(t *testing.T) {
	if got := String(); got != "0.0.0-dev" {
		t.Fatalf("default String() = %q, want %q (ldflags override is applied at build)", got, "0.0.0-dev")
	}
}
