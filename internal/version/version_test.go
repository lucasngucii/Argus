package version

import "testing"

func TestStringIsSemver(t *testing.T) {
	if g := String(); g == "" || g[0] < '0' || g[0] > '9' {
		t.Fatalf("version %q not semver-looking", g)
	}
}
