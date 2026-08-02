package cli

import "testing"

// shadowVerdict is the pure decision behind the PATH-shadow WARN: our binary
// answers `version` with a banner starting "argus "; a foreign `argus` that
// shadows ours on PATH does not, so the wired hook (`argus gate`, resolved via
// PATH) would silently exec a different program.
func TestShadowVerdict(t *testing.T) {
	cases := []struct {
		name     string
		out      string
		runErr   error
		wantWarn bool
	}{
		{"our banner", "argus 0.1.13\n", nil, false},
		{"our banner other version", "argus 0.1.9\n", nil, false},
		{"banner with surrounding space", "  argus 1.2.3  \n", nil, false},
		{"impostor bare version", "0.0.3\n", nil, true},
		{"impostor usage text", "usage: argus-tool ...\n", nil, true},
		{"run error (unknown subcommand)", "", errFake, true},
		{"empty output", "", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, warn := shadowVerdict("/usr/local/bin/argus", tc.out, tc.runErr)
			if warn != tc.wantWarn {
				t.Fatalf("shadowVerdict(%q, err=%v) warn=%v, want %v", tc.out, tc.runErr, warn, tc.wantWarn)
			}
		})
	}
}

var errFake = fakeErr("boom")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }
