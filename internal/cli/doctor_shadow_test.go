package cli

import (
	"os"
	"strings"
	"testing"
)

// TestMain defaults every cli test to a deterministic "genuine argus on PATH"
// probe, so Doctor() never shells out to the test machine's real argus — that
// made the shadow WARN environment-dependent and, before the WaitDelay bound,
// could hang the suite on a slow/hung launcher. Shadow-specific tests override
// pathArgusProbe and restore it.
func TestMain(m *testing.M) {
	pathArgusProbe = func() argusProbe {
		return argusProbe{path: "/stub/bin/argus", version: "argus 9.9.9\n"}
	}
	os.Exit(m.Run())
}

// shadowVerdict is the pure decision behind the PATH-shadow WARN: our binary
// answers `version` with `argus <digit…>`; a foreign `argus` that shadows ours
// on PATH does not, so the wired hook (`argus gate`, resolved via PATH) would
// silently exec a different program.
func TestShadowVerdict(t *testing.T) {
	cases := []struct {
		name     string
		out      string
		runErr   error
		wantWarn bool
	}{
		{"our banner", "argus 0.1.14\n", nil, false},
		{"our banner other version", "argus 0.1.9\n", nil, false},
		{"banner with surrounding space", "  argus 1.2.3  \n", nil, false},
		{"argus but no version token", "argus is a build tool\n", nil, true},
		{"name only, no space", "argus\n", nil, true},
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

// Doctor() surfaces the shadow/not-on-PATH WARN from the injected probe, and
// never lets it change the exit code.
func TestDoctorShadowWarningsFromProbe(t *testing.T) {
	restore := pathArgusProbe
	defer func() { pathArgusProbe = restore }()

	cases := []struct {
		name  string
		probe argusProbe
		want  string // substring the WARN must contain; "" means no shadow WARN
	}{
		{"genuine", argusProbe{path: "/x/argus", version: "argus 1.0.0\n"}, ""},
		{"not on PATH", argusProbe{}, "not found on PATH"},
		{"foreign impostor", argusProbe{path: "/other/argus", version: "0.0.3\n"}, "does not identify as this Argus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pathArgusProbe = func() argusProbe { return tc.probe }
			var b strings.Builder
			warnShadowedArgus(&b)
			out := b.String()
			if tc.want == "" {
				if strings.Contains(out, "WARN argus") {
					t.Errorf("genuine argus must not warn, got %q", out)
				}
				return
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("want WARN containing %q, got %q", tc.want, out)
			}
		})
	}
}

var errFake = fakeErr("boom")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }
