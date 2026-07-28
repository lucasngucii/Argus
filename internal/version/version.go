// Package version reports the Argus build version.
package version

// version is the build version. It defaults to a dev placeholder and is
// overridden at link time by release builds via:
//
//	-ldflags "-X github.com/lucasngucii/argus/internal/version.version=<tag>"
var version = "0.0.0-dev"

// String returns the current Argus semantic version.
func String() string { return version }
