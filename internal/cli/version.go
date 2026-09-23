package cli

import "runtime/debug"

// version is set at build time with -ldflags "-X ...cli.version=v1.2.3".
var version = "dev"

// Version returns the build version, falling back to the module version
// when installed with `go install`.
func Version() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
