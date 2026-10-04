package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// version is the release version, set at build time for release binaries:
//
//	go build -ldflags "-X main.version=v1.2.0"
//
// Left empty, it falls back to what the Go toolchain recorded: the module
// version under go install, or a pseudo-version for a build from a git
// checkout.
var version string

// versionString describes the build: the version, the commit it was built
// from when known, and the Go toolchain and platform.
func versionString() string {
	info, _ := debug.ReadBuildInfo()
	return describeBuild(version, info)
}

func describeBuild(v string, info *debug.BuildInfo) string {
	var revision string
	var modified bool
	if info != nil {
		if v == "" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	if v == "" || v == "(devel)" {
		v = "devel"
	}
	build := fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if revision != "" {
		revision = revision[:min(len(revision), 12)]
		if modified {
			revision += "-dirty"
		}
		build = "commit " + revision + ", " + build
	}
	return fmt.Sprintf("smbproxy %s (%s)", v, build)
}
