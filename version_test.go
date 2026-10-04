package main

import (
	"runtime"
	"runtime/debug"
	"testing"
)

func TestDescribeBuild(t *testing.T) {
	platform := runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	vcs := func(modified string) []debug.BuildSetting {
		return []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.modified", Value: modified},
		}
	}
	cases := []struct {
		name    string
		version string
		info    *debug.BuildInfo
		want    string
	}{
		{"no build info", "", nil, "smbproxy devel (" + platform + ")"},
		{"set at build time", "v1.2.0", nil, "smbproxy v1.2.0 (" + platform + ")"},
		{
			"go run or test", "", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			"smbproxy devel (" + platform + ")",
		},
		{
			"go install", "", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.0"}},
			"smbproxy v1.2.0 (" + platform + ")",
		},
		{
			"set at build time wins", "v1.2.0",
			&debug.BuildInfo{Main: debug.Module{Version: "v1.2.1-0.20261004120000-0123456789ab"}, Settings: vcs("false")},
			"smbproxy v1.2.0 (commit 0123456789ab, " + platform + ")",
		},
		{
			"uncommitted changes", "",
			&debug.BuildInfo{Main: debug.Module{Version: "v1.2.1-0.20261004120000-0123456789ab+dirty"}, Settings: vcs("true")},
			"smbproxy v1.2.1-0.20261004120000-0123456789ab+dirty (commit 0123456789ab-dirty, " + platform + ")",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := describeBuild(c.version, c.info); got != c.want {
				t.Errorf("describeBuild = %q, want %q", got, c.want)
			}
		})
	}
}
