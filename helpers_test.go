package main

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ftUnixEpoch is 1970-01-01T00:00:00Z as a Windows FILETIME.
const ftUnixEpoch uint64 = 116444736000000000

func TestFiletimeToTime(t *testing.T) {
	cases := []struct {
		name string
		ft   uint64
		want time.Time
	}{
		{"zero", 0, time.Time{}},
		{"before unix epoch", ftUnixEpoch - 1, time.Time{}},
		{"unix epoch", ftUnixEpoch, time.Unix(0, 0).UTC()},
		{"one second", ftUnixEpoch + 10_000_000, time.Unix(1, 0).UTC()},
		{"100ns resolution", ftUnixEpoch + 1, time.Unix(0, 100).UTC()},
		{"2024-01-01", 133485408000000000, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		if got := filetimeToTime(c.ft); !got.Equal(c.want) {
			t.Errorf("%s: filetimeToTime(%d) = %v, want %v", c.name, c.ft, got, c.want)
		}
	}
}

func TestAllocSize(t *testing.T) {
	cases := []struct{ in, want int64 }{
		{-5, 0},
		{0, 0},
		{1, 4096},
		{4095, 4096},
		{4096, 4096},
		{4097, 8192},
		{1 << 20, 1 << 20},
	}
	for _, c := range cases {
		if got := allocSize(c.in); got != c.want {
			t.Errorf("allocSize(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSmbBase(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "\\"},
		{"\\", "\\"},
		{"\\\\", "\\"},
		{"file.txt", "file.txt"},
		{"\\file.txt", "file.txt"},
		{"dir\\sub\\file.txt", "file.txt"},
		{"dir\\sub\\", "sub"},
	}
	for _, c := range cases {
		if got := smbBase(c.in); got != c.want {
			t.Errorf("smbBase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRemotePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"\\", ""},
		{"\\\\dir\\file", "dir\\file"},
		{"dir\\file\\", "dir\\file\\"},
		{"/", ""},                           // leading forward slash trimmed
		{"/dir/file", "dir\\file"},          // forward slashes normalized
		{"dir/sub\\file", "dir\\sub\\file"}, // mixed slashes
	}
	for _, c := range cases {
		if got := remotePath(c.in); got != c.want {
			t.Errorf("remotePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestJoinRemote(t *testing.T) {
	cases := []struct{ base, rel, want string }{
		{"", "", ""},
		{"", "a\\b", "a\\b"},
		{"Users\\Public", "", "Users\\Public"},
		{"Users\\Public", "sub\\f.txt", "Users\\Public\\sub\\f.txt"},
	}
	for _, c := range cases {
		if got := joinRemote(c.base, c.rel); got != c.want {
			t.Errorf("joinRemote(%q, %q) = %q, want %q", c.base, c.rel, got, c.want)
		}
	}
}

func TestHasDotDot(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"dir\\file.txt", false},
		{"..", true},
		{"..\\..\\Windows", true},
		{"dir\\..\\other", true},
		{"dir\\..hidden\\file", false}, // "..hidden" is not a traversal component
	}
	for _, c := range cases {
		if got := hasDotDot(c.in); got != c.want {
			t.Errorf("hasDotDot(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestErrToStatus(t *testing.T) {
	denied := smb.StatusMap[smb.StatusAccessDenied]
	cases := []struct {
		name string
		err  error
		want uint32
	}{
		{"nil", nil, smb.StatusOk},
		{"sentinel", denied, smb.StatusAccessDenied},
		{"wrapped sentinel", fmt.Errorf("open: %w", denied), smb.StatusAccessDenied},
		{"unknown error", errors.New("boom"), smb.StatusObjectNameNotFound},
	}
	for _, c := range cases {
		if got := errToStatus(c.err); got != c.want {
			t.Errorf("%s: errToStatus = 0x%08x, want 0x%08x", c.name, got, c.want)
		}
	}
}

func TestSharedFileAttrs(t *testing.T) {
	cases := []struct {
		name string
		sf   smb.SharedFile
		want uint32
	}{
		{"plain file", smb.SharedFile{}, server.FileAttributeNormal},
		{"dir", smb.SharedFile{IsDir: true}, server.FileAttributeDirectory},
		{"hidden readonly file", smb.SharedFile{IsHidden: true, IsReadOnly: true},
			server.FileAttributeNormal | server.FileAttributeHidden | server.FileAttributeReadonly},
		{"junction dir", smb.SharedFile{IsDir: true, IsJunction: true},
			server.FileAttributeDirectory | 0x00000400},
	}
	for _, c := range cases {
		if got := sharedFileAttrs(c.sf); got != c.want {
			t.Errorf("%s: sharedFileAttrs = 0x%x, want 0x%x", c.name, got, c.want)
		}
	}
}

func TestFixTime(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	set := time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)
	if got := fixTime(time.Time{}, now); !got.Equal(now) {
		t.Errorf("fixTime(zero) = %v, want %v", got, now)
	}
	if got := fixTime(set, now); !got.Equal(set) {
		t.Errorf("fixTime(set) = %v, want %v", got, set)
	}
}

func TestSharedFileToDirEntry(t *testing.T) {
	const ft2024 uint64 = 133485408000000000
	want2024 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	before := time.Now()
	e := sharedFileToDirEntry(smb.SharedFile{
		Name:          "a.bin",
		Size:          5000,
		IsReadOnly:    true,
		CreationTime:  ft2024,
		LastWriteTime: ft2024,
		// LastAccessTime and ChangeTime left zero → filled with now
	})
	after := time.Now()

	if e.Name != "a.bin" || e.Size != 5000 || e.AllocationSize != 8192 {
		t.Errorf("name/size/alloc = %q/%d/%d, want a.bin/5000/8192", e.Name, e.Size, e.AllocationSize)
	}
	if want := server.FileAttributeNormal | server.FileAttributeReadonly; e.Attributes != want {
		t.Errorf("attributes = 0x%x, want 0x%x", e.Attributes, want)
	}
	if !e.CreationTime.Equal(want2024) || !e.LastWriteTime.Equal(want2024) {
		t.Errorf("creation/lastwrite = %v/%v, want %v", e.CreationTime, e.LastWriteTime, want2024)
	}
	for name, ts := range map[string]time.Time{"LastAccessTime": e.LastAccessTime, "ChangeTime": e.ChangeTime} {
		if ts.Before(before) || ts.After(after) {
			t.Errorf("%s = %v, want substituted now in [%v, %v]", name, ts, before, after)
		}
	}
}
