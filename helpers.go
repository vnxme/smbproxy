package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ftEpochDiff uint64 = 116444736000000000
	if ft < ftEpochDiff {
		return time.Time{}
	}
	return time.Unix(0, int64((ft-ftEpochDiff)*100)).UTC()
}

func allocSize(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return ((n-1)/4096 + 1) * 4096
}

func smbBase(p string) string {
	p = strings.TrimRight(p, "\\")
	if p == "" {
		return "\\"
	}
	if i := strings.LastIndexByte(p, '\\'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// normSlashes converts forward slashes to the SMB path separator (backslash),
// so paths written either way — by non-Windows clients or in config — behave
// the same. '/' is not a legal character in an SMB file name, so this never
// alters a real name.
func normSlashes(p string) string { return strings.ReplaceAll(p, "/", "\\") }

// remotePath converts a client path to a share-relative remote path: slashes are
// normalized to backslashes and leading separators are trimmed.
func remotePath(p string) string { return strings.TrimLeft(normSlashes(p), "\\") }

// joinRemote joins a mapping's inner base directory with a client-relative path
// (both already stripped of surrounding backslashes) into one share-relative
// remote path. Either part may be empty.
func joinRemote(base, rel string) string {
	switch {
	case base == "":
		return rel
	case rel == "":
		return base
	default:
		return base + "\\" + rel
	}
}

// hasDotDot reports whether any component of a backslash-separated path is "..".
// It is used to reject attempts to traverse above a mapping's inner base
// directory, keeping that directory a boundary rather than just a start point.
func hasDotDot(p string) bool {
	for part := range strings.SplitSeq(p, "\\") {
		if part == ".." {
			return true
		}
	}
	return false
}

// NTSTATUS codes go-smb does not define.
const (
	statusIoTimeout              uint32 = 0xc00000b5 // STATUS_IO_TIMEOUT
	statusBadNetworkPath         uint32 = 0xc00000be // STATUS_BAD_NETWORK_PATH
	statusUnexpectedNetworkError uint32 = 0xc00000c4 // STATUS_UNEXPECTED_NETWORK_ERROR
	statusNetworkSessionExpired  uint32 = 0xc000035c // STATUS_NETWORK_SESSION_EXPIRED
)

// ntStatus returns the NTSTATUS the target answered with, if err carries one:
// go-smb reports it as an *smb.NTStatusError (whose raw Status survives even
// for codes missing from smb.StatusMap) or, in places, as a bare StatusMap
// sentinel.
func ntStatus(err error) (uint32, bool) {
	if nt, ok := errors.AsType[*smb.NTStatusError](err); ok {
		return nt.Status, true
	}
	for code, sentinel := range smb.StatusMap {
		if errors.Is(err, sentinel) {
			return code, true
		}
	}
	return 0, false
}

// sessionLost reports whether code means the target dropped the proxy's own
// upstream session or tree connect. These concern the proxy's connection, not
// the client's: do redials on them, and they are never passed to a client,
// which would take them as its session with the proxy having ended.
func sessionLost(code uint32) bool {
	switch code {
	case smb.StatusUserSessionDeleted, statusNetworkSessionExpired, smb.StatusNetworkNameDeleted:
		return true
	}
	return false
}

// errToStatus converts an upstream failure into the NTSTATUS reported to the
// client:
//   - a failure to connect to the target: STATUS_ACCESS_DENIED when the target
//     refused the proxy's credentials (passing on a logon failure would make
//     the client re-prompt for credentials that are not at fault), otherwise
//     STATUS_BAD_NETWORK_PATH;
//   - a request that timed out: STATUS_IO_TIMEOUT;
//   - an NTSTATUS answer from the target: that status, unless it reports the
//     proxy's own session lost (see sessionLost);
//   - anything else, a broken connection: STATUS_UNEXPECTED_NETWORK_ERROR.
func errToStatus(err error) uint32 {
	if err == nil {
		return 0
	}
	if _, ok := errors.AsType[*connectError](err); ok {
		if _, answered := ntStatus(err); answered {
			return smb.StatusAccessDenied
		}
		return statusBadNetworkPath
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return statusIoTimeout
	}
	if code, answered := ntStatus(err); answered && !sessionLost(code) {
		return code
	}
	return statusUnexpectedNetworkError
}

func sharedFileAttrs(sf smb.SharedFile) uint32 {
	var a uint32
	if sf.IsDir {
		a |= server.FileAttributeDirectory
	} else {
		a |= server.FileAttributeNormal
	}
	if sf.IsHidden {
		a |= server.FileAttributeHidden
	}
	if sf.IsReadOnly {
		a |= server.FileAttributeReadonly
	}
	if sf.IsJunction {
		a |= 0x00000400
	}
	return a
}

func fixTime(t, now time.Time) time.Time {
	if t.IsZero() {
		return now
	}
	return t
}

func sharedFileToDirEntry(sf smb.SharedFile) server.DirEntry {
	now := time.Now()
	return server.DirEntry{
		Name:           sf.Name,
		Size:           int64(sf.Size),
		AllocationSize: allocSize(int64(sf.Size)),
		Attributes:     sharedFileAttrs(sf),
		CreationTime:   fixTime(filetimeToTime(sf.CreationTime), now),
		LastAccessTime: fixTime(filetimeToTime(sf.LastAccessTime), now),
		LastWriteTime:  fixTime(filetimeToTime(sf.LastWriteTime), now),
		ChangeTime:     fixTime(filetimeToTime(sf.ChangeTime), now),
	}
}

// readAheadSize is the upstream batch size for the cache and prefetch.
// Matches MaxReadSize in ServerConfig so one client READ → one upstream batch.
const readAheadSize = 8 << 20 // 8 MiB
