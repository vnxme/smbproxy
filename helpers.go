package main

import (
	"errors"
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

func remotePath(p string) string { return strings.TrimLeft(p, "\\") }

func errToStatus(err error) uint32 {
	if err == nil {
		return 0
	}
	for code, sentinel := range smb.StatusMap {
		if errors.Is(err, sentinel) {
			return code
		}
	}
	return smb.StatusObjectNameNotFound
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
