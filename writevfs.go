package main

import (
	"context"
	"encoding/binary"
	"log"
	"runtime/debug"
	"time"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ---------------------------------------------------------------------------
// Write path — creating, writing, renaming, deleting and truncating on the
// target, for shares with read_only: false
//
// go-smb's write gate (Share.WritableUsers and friends, set from write_access)
// refuses CREATE dispositions that change anything, WRITE and SET_INFO from
// sessions that may not write, before these methods run.
// ---------------------------------------------------------------------------

// Access rights that let a handle change its file (MS-SMB2 2.2.13.1).
const (
	accessWriteData       = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	accessAppendData      = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	accessWriteEA         = 0x00000010
	accessDeleteChild     = 0x00000040
	accessWriteAttributes = 0x00000100
	accessDelete          = 0x00010000
	accessWriteDAC        = 0x00040000
	accessWriteOwner      = 0x00080000
	accessMaximumAllowed  = 0x02000000
	accessGenericAll      = 0x10000000
	accessGenericWrite    = 0x40000000

	writeAccessMask = accessWriteData | accessAppendData | accessWriteEA | accessDeleteChild |
		accessWriteAttributes | accessDelete | accessWriteDAC | accessWriteOwner |
		accessMaximumAllowed | accessGenericAll | accessGenericWrite
)

// fileDispositionInformationEx is the extended delete disposition (MS-FSCC
// 2.4.12), which Windows 10 and later send instead of the classic one.
const fileDispositionInformationEx = 0x40

// writeIntent reports whether a CREATE may change something: a disposition
// other than opening an existing file, delete-on-close, or any access right
// that lets the handle modify its file.
func writeIntent(req server.CreateRequest) bool {
	return req.CreateDisposition != smb.FileOpen ||
		req.CreateOptions&smb.FileDeleteOnClose != 0 ||
		req.DesiredAccess&writeAccessMask != 0
}

// createForWrite opens remote on the target as the client asked: its
// disposition, access, sharing, attributes and options pass through, so the
// target creates, overwrites, makes folders and deletes on close exactly as
// requested, and reports what it did. Opens that change nothing keep the
// read path, with its permissive defaults.
func (v *proxyVFS) createForWrite(req server.CreateRequest, rel, remote string) (server.CreateResult, uint32, error) {
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = req.DesiredAccess
	opts.FileAttr = req.FileAttributes
	opts.ShareAccess = req.ShareAccess
	opts.CreateDisp = req.CreateDisposition
	opts.CreateOpts = req.CreateOptions

	var upFile upstreamFile
	err := v.up.do(func(c upstreamConn) error {
		var e error
		upFile, e = c.OpenFileExt(v.share, remote, opts)
		return e
	})
	if err != nil {
		return server.CreateResult{}, errToStatus(err), nil
	}
	v.up.hold() // released by Close, as on the read path
	h := handleFromFile(req, upFile, v.share)
	h.info.FileID = v.fileID(rel)
	return server.CreateResult{Handle: h, CreateAction: upFile.meta().createAction, Info: h.info}, smb.StatusOk, nil
}

func (v *proxyVFS) Write(_ context.Context, h server.Handle, offset int64, data []byte) (n int, status uint32, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] Write offset=%d panic: %v\n%s", offset, r, debug.Stack())
			n, status, err = 0, statusUnexpectedNetworkError, nil
		}
	}()
	ph := h.(*proxyHandle)
	ph.fileMu.RLock()
	defer ph.fileMu.RUnlock()
	if ph.file == nil {
		if ph.isRoot {
			return 0, smb.StatusAccessDenied, nil
		}
		return 0, smb.StatusFileClosed, nil
	}

	v.up.mu.Lock()
	ctx, cancel := v.up.ioContext()
	n, err = ph.file.WriteFile(ctx, data, uint64(offset))
	cancel()
	v.up.mu.Unlock()

	// Whatever was written, the handle's read-ahead may now be stale.
	ph.discardReadAhead()
	if n > 0 {
		end := offset + int64(n)
		now := time.Now()
		ph.updateInfo(func(fi *server.FileInfo) {
			if end > fi.Size {
				fi.Size, fi.AllocationSize = end, allocSize(end)
			}
			fi.LastWriteTime, fi.ChangeTime = now, now
		})
	}
	if err != nil {
		return n, errToStatus(err), nil
	}
	return n, smb.StatusOk, nil
}

func (v *proxyVFS) Flush(_ context.Context, h server.Handle) (uint32, error) {
	ph := h.(*proxyHandle)
	ph.fileMu.RLock()
	defer ph.fileMu.RUnlock()
	if ph.file == nil || ph.isDir {
		return smb.StatusOk, nil // nothing buffered to flush
	}
	v.up.mu.Lock()
	ctx, cancel := v.up.ioContext()
	err := ph.file.Flush(ctx)
	cancel()
	v.up.mu.Unlock()
	if err != nil {
		return errToStatus(err), nil
	}
	return smb.StatusOk, nil
}

// SetFileInfo forwards the information classes that change a file to the
// target: a rename (its new name confined to the mapped folder), a delete
// disposition, a new end of file or allocation, and timestamps and
// attributes. The handle's own metadata follows, so later queries through it
// report the change. Other classes are not supported.
func (v *proxyVFS) SetFileInfo(_ context.Context, h server.Handle, class byte, raw []byte) (status uint32, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] SetFileInfo class=0x%02x panic: %v\n%s", class, r, debug.Stack())
			status, err = statusUnexpectedNetworkError, nil
		}
	}()
	ph := h.(*proxyHandle)
	ph.fileMu.RLock()
	defer ph.fileMu.RUnlock()
	if ph.file == nil {
		if ph.isRoot {
			return smb.StatusAccessDenied, nil // the share root is not the client's to change
		}
		return smb.StatusFileClosed, nil
	}

	buf, newPath := raw, ""
	switch class {
	case smb.FileRenameInformation:
		var st uint32
		if buf, newPath, st = v.translateRename(raw); st != smb.StatusOk {
			return st, nil
		}
	case smb.FileBasicInformation, smb.FileDispositionInformation, fileDispositionInformationEx,
		smb.FileAllocationInformation, smb.FileEndOfFileInformation:
	case smb.FilePositionInformation:
		return smb.StatusOk, nil // the client's file position: nothing on the target to change
	default:
		return smb.StatusNotSupported, nil
	}

	v.up.mu.Lock()
	err = ph.file.SetInfo(class, buf)
	v.up.mu.Unlock()
	if err != nil {
		return errToStatus(err), nil
	}
	ph.applySetInfo(class, raw, newPath)
	return smb.StatusOk, nil
}

// translateRename rewrites a FILE_RENAME_INFORMATION payload (MS-FSCC
// 2.4.37: ReplaceIfExists(1), Reserved(7), RootDirectory(8),
// FileNameLength(4), FileName) for the target: the new name, relative to the
// client's share root, becomes relative to the target share, inside the
// mapped folder. A name that climbs out of it with ".." is refused, as it is
// on open. It returns the payload, the new client-relative path, and a status.
func (v *proxyVFS) translateRename(raw []byte) ([]byte, string, uint32) {
	if len(raw) < 20 {
		return nil, "", smb.StatusInfoLengthMismatch
	}
	if binary.LittleEndian.Uint64(raw[8:16]) != 0 {
		return nil, "", smb.StatusNotSupported // relative to an open directory: SMB2 clients do not send this
	}
	nameLen := int(binary.LittleEndian.Uint32(raw[16:20]))
	if nameLen%2 != 0 || 20+nameLen > len(raw) {
		return nil, "", smb.StatusInvalidParameter
	}
	units := make([]uint16, nameLen/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[20+2*i:])
	}
	rel := remotePath(string(utf16.Decode(units)))
	switch {
	case rel == "":
		return nil, "", smb.StatusObjectNameInvalid
	case hasDotDot(rel):
		return nil, "", smb.StatusAccessDenied // keep the mapped folder a boundary
	}
	name := utf16.Encode([]rune(joinRemote(v.base, rel)))
	out := make([]byte, 20+2*len(name))
	copy(out, raw[:16]) // ReplaceIfExists, Reserved, RootDirectory
	binary.LittleEndian.PutUint32(out[16:], uint32(2*len(name)))
	for i, u := range name {
		binary.LittleEndian.PutUint16(out[20+2*i:], u)
	}
	return out, rel, smb.StatusOk
}

// applySetInfo updates the handle's metadata after the target accepted a
// SET_INFO, so later queries through the handle report the change.
func (ph *proxyHandle) applySetInfo(class byte, raw []byte, newPath string) {
	now := time.Now()
	switch class {
	case smb.FileRenameInformation:
		ph.infoMu.Lock()
		ph.path = newPath
		ph.info.Name = smbBase(newPath)
		ph.info.ChangeTime = now
		ph.infoMu.Unlock()
	case smb.FileEndOfFileInformation:
		if len(raw) >= 8 {
			size := int64(binary.LittleEndian.Uint64(raw))
			ph.discardReadAhead()
			ph.updateInfo(func(fi *server.FileInfo) {
				fi.Size, fi.AllocationSize = size, allocSize(size)
				fi.LastWriteTime, fi.ChangeTime = now, now
			})
		}
	case smb.FileAllocationInformation:
		// An allocation below the end of file truncates the file to it.
		if len(raw) >= 8 {
			alloc := int64(binary.LittleEndian.Uint64(raw))
			ph.discardReadAhead()
			ph.updateInfo(func(fi *server.FileInfo) {
				fi.AllocationSize = alloc
				if alloc < fi.Size {
					fi.Size = alloc
				}
			})
		}
	case smb.FileBasicInformation:
		// FILE_BASIC_INFORMATION (MS-FSCC 2.4.7): four FILETIMEs, where 0
		// (and the special values -1 and -2) leave a time as it is, then
		// the attributes, where 0 leaves them as they are.
		if len(raw) >= 36 {
			ph.updateInfo(func(fi *server.FileInfo) {
				for i, t := range []*time.Time{&fi.CreationTime, &fi.LastAccessTime, &fi.LastWriteTime, &fi.ChangeTime} {
					if ft := int64(binary.LittleEndian.Uint64(raw[8*i:])); ft > 0 {
						*t = filetimeToTime(uint64(ft))
					}
				}
				if attrs := binary.LittleEndian.Uint32(raw[32:]); attrs != 0 {
					fi.Attributes = attrs
				}
			})
		}
	}
}

// discardReadAhead drops the handle's cached and prefetched data, which a
// change to the file through the handle may have made stale. A read-ahead
// still running caches nothing.
func (ph *proxyHandle) discardReadAhead() {
	ph.clearCache()
}
