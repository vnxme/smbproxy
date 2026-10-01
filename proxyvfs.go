package main

import (
	"context"
	"errors"
	"io"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ---------------------------------------------------------------------------
// proxyHandle — implements server.Handle
// ---------------------------------------------------------------------------

type proxyHandle struct {
	info   server.FileInfo
	path   server.Path
	isDir  bool
	file   upstreamFile
	isRoot bool

	fileMu sync.RWMutex

	cacheMu   sync.Mutex
	cacheOff  int64
	cacheData []byte

	prefMu   sync.Mutex
	prefOff  int64
	prefData []byte
	prefErr  error
	prefDone chan struct{}

	mu          sync.Mutex
	entries     []server.DirEntry
	pos         int
	listed      bool
	lastPattern string
}

func (h *proxyHandle) Stat() (server.FileInfo, error) { return h.info, nil }
func (h *proxyHandle) Path() server.Path              { return h.path }
func (h *proxyHandle) IsDir() bool                    { return h.isDir }

// ---------------------------------------------------------------------------
// proxyVFS — implements server.VFS
// ---------------------------------------------------------------------------

type proxyVFS struct {
	up    *upstream // shared across all VFS instances on the same connection
	share string
}

func openDirOpts() *smb.CreateReqOpts {
	o := smb.NewCreateReqOpts()
	o.DesiredAccess = smb.DAccMaskFileListDirectory |
		smb.DAccMaskFileReadAttributes |
		smb.DAccMaskReadControl |
		smb.DAccMaskSynchronize
	o.CreateOpts = smb.FileDirectoryFile
	o.ShareAccess = smb.FileShareRead | smb.FileShareWrite | smb.FileShareDelete
	o.CreateDisp = smb.FileOpen
	return o
}

func openFileOpts() *smb.CreateReqOpts {
	o := smb.NewCreateReqOpts()
	o.ShareAccess = smb.FileShareRead | smb.FileShareWrite
	o.CreateDisp = smb.FileOpen
	return o
}

func syntheticRootHandle(shareName string) *proxyHandle {
	now := time.Now()
	return &proxyHandle{
		info: server.FileInfo{
			Name:           shareName,
			Attributes:     server.FileAttributeDirectory,
			CreationTime:   now,
			LastAccessTime: now,
			LastWriteTime:  now,
			ChangeTime:     now,
		},
		path:   "\\",
		isDir:  true,
		isRoot: true,
	}
}

func handleFromFile(req server.CreateRequest, f upstreamFile, shareName string) *proxyHandle {
	now := time.Now()
	m := f.meta()
	attrs := m.attributes
	if attrs == 0 {
		if f.IsDir() {
			attrs = server.FileAttributeDirectory
		} else {
			attrs = server.FileAttributeNormal
		}
	}
	name := smbBase(req.Path)
	if name == "\\" || name == "" {
		name = shareName
	}
	return &proxyHandle{
		info: server.FileInfo{
			Name:           name,
			Size:           int64(m.endOfFile),
			AllocationSize: allocSize(int64(m.endOfFile)),
			Attributes:     attrs,
			CreationTime:   fixTime(filetimeToTime(m.creationTime), now),
			LastAccessTime: fixTime(filetimeToTime(m.lastAccessTime), now),
			LastWriteTime:  fixTime(filetimeToTime(m.lastWriteTime), now),
			ChangeTime:     fixTime(filetimeToTime(m.changeTime), now),
		},
		path:  req.Path,
		isDir: f.IsDir(),
		file:  f,
	}
}

func (v *proxyVFS) Create(_ context.Context, _ *server.Session, req server.CreateRequest) (result server.CreateResult, status uint32, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] Create %q panic: %v\n%s", req.Path, r, debug.Stack())
			result, status = server.CreateResult{}, smb.StatusObjectNameNotFound
		}
	}()

	remote := remotePath(req.Path)
	if remote == "" {
		h := syntheticRootHandle(v.share)
		return server.CreateResult{Handle: h, CreateAction: smb.FileOpened, Info: h.info}, 0, nil
	}

	wantsDir := (req.CreateOptions&smb.FileDirectoryFile) != 0 ||
		(req.FileAttributes&smb.FileAttrDirectory) != 0

	v.up.mu.Lock()
	defer v.up.mu.Unlock()

	var upFile upstreamFile
	if wantsDir {
		upFile, err = v.up.conn.OpenFileExt(v.share, remote, openDirOpts())
		if err != nil {
			o := openDirOpts()
			o.CreateOpts = 0
			upFile, err = v.up.conn.OpenFileExt(v.share, remote, o)
		}
	} else {
		upFile, err = v.up.conn.OpenFileExt(v.share, remote, openFileOpts())
		if err != nil {
			upFile, err = v.up.conn.OpenFileExt(v.share, remote, openDirOpts())
		}
	}
	if err != nil {
		return server.CreateResult{}, errToStatus(err), nil
	}

	h := handleFromFile(req, upFile, v.share)
	return server.CreateResult{Handle: h, CreateAction: smb.FileOpened, Info: h.info}, 0, nil
}

func (v *proxyVFS) Close(_ context.Context, h server.Handle) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] Close panic: %v\n%s", r, debug.Stack())
		}
	}()
	ph := h.(*proxyHandle)

	ph.fileMu.Lock()
	file := ph.file
	ph.file = nil
	ph.fileMu.Unlock()

	ph.cacheMu.Lock()
	ph.cacheData = nil
	ph.cacheMu.Unlock()

	ph.prefMu.Lock()
	done := ph.prefDone
	ph.prefMu.Unlock()
	if done != nil {
		<-done
	}
	ph.prefMu.Lock()
	ph.prefData = nil
	ph.prefDone = nil
	ph.prefOff = -1
	ph.prefMu.Unlock()

	if file != nil {
		func() {
			v.up.mu.Lock()
			defer v.up.mu.Unlock()
			_ = file.CloseFile()
		}()
	}
	return nil
}

func (v *proxyVFS) Read(_ context.Context, h server.Handle, offset int64, buf []byte) (n int, status uint32, err error) {
	ph := h.(*proxyHandle)

	ph.fileMu.RLock()
	defer ph.fileMu.RUnlock()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] Read offset=%d panic: %v\n%s", offset, r, debug.Stack())
			n, status = 0, smb.FsctlStatusPipeBroken
		}
	}()

	if ph.file == nil {
		if ph.isRoot {
			return 0, smb.StatusAccessDenied, nil
		}
		return 0, smb.StatusFileClosed, nil
	}

	need := len(buf)

	// ---- tier 1: cache hit ----
	ph.cacheMu.Lock()
	if ph.cacheData != nil {
		cacheOff := ph.cacheOff
		cacheLen := int64(len(ph.cacheData))
		cacheEnd := cacheOff + cacheLen
		if offset >= cacheOff && offset < cacheEnd {
			start := int(offset - cacheOff)
			avail := len(ph.cacheData) - start
			serve := min(avail, need)
			copy(buf[:serve], ph.cacheData[start:start+serve])
			triggerAt := cacheOff + cacheLen/2
			nextOff := cacheEnd
			ph.cacheMu.Unlock()
			if offset+int64(serve) >= triggerAt {
				v.startPrefetch(ph, nextOff)
			}
			if serve == 0 {
				return 0, smb.StatusEndOfFile, nil
			}
			return serve, smb.StatusOk, nil
		}
	}
	ph.cacheMu.Unlock()

	// ---- tier 2: prefetch hit ----
	ph.prefMu.Lock()
	if ph.prefDone != nil && ph.prefOff == offset {
		done := ph.prefDone
		ph.prefMu.Unlock()
		<-done
		ph.prefMu.Lock()
		data, pErr := ph.prefData, ph.prefErr
		ph.prefData = nil
		ph.prefOff = -1
		ph.prefDone = nil
		ph.prefMu.Unlock()

		isEOF := errors.Is(pErr, io.EOF) ||
			errors.Is(pErr, smb.StatusMap[smb.StatusEndOfFile])
		if pErr != nil && !isEOF {
			return 0, errToStatus(pErr), nil
		}
		if len(data) == 0 {
			return 0, smb.StatusEndOfFile, nil
		}
		ph.cacheMu.Lock()
		ph.cacheOff = offset
		ph.cacheData = data
		ph.cacheMu.Unlock()
		v.startPrefetch(ph, offset+int64(len(data)))

		serve := min(len(data), need)
		copy(buf[:serve], data[:serve])
		return serve, smb.StatusOk, nil
	}
	ph.prefMu.Unlock()

	// ---- tier 3: synchronous fetch ----
	upBuf := make([]byte, readAheadSize)
	totalN := 0
	v.up.mu.Lock()
	for totalN < readAheadSize {
		rn, rErr := ph.file.ReadFile(upBuf[totalN:], uint64(offset)+uint64(totalN))
		if rn > 0 {
			totalN += rn
		}
		isEOF := errors.Is(rErr, io.EOF) ||
			errors.Is(rErr, smb.StatusMap[smb.StatusEndOfFile])
		if rErr != nil {
			if !isEOF && totalN == 0 {
				v.up.mu.Unlock()
				return 0, errToStatus(rErr), nil
			}
			break
		}
		if rn == 0 {
			break
		}
	}
	v.up.mu.Unlock()

	if totalN == 0 {
		return 0, smb.StatusEndOfFile, nil
	}
	ph.cacheMu.Lock()
	ph.cacheOff = offset
	ph.cacheData = upBuf[:totalN]
	ph.cacheMu.Unlock()
	v.startPrefetch(ph, offset+int64(totalN))

	serve := min(totalN, need)
	copy(buf[:serve], upBuf[:serve])
	return serve, smb.StatusOk, nil
}

func (v *proxyVFS) startPrefetch(ph *proxyHandle, off int64) {
	ph.prefMu.Lock()
	if ph.prefDone != nil {
		ph.prefMu.Unlock()
		return
	}
	ch := make(chan struct{})
	ph.prefDone = ch
	ph.prefOff = off
	ph.prefMu.Unlock()

	go func() {
		defer close(ch)

		ph.fileMu.RLock()
		file := ph.file
		ph.fileMu.RUnlock()
		if file == nil {
			return
		}

		upBuf := make([]byte, readAheadSize)
		totalN := 0
		var fetchErr error

		v.up.mu.Lock()
		for totalN < readAheadSize {
			rn, rErr := file.ReadFile(upBuf[totalN:], uint64(off)+uint64(totalN))
			if rn > 0 {
				totalN += rn
			}
			isEOF := errors.Is(rErr, io.EOF) ||
				errors.Is(rErr, smb.StatusMap[smb.StatusEndOfFile])
			if rErr != nil {
				if !isEOF && totalN == 0 {
					fetchErr = rErr
				}
				break
			}
			if rn == 0 {
				break
			}
		}
		v.up.mu.Unlock()

		ph.prefMu.Lock()
		if totalN > 0 {
			ph.prefData = upBuf[:totalN]
		}
		ph.prefErr = fetchErr
		ph.prefMu.Unlock()
	}()
}

func (v *proxyVFS) Write(_ context.Context, _ server.Handle, _ int64, _ []byte) (int, uint32, error) {
	return 0, smb.StatusAccessDenied, nil
}

func (v *proxyVFS) Flush(_ context.Context, _ server.Handle) (uint32, error) {
	return 0, nil
}

func (v *proxyVFS) QueryDirectory(_ context.Context, h server.Handle, pattern string, restart bool) (entries []server.DirEntry, status uint32, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] QueryDirectory %q panic: %v\n%s", pattern, r, debug.Stack())
			entries, status = nil, smb.StatusObjectNameNotFound
		}
	}()

	ph := h.(*proxyHandle)
	ph.mu.Lock()
	defer ph.mu.Unlock()

	if pattern == "" {
		pattern = "*"
	}

	if restart || !ph.listed || pattern != ph.lastPattern {
		var raw []smb.SharedFile

		if ph.isRoot {
			func() {
				v.up.mu.Lock()
				defer v.up.mu.Unlock()
				tcErr := v.up.conn.TreeConnect(v.share)
				if tcErr == nil {
					raw, err = v.up.conn.ListDirectory(v.share, "", pattern)
				} else {
					err = tcErr
				}
			}()
		} else {
			if ph.file == nil {
				return nil, smb.StatusFileClosed, nil
			}
			var flags byte
			if restart {
				flags = smb.RestartScans
			}
			func() {
				v.up.mu.Lock()
				defer v.up.mu.Unlock()
				raw, err = ph.file.QueryDirectory(pattern, flags, 0, 65536)
			}()
		}

		if err != nil {
			if errors.Is(err, smb.StatusMap[smb.StatusNoMoreFiles]) {
				ph.listed, ph.lastPattern, ph.entries, ph.pos = true, pattern, nil, 0
				return nil, smb.StatusNoMoreFiles, nil
			}
			return nil, errToStatus(err), nil
		}

		converted := make([]server.DirEntry, len(raw))
		for i, sf := range raw {
			converted[i] = sharedFileToDirEntry(sf)
		}
		ph.entries, ph.pos, ph.listed, ph.lastPattern = converted, 0, true, pattern
	}

	if ph.pos >= len(ph.entries) {
		return nil, smb.StatusNoMoreFiles, nil
	}
	result := ph.entries[ph.pos:]
	ph.pos = len(ph.entries)
	return result, 0, nil
}

func (v *proxyVFS) QueryFileInfo(_ context.Context, _ server.Handle, _ byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

func (v *proxyVFS) SetFileInfo(_ context.Context, _ server.Handle, _ byte, _ []byte) (uint32, error) {
	return smb.StatusAccessDenied, nil
}

func (v *proxyVFS) QueryFSInfo(_ context.Context, _ byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

func (v *proxyVFS) QuerySecurity(_ context.Context, _ server.Handle, _ uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

func (v *proxyVFS) Ioctl(_ context.Context, _ server.Handle, _ uint32, _ []byte, _ uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}
