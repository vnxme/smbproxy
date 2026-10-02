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

	prefMu sync.Mutex
	pref   *prefetch      // the current read-ahead; nil when none is queued
	prefWG sync.WaitGroup // every prefetch goroutine, including discarded ones

	mu          sync.Mutex
	entries     []server.DirEntry
	pos         int
	listed      bool
	lastPattern string
}

// prefetch is one background read-ahead of up to readAheadSize bytes at off.
// Its goroutine sets data and err before closing done, so they are safe to
// read once done is closed. Each prefetch owns its result, so a stale one can
// be discarded while still running without clobbering its replacement.
type prefetch struct {
	off  int64
	done chan struct{}
	data []byte
	err  error
}

func (h *proxyHandle) Stat() (server.FileInfo, error) { return h.info, nil }
func (h *proxyHandle) Path() server.Path              { return h.path }
func (h *proxyHandle) IsDir() bool                    { return h.isDir }

// ---------------------------------------------------------------------------
// proxyVFS — implements server.VFS
// ---------------------------------------------------------------------------

type proxyVFS struct {
	up    *upstream // shared across all VFS instances on the same connection
	share string    // target SMB share (e.g. "C$", or a Samba share like "data")
	base  string    // inner directory within the share this local share maps to (empty = root)
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

	rel := remotePath(req.Path)
	if rel == "" {
		// The client's root is synthetic; its contents are the mapping's base
		// directory, listed by QueryDirectory.
		h := syntheticRootHandle(v.share)
		return server.CreateResult{Handle: h, CreateAction: smb.FileOpened, Info: h.info}, 0, nil
	}
	if hasDotDot(rel) {
		// Keep the mapping's base directory a boundary: no traversal above it.
		return server.CreateResult{}, smb.StatusAccessDenied, nil
	}
	remote := joinRemote(v.base, rel)

	wantsDir := (req.CreateOptions&smb.FileDirectoryFile) != 0 ||
		(req.FileAttributes&smb.FileAttrDirectory) != 0

	var upFile upstreamFile
	err = v.up.do(func(c upstreamConn) error {
		var e error
		if wantsDir {
			upFile, e = c.OpenFileExt(v.share, remote, openDirOpts())
			if e != nil {
				o := openDirOpts()
				o.CreateOpts = 0
				upFile, e = c.OpenFileExt(v.share, remote, o)
			}
		} else {
			upFile, e = c.OpenFileExt(v.share, remote, openFileOpts())
			if e != nil {
				upFile, e = c.OpenFileExt(v.share, remote, openDirOpts())
			}
		}
		return e
	})
	if err != nil {
		return server.CreateResult{}, errToStatus(err), nil
	}

	// Pin the connection open for the lifetime of this handle so the idle
	// reaper cannot close it mid-use; Close drops the pin.
	v.up.hold()
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

	// No Read can still be using the cache: each holds fileMu.RLock throughout,
	// and from here on sees the nil file and returns before reaching it.
	ph.setCache(0, nil)

	ph.prefMu.Lock()
	ph.pref = nil
	ph.prefMu.Unlock()
	// Wait out every read-ahead, including discarded ones still running, so
	// none touches the upstream file after it is closed below.
	ph.prefWG.Wait()

	if file != nil {
		func() {
			v.up.mu.Lock()
			defer v.up.mu.Unlock()
			_ = file.CloseFile()
		}()
		// Drop the pin taken in Create; only file-backed handles hold one (the
		// synthetic root handle has no upstream file), so this mirrors hold.
		v.up.release()
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
	if p := ph.pref; p != nil && p.off == offset {
		ph.pref = nil
		ph.prefMu.Unlock()
		<-p.done
		if p.err != nil {
			return 0, errToStatus(p.err), nil
		}
		if len(p.data) == 0 {
			return 0, smb.StatusEndOfFile, nil
		}
		serve := copy(buf[:min(len(p.data), need)], p.data)
		ph.setCache(offset, p.data)
		v.startPrefetch(ph, offset+int64(len(p.data)))
		return serve, smb.StatusOk, nil
	}
	ph.prefMu.Unlock()

	// ---- tier 3: synchronous fetch ----
	data, fErr := v.fetch(ph.file, offset, ph.info.Size)
	if fErr != nil {
		return 0, errToStatus(fErr), nil
	}
	if len(data) == 0 {
		return 0, smb.StatusEndOfFile, nil
	}
	serve := copy(buf[:min(len(data), need)], data)
	ph.setCache(offset, data)
	v.startPrefetch(ph, offset+int64(len(data)))
	return serve, smb.StatusOk, nil
}

// setCache makes data, read from the target at off, the handle's cached
// region and recycles the buffer it replaces. Readers copy out of the cache
// under cacheMu, so once swapped out the old buffer has no other user.
func (ph *proxyHandle) setCache(off int64, data []byte) {
	ph.cacheMu.Lock()
	old := ph.cacheData
	ph.cacheOff, ph.cacheData = off, data
	ph.cacheMu.Unlock()
	putReadBuf(old)
}

// probeSize is how much fetch asks for at or past the end of file as seen
// when the handle was opened. The file may have grown since, so such a read
// still goes upstream, but without committing a full read-ahead buffer to
// what is usually an EOF.
const probeSize = 64 << 10

// fetch reads one batch from the target at off: readAheadSize bytes, clamped
// to the end of a file whose size was size when opened, so a small file does
// not cost a full read-ahead buffer. It returns the bytes read, which may be
// fewer at end of file and are empty at it, or the error that prevented
// reading anything; an EOF is not an error. Full-size buffers come from
// readBufPool and go back to it via putReadBuf once no longer cached.
func (v *proxyVFS) fetch(file upstreamFile, off, size int64) ([]byte, error) {
	want := int64(probeSize)
	if rest := size - off; rest > 0 {
		want = min(rest, readAheadSize)
	}
	upBuf := getReadBuf(int(want))

	totalN := 0
	var fetchErr error
	v.up.mu.Lock()
	for totalN < len(upBuf) {
		rn, rErr := file.ReadFile(upBuf[totalN:], uint64(off)+uint64(totalN))
		if rn > 0 {
			totalN += rn
		}
		if rErr != nil {
			isEOF := errors.Is(rErr, io.EOF) ||
				errors.Is(rErr, smb.StatusMap[smb.StatusEndOfFile])
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

	if totalN == 0 {
		putReadBuf(upBuf)
		return nil, fetchErr
	}
	return upBuf[:totalN], nil
}

// readBufPool recycles full read-ahead buffers, which a streaming client
// otherwise allocates at readAheadSize per batch. Smaller, end-of-file
// buffers are plain allocations left to the garbage collector.
var readBufPool = sync.Pool{New: func() any { return new([readAheadSize]byte) }}

// getReadBuf returns a buffer of length n, pooled when n is a full batch.
func getReadBuf(n int) []byte {
	if n == readAheadSize {
		return readBufPool.Get().(*[readAheadSize]byte)[:]
	}
	return make([]byte, n)
}

// putReadBuf recycles b if it is a full-size buffer from getReadBuf. The
// caller must hold the only reference to it.
func putReadBuf(b []byte) {
	if cap(b) == readAheadSize {
		readBufPool.Put((*[readAheadSize]byte)(b[:readAheadSize]))
	}
}

// startPrefetch queues a background read-ahead at off. A read-ahead already
// queued for off is kept; one for any other offset is stale (the client has
// moved elsewhere in the file) and is replaced, so a seek does not leave
// read-ahead stuck on a region that will never be read. Nothing is queued at
// or past the end of the file as it was when opened: that read would almost
// always come back empty, and a client reading on past it (into a file that
// has since grown) is served by a synchronous fetch instead.
//
// The caller must hold ph.fileMu.RLock with ph.file non-nil. The goroutine is
// handed the file rather than taking fileMu itself: a pending Close's Lock
// would block that RLock while Read, holding its own RLock, waits for the
// prefetch to finish — a deadlock.
func (v *proxyVFS) startPrefetch(ph *proxyHandle, off int64) {
	if off >= ph.info.Size {
		return
	}
	ph.prefMu.Lock()
	if ph.pref != nil && ph.pref.off == off {
		ph.prefMu.Unlock()
		return
	}
	p := &prefetch{off: off, done: make(chan struct{})}
	ph.pref = p
	file := ph.file
	ph.prefWG.Add(1)
	ph.prefMu.Unlock()

	go func() {
		defer ph.prefWG.Done()
		defer close(p.done)
		p.data, p.err = v.fetch(file, off, ph.info.Size)
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
			err = v.up.do(func(c upstreamConn) error {
				if tcErr := c.TreeConnect(v.share); tcErr != nil {
					return tcErr
				}
				var e error
				raw, e = c.ListDirectory(v.share, v.base, pattern)
				return e
			})
		} else {
			if ph.file == nil {
				return nil, smb.StatusFileClosed, nil
			}
			func() {
				v.up.mu.Lock()
				defer v.up.mu.Unlock()
				raw, err = queryDirAll(ph.file, pattern)
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

// queryDirAll lists every entry of the open directory f matching pattern. One
// upstream QUERY_DIRECTORY returns only as many entries as fit its output
// buffer, so it keeps asking until the target reports no more files. The first
// request always restarts the scan: a handle that was listed before (or under
// another pattern) has an exhausted upstream enumeration that would otherwise
// yield nothing.
func queryDirAll(f upstreamFile, pattern string) ([]smb.SharedFile, error) {
	var all []smb.SharedFile
	flags := smb.RestartScans
	for {
		batch, err := f.QueryDirectory(pattern, flags, 0, 65536)
		if errors.Is(err, smb.StatusMap[smb.StatusNoMoreFiles]) && len(all) > 0 {
			return all, nil
		}
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			if len(all) == 0 {
				return nil, smb.StatusMap[smb.StatusNoMoreFiles]
			}
			return all, nil
		}
		all = append(all, batch...)
		flags = 0
	}
}

// QueryFileInfo returns StatusNotSupported on purpose: the library then
// serializes the info class from the handle's Stat() snapshot, which already
// holds the target's real metadata (size, attributes, all four timestamps)
// captured when the file was opened. go-smb exposes no raw per-class file-info
// query to forward, and the snapshot is current for Explorer's Properties,
// which opens a fresh handle before querying — so this is already served from
// upstream data; there is nothing further to proxy here.
func (v *proxyVFS) QueryFileInfo(_ context.Context, _ server.Handle, _ byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

func (v *proxyVFS) SetFileInfo(_ context.Context, _ server.Handle, _ byte, _ []byte) (uint32, error) {
	return smb.StatusAccessDenied, nil
}

func (v *proxyVFS) QueryFSInfo(_ context.Context, _ byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// QuerySecurity proxies the client's request for a file's security descriptor
// (the Explorer "Security" tab: real owner, group and ACLs) through to the
// target. It operates on the already-open handle like Read/QueryDirectory, so
// it does not redial on a transport error. On anything that leaves no real
// descriptor — the synthetic root, a closed handle, or an upstream error — it
// returns StatusNotSupported so the library falls back to its default
// descriptor and Properties still opens.
func (v *proxyVFS) QuerySecurity(_ context.Context, h server.Handle, additionalInformation uint32) (buf []byte, status uint32, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] QuerySecurity panic: %v\n%s", r, debug.Stack())
			buf, status, err = nil, smb.StatusNotSupported, nil
		}
	}()

	ph := h.(*proxyHandle)
	ph.fileMu.RLock()
	file := ph.file
	ph.fileMu.RUnlock()
	if file == nil {
		return nil, smb.StatusNotSupported, nil
	}

	var sd []byte
	func() {
		v.up.mu.Lock()
		defer v.up.mu.Unlock()
		sd, err = file.QuerySecurity(additionalInformation)
	}()
	if err != nil {
		log.Printf("[proxy] QuerySecurity upstream error: %v", err)
		return nil, smb.StatusNotSupported, nil
	}
	return sd, smb.StatusOk, nil
}

func (v *proxyVFS) Ioctl(_ context.Context, _ server.Handle, _ uint32, _ []byte, _ uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}
