package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ---------------------------------------------------------------------------
// proxyHandle — implements server.Handle
// ---------------------------------------------------------------------------

type proxyHandle struct {
	// info and path change as a client writes, truncates, sets timestamps or
	// renames through the handle; infoMu guards them. Read them through Stat
	// and Path.
	infoMu sync.Mutex
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

func (h *proxyHandle) Stat() (server.FileInfo, error) {
	h.infoMu.Lock()
	defer h.infoMu.Unlock()
	return h.info, nil
}

func (h *proxyHandle) Path() server.Path {
	h.infoMu.Lock()
	defer h.infoMu.Unlock()
	return h.path
}

func (h *proxyHandle) IsDir() bool { return h.isDir }

// size returns the file's current size as the proxy knows it.
func (h *proxyHandle) size() int64 {
	h.infoMu.Lock()
	defer h.infoMu.Unlock()
	return h.info.Size
}

// updateInfo applies fn to the handle's metadata under its lock.
func (h *proxyHandle) updateInfo(fn func(*server.FileInfo)) {
	h.infoMu.Lock()
	defer h.infoMu.Unlock()
	fn(&h.info)
}

// ---------------------------------------------------------------------------
// proxyVFS — implements server.VFS
// ---------------------------------------------------------------------------

type proxyVFS struct {
	up    *upstream // shared across all VFS instances on the same connection
	share string    // target SMB share (e.g. "C$", or a Samba share like "data")
	base  string    // inner directory within the share this local share maps to (empty = root)

	// canWrite reports whether a session may change this share (see
	// share.canWrite); nil means no one may. go-smb's write gate already
	// refuses writes from everyone else; this only decides how Create opens
	// a file on the target (see createForWrite).
	canWrite func(*server.Session) bool

	fsMu         sync.Mutex
	fsCache      map[byte]fsCached // target volume information by class (see volumeInfo)
	noSectorInfo bool              // the target refused FileFsSectorSizeInformation
}

type fsCached struct {
	at  time.Time
	buf []byte
}

// openDirOpts opens a directory for listing. It shares the directory fully,
// whatever the client asked: it asks the target for list access even when the
// client asked for attributes alone, and such an open, exempt from sharing
// modes on Windows, must not keep other clients from renaming or deleting the
// directory.
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

// contentAccess are the rights that reach a file's contents. Sharing modes
// apply only to opens asking for one of these (or for write or delete rights,
// which take the write path); an open without them reads metadata alone.
const contentAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileExecute |
	smb.FAccMaskGenericRead | smb.FAccMaskGenericExecute | smb.FAccMaskGenericAll |
	smb.FAccMaskMaximumAllowed

// metadataAccess are the read rights that sharing modes never block.
const metadataAccess = smb.FAccMaskFileReadAttributes | smb.FAccMaskFileReadEA |
	smb.FAccMaskReadControl | smb.FAccMaskSynchronize

// openFileOpts opens a file for reading on behalf of a client that asked for
// access and share mode share.
//
// A client asking only for metadata gets just that on the target too: as on
// Windows, such an open succeeds while another client holds the file
// exclusively (Explorer stats a file it is still copying, for instance), where
// opening it for reading would fail with a sharing violation.
//
// The share mode is the client's, so the target applies it between all the
// proxy's clients as Windows would between processes: a reader that allows
// deletion lets others rename or delete the file while it reads, and one that
// allows no writing keeps others from writing.
func openFileOpts(access, share uint32) *smb.CreateReqOpts {
	o := smb.NewCreateReqOpts()
	if access&contentAccess == 0 {
		o.DesiredAccess = access&metadataAccess | smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize
	}
	o.ShareAccess = share
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

func (v *proxyVFS) Create(_ context.Context, sess *server.Session, req server.CreateRequest) (result server.CreateResult, status uint32, err error) {
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
		h.info.FileID = v.fileID("")
		return server.CreateResult{Handle: h, CreateAction: smb.FileOpened, Info: h.info}, 0, nil
	}
	if hasDotDot(rel) {
		// Keep the mapping's base directory a boundary: no traversal above it.
		return server.CreateResult{}, smb.StatusAccessDenied, nil
	}
	remote := joinRemote(v.base, rel)
	if writeIntent(req) && v.canWrite != nil && sess != nil && v.canWrite(sess) {
		return v.createForWrite(req, rel, remote)
	}

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
			upFile, e = c.OpenFileExt(v.share, remote, openFileOpts(req.DesiredAccess, req.ShareAccess))
			if e != nil {
				// It may be a directory the file open could not reach. If the
				// target says it is not one, the file open's own failure (a
				// sharing violation, say) is the answer.
				f, de := c.OpenFileExt(v.share, remote, openDirOpts())
				if code, ok := ntStatus(de); !ok || code != smb.StatusNotADirectory {
					upFile, e = f, de
				}
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
	h.info.FileID = v.fileID(rel)
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
	data, fErr := v.fetch(ph.file, offset, ph.size())
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
func (h *proxyHandle) setCache(off int64, data []byte) {
	h.cacheMu.Lock()
	old := h.cacheData
	h.cacheOff, h.cacheData = off, data
	h.cacheMu.Unlock()
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
		ctx, cancel := v.up.ioContext()
		rn, rErr := file.ReadFile(ctx, upBuf[totalN:], uint64(off)+uint64(totalN))
		cancel()
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
		readBufPool.Put((*[readAheadSize]byte)(b[:cap(b)]))
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
	size := ph.size()
	if off >= size {
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
		p.data, p.err = v.fetch(file, off, size)
	}()
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
				raw, err = queryDirAll(v.up, ph.file, pattern)
			}()
		}

		if err != nil && !errors.Is(err, smb.StatusMap[smb.StatusNoMoreFiles]) {
			return nil, errToStatus(err), nil
		}

		dirRel := remotePath(ph.Path())
		converted := make([]server.DirEntry, 0, len(raw)+2)
		if pattern == "*" {
			converted = append(converted, dotEntries(ph, dirRel, v.fileID)...)
		}
		for _, sf := range raw {
			if sf.Name == "." || sf.Name == ".." {
				continue // already added, or filtered out by pattern
			}
			e := sharedFileToDirEntry(sf)
			e.FileID = v.fileID(entryRel(dirRel, sf.Name))
			converted = append(converted, e)
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

// dotEntries returns the "." and ".." entries that Windows servers and Samba
// list first in every directory, the share root included. go-smb's client
// drops them from the target's replies, so the proxy adds its own; without
// them an empty directory lists as STATUS_NO_SUCH_FILE, which some clients,
// such as newer smbclient versions, report as an error. Both carry the
// directory's own metadata: what clients use them for is their presence,
// and the parent's would cost a round trip to the target.
func dotEntries(ph *proxyHandle, dirRel string, fileID func(string) uint64) []server.DirEntry {
	info, _ := ph.Stat()
	info.Attributes |= server.FileAttributeDirectory
	now := time.Now()
	info.CreationTime = fixTime(info.CreationTime, now)
	info.LastAccessTime = fixTime(info.LastAccessTime, now)
	info.LastWriteTime = fixTime(info.LastWriteTime, now)
	info.ChangeTime = fixTime(info.ChangeTime, now)
	dot, dotdot := info, info
	dot.Name, dot.FileID = ".", fileID(entryRel(dirRel, "."))
	dotdot.Name, dotdot.FileID = "..", fileID(entryRel(dirRel, ".."))
	return []server.DirEntry{{FileInfo: dot}, {FileInfo: dotdot}}
}

// queryDirAll lists every entry of the open directory f matching pattern. One
// upstream QUERY_DIRECTORY returns only as many entries as fit its output
// buffer, so it keeps asking until the target reports no more files. The first
// request always restarts the scan: a handle that was listed before (or under
// another pattern) has an exhausted upstream enumeration that would otherwise
// yield nothing. Each request is bounded by u's I/O timeout. The caller must
// hold u.mu.
func queryDirAll(u *upstream, f upstreamFile, pattern string) ([]smb.SharedFile, error) {
	var all []smb.SharedFile
	flags := smb.RestartScans
	for {
		ctx, cancel := u.ioContext()
		batch, err := f.QueryDirectory(ctx, pattern, flags, 0, 65536)
		cancel()
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

// QueryFileInfo mostly returns StatusNotSupported on purpose: the library then
// serializes the info class from the handle's Stat() snapshot, which already
// holds the target's real metadata (size, attributes, all four timestamps)
// captured when the file was opened. go-smb exposes no raw per-class file-info
// query to forward, and the snapshot is current for Explorer's Properties,
// which opens a fresh handle before querying.
//
// It answers, from the same snapshot, the classes Windows clients need that
// the library's fallback cannot serialize:
//   - FileInternalInformation (the file ID), which Win32
//     GetFileInformationByHandle queries; applications such as Notepad fail
//     to open a file when it is unsupported.
//   - FileStreamInformation: a file's single unnamed data stream. Alternate
//     data streams are not enumerated, though they can still be opened by name.
func (v *proxyVFS) QueryFileInfo(_ context.Context, h server.Handle, class byte) (any, uint32, error) {
	switch class {
	case smb.FileInternalInformation:
		info, _ := h.Stat()
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, info.FileID)
		return buf, smb.StatusOk, nil
	case smb.FileStreamInformation:
		if h.IsDir() {
			return []byte{}, smb.StatusOk, nil // a directory has no unnamed data stream
		}
		info, _ := h.Stat()
		return streamInfo(info), smb.StatusOk, nil
	}
	return nil, smb.StatusNotSupported, nil
}

// streamInfo serializes a FILE_STREAM_INFORMATION list (MS-FSCC 2.4.43)
// holding the file's unnamed data stream, "::$DATA".
func streamInfo(info server.FileInfo) []byte {
	name := utf16.Encode([]rune("::$DATA"))
	buf := make([]byte, 24+2*len(name))
	// NextEntryOffset (0 = last entry) stays zero.
	binary.LittleEndian.PutUint32(buf[4:], uint32(2*len(name)))
	binary.LittleEndian.PutUint64(buf[8:], uint64(info.Size))
	binary.LittleEndian.PutUint64(buf[16:], uint64(info.AllocationSize))
	for i, c := range name {
		binary.LittleEndian.PutUint16(buf[24+2*i:], c)
	}
	return buf
}

// fileID returns a stable, nonzero ID for the file at the client-relative path
// rel ("" for the share root), for FileInternalInformation and the FileId of
// directory entries. go-smb does not expose the target's own file IDs, so it
// is a hash of the share-relative remote path, case-folded as Windows paths
// are case-insensitive. The same file thus reports the same ID from every
// handle and listing, which clients use to tell files apart.
func (v *proxyVFS) fileID(rel string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(v.share + "\\" + joinRemote(v.base, rel))))
	if id := h.Sum64(); id != 0 {
		return id
	}
	return 1
}

// entryRel returns the client-relative path of the entry named name in the
// directory at dirRel, resolving the "." and ".." entries to the directory
// itself and its parent.
func entryRel(dirRel, name string) string {
	switch name {
	case ".":
		return dirRel
	case "..":
		if parent, _, ok := strings.CutLast(dirRel, `\`); ok {
			return parent
		}
		return ""
	}
	return joinRemote(dirRel, name)
}

// Filesystem information classes answered by QueryFSInfo (MS-FSCC 2.5).
const (
	fsVolumeInformation     = 0x01
	fsSizeInformation       = 0x03
	fsDeviceInformation     = 0x04
	fsAttributeInformation  = 0x05
	fsFullSizeInformation   = 0x07
	fsObjectIDInformation   = 0x08
	fsSectorSizeInformation = 0x0b
)

// fsSizes are the sizes of the fixed-size structures of the classes passed
// through from the target: the only part of its reply passed on.
var fsSizes = map[byte]int{fsSizeInformation: 24, fsFullSizeInformation: 32, fsSectorSizeInformation: 28}

// fsQueryBuffer is the reply size the target is allowed: enough for every
// class passed through, FileFsAttributeInformation's file system name
// included.
const fsQueryBuffer = 512

// fsProxiedAttributes are the FileFsAttributeInformation flags passed on from
// the target: those describing names and ACLs, which the proxy passes through
// as they are. FILE_PERSISTENT_ACLS is what makes Explorer show the Security
// tab. The others announce operations the proxy does not carry (compression,
// sparse files, reparse points, quotas, encryption, named streams, object
// IDs, transactions...), so a client must not count on them.
const fsProxiedAttributes = 0x00000001 | // FILE_CASE_SENSITIVE_SEARCH
	0x00000002 | // FILE_CASE_PRESERVED_NAMES
	0x00000004 | // FILE_UNICODE_ON_DISK
	0x00000008 // FILE_PERSISTENT_ACLS

// fsBytesPerSector is the sector size assumed when a target reports none.
const fsBytesPerSector = 512

// fsCacheTTL is how long a target's volume information is reused. Explorer
// asks for it several times in a row when it shows a drive.
const fsCacheTTL = 2 * time.Second

// QueryFSInfo answers the filesystem classes Windows clients query. The volume
// sizes (Explorer's drive size and free space, and the free space checked
// before a copy) and sector sizes come from the target's volume holding the
// mapped folder, including any quota the target applies to its account. The
// other classes are ones go-smb's fallback cannot serialize, or serializes
// unsafely, answered with synthetic but self-consistent values; the rest
// (attribute information) are left to that fallback.
func (v *proxyVFS) QueryFSInfo(_ context.Context, class byte) (any, uint32, error) {
	le := binary.LittleEndian
	switch class {
	case fsSizeInformation, fsFullSizeInformation, fsSectorSizeInformation:
		var buf []byte
		var err error
		if class == fsSectorSizeInformation {
			buf, err = v.sectorSize()
		} else {
			buf, err = v.volumeInfo(class)
		}
		if err != nil {
			status := errToStatus(err)
			if status == smb.StatusNotSupported {
				// Not a fallback to go-smb's invented sizes: those are what
				// this replaces.
				status = statusInvalidDeviceRequest
			}
			return nil, status, nil
		}
		return buf, smb.StatusOk, nil
	case fsAttributeInformation:
		buf, err := v.volumeInfo(class)
		if err != nil {
			// go-smb's fallback: NTFS, preserving case, without ACLs.
			return nil, smb.StatusNotSupported, nil
		}
		buf = bytes.Clone(buf)
		le.PutUint32(buf, le.Uint32(buf)&fsProxiedAttributes)
		return buf, smb.StatusOk, nil
	case fsVolumeInformation:
		// go-smb's fallback appends the share name as the volume label and
		// never trims a reply to the client's OutputBufferLength, which this
		// method is not told. Win32 GetFileInformationByHandle asks with a
		// 24-byte buffer, the bare structure size, and rejects a longer reply,
		// so Notepad, among others, fails to open any file. With an empty
		// label the reply is the 18-byte fixed part, which always fits.
		buf := make([]byte, 18)
		// VolumeCreationTime stays zero; the serial number is per share, so
		// two shares never look like one volume.
		copy(buf[8:12], v.objectID("")[16:20])
		// VolumeLabelLength 0, SupportsObjects 0 (no label follows).
		return buf, smb.StatusOk, nil
	case fsDeviceInformation:
		buf := make([]byte, 8)
		le.PutUint32(buf[0:], 0x00000007) // DeviceType: FILE_DEVICE_DISK
		le.PutUint32(buf[4:], 0x00000020) // Characteristics: FILE_DEVICE_IS_MOUNTED
		return buf, smb.StatusOk, nil
	case fsObjectIDInformation:
		// ObjectId is the volume ID objectID reports as BirthVolumeId;
		// ExtendedInfo (48 bytes) stays zero.
		buf := make([]byte, 64)
		copy(buf, v.objectID("")[16:32])
		return buf, smb.StatusOk, nil
	}
	return nil, smb.StatusNotSupported, nil
}

// sectorSize returns FileFsSectorSizeInformation from the target. A target
// without it (SMB 2 servers before Windows 8, older Samba) is not asked again;
// the reply is then built from the sector size the target reports in its
// FileFsSizeInformation, so every class describes the same volume.
func (v *proxyVFS) sectorSize() ([]byte, error) {
	v.fsMu.Lock()
	noSectorInfo := v.noSectorInfo
	v.fsMu.Unlock()
	if !noSectorInfo {
		buf, err := v.volumeInfo(fsSectorSizeInformation)
		if !classRefused(err) {
			return buf, err
		}
		v.fsMu.Lock()
		v.noSectorInfo = true
		v.fsMu.Unlock()
	}
	size, err := v.volumeInfo(fsSizeInformation)
	if err != nil {
		return nil, err
	}
	return sectorSizeInfo(binary.LittleEndian.Uint32(size[20:])), nil
}

// classRefused reports whether err is a target's refusal of an information
// class it does not implement.
func classRefused(err error) bool {
	code, ok := ntStatus(err)
	return ok && (code == smb.StatusNotSupported || code == statusInvalidInfoClass || code == smb.StatusInvalidParameter)
}

// sectorSizeInfo builds FileFsSectorSizeInformation for a volume with
// bytesPerSector-byte sectors, aligned on its device.
func sectorSizeInfo(bytesPerSector uint32) []byte {
	if bytesPerSector == 0 {
		bytesPerSector = fsBytesPerSector
	}
	buf := make([]byte, 28)
	for i := range 4 { // logical, physical (atomicity, performance), effective
		binary.LittleEndian.PutUint32(buf[4*i:], bytesPerSector)
	}
	binary.LittleEndian.PutUint32(buf[16:], 0x00000003) // SSINFO_FLAGS_ALIGNED_DEVICE | _PARTITION_ALIGNED_ON_DEVICE
	return buf
}

// volumeInfo returns a filesystem information class from the target: the
// reply to querying the mapped folder, cut to the class's structure (see
// fsLength), and reused for fsCacheTTL. QUERY_INFO needs an open handle, so the folder is
// opened for attributes alone and closed again.
func (v *proxyVFS) volumeInfo(class byte) ([]byte, error) {
	v.fsMu.Lock()
	defer v.fsMu.Unlock()
	if c, ok := v.fsCache[class]; ok && time.Since(c.at) < fsCacheTTL {
		return c.buf, nil
	}

	var buf []byte
	err := v.up.do(func(c upstreamConn) error {
		o := openDirOpts()
		o.DesiredAccess = smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize
		f, err := c.OpenFileExt(v.share, v.base, o)
		if err != nil {
			return err
		}
		defer func() { _ = f.CloseFile() }()
		buf, err = f.QueryFSInfo(class, fsQueryBuffer)
		return err
	})
	if err != nil {
		return nil, err
	}
	n := fsLength(class, buf)
	if n < 0 {
		return nil, fmt.Errorf("target answered FS info class 0x%02x with a short reply (%d bytes)", class, len(buf))
	}
	buf = buf[:n]
	if v.fsCache == nil {
		v.fsCache = make(map[byte]fsCached)
	}
	v.fsCache[class] = fsCached{at: time.Now(), buf: buf}
	return buf, nil
}

// fsLength returns the length of the class's structure at the start of buf,
// or -1 if buf is too short to hold it.
func fsLength(class byte, buf []byte) int {
	n := fsSizes[class]
	if class == fsAttributeInformation {
		// FileSystemAttributes, MaximumComponentNameLength,
		// FileSystemNameLength, then the name.
		if len(buf) < 12 {
			return -1
		}
		n = 12 + int(binary.LittleEndian.Uint32(buf[8:]))
	}
	if n == 0 || n > len(buf) {
		return -1
	}
	return n
}

// QuerySecurity proxies the client's request for a file's security descriptor
// (the Explorer "Security" tab: real owner, group and ACLs) through to the
// target. It operates on the already-open handle like Read/QueryDirectory, so
// it does not redial on a transport error. The synthetic root has no handle on
// the target: its descriptor is the mapped folder's (see rootSecurity). On
// anything that leaves no real descriptor — a closed handle, or an upstream
// error — it returns StatusNotSupported so the library falls back to its
// default descriptor and Properties still opens.
func (v *proxyVFS) QuerySecurity(_ context.Context, h server.Handle, additionalInformation uint32) (buf []byte, status uint32, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] QuerySecurity panic: %v\n%s", r, debug.Stack())
			buf, status, err = nil, smb.StatusNotSupported, nil
		}
	}()

	ph := h.(*proxyHandle)
	if ph.isRoot {
		sd, err := v.rootSecurity(additionalInformation)
		if err != nil {
			log.Printf("[proxy] QuerySecurity of the mapped folder: upstream error: %v", err)
			return nil, smb.StatusNotSupported, nil
		}
		return sd, smb.StatusOk, nil
	}
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

// rootSecurity returns the security descriptor of the mapped folder, the
// share's root, opening it on the target for reading its descriptor alone.
func (v *proxyVFS) rootSecurity(additionalInformation uint32) ([]byte, error) {
	var sd []byte
	err := v.up.do(func(c upstreamConn) error {
		o := openDirOpts()
		o.DesiredAccess = smb.FAccMaskReadControl | smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize
		f, err := c.OpenFileExt(v.share, v.base, o)
		if err != nil {
			return err
		}
		defer func() { _ = f.CloseFile() }()
		sd, err = f.QuerySecurity(additionalInformation)
		return err
	})
	return sd, err
}

// FSCTL codes answered by Ioctl (MS-FSCC 2.3).
const (
	fsctlGetObjectID         = 0x0009009c
	fsctlCreateOrGetObjectID = 0x000900c0
)

// Ioctl answers the object-ID FSCTLs and refuses the rest. Windows asks for a
// file's object ID (for distributed link tracking) when the shell hands a
// file to an application such as Notepad, and the open can fail when it is
// unsupported. go-smb cannot forward FSCTLs to the target, so, like Samba,
// the ID is synthesized: stable for a given file and distinct between files.
func (v *proxyVFS) Ioctl(_ context.Context, h server.Handle, ctlCode uint32, _ []byte, maxOut uint32) ([]byte, uint32, error) {
	switch ctlCode {
	case fsctlGetObjectID, fsctlCreateOrGetObjectID:
		if maxOut < 64 {
			return nil, smb.StatusBufferTooSmall, nil
		}
		return v.objectID(h.Path()), smb.StatusOk, nil
	}
	return nil, smb.StatusNotSupported, nil
}

// objectID serializes a FILE_OBJECTID_BUFFER (MS-FSCC 2.1.3.1) for the file at
// the client path p: ObjectId and BirthObjectId are a 128-bit hash of the
// file's location on the target, BirthVolumeId one of the target share, and
// DomainId is zero.
func (v *proxyVFS) objectID(p string) []byte {
	volume := strings.ToLower(v.up.t.addr() + "\\" + v.share)
	file := volume + "\\" + strings.ToLower(joinRemote(v.base, remotePath(p)))
	sum := func(s string) []byte {
		h := fnv.New128a()
		h.Write([]byte(s))
		return h.Sum(nil)
	}
	buf := make([]byte, 64)
	copy(buf[0:], sum(file))
	copy(buf[16:], sum(volume))
	copy(buf[32:], buf[0:16])
	return buf
}
