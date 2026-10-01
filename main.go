// smbproxy: local SMB server that authenticates upstream using NTLM credential
// hashes, exposing remote Windows shares to local SMB clients.
//
// Architecture:
//   Windows Explorer → [local SMB server (this tool)] → [target(s), NTLM auth]
//
// Multiple upstream shares can be proxied simultaneously. Mappings that share
// the same (host, user, domain, credential) tuple reuse a single upstream SMB
// connection; different credentials get separate connections.
//
// Build:
//   go mod tidy && go build -o smbproxy .
//
// Usage (single share):
//   sudo ./smbproxy \
//     -map "share:10.0.0.5:C$:Administrator:CORP:8846f7eaee8fb117ad06bdd830b7586c"
//
// Usage (multiple shares, possibly across multiple hosts):
//   sudo ./smbproxy \
//     -map "corp_c:10.0.0.5:C$:Administrator:CORP:8846...86c" \
//     -map "corp_d:10.0.0.5:D$:Administrator:CORP:8846...86c" \
//     -map "dev:10.0.0.6:Builds:svc_build:CORP:aad3...04ee:dead...beef"
//
// The credential field accepts either 32 hex chars (NTLM hash) or the
// "lmhash:nthash" pair format — only the NT half is used for authentication.
//
// Connect from Explorer:  \\<this-host>\<local-share-name>
// Map a drive:            net use Z: \\<this-host>\corp_c /user:guest guest

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcesrv "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

// ---------------------------------------------------------------------------
// Flag helpers
// ---------------------------------------------------------------------------

// multiFlag is a repeatable string flag.
type multiFlag []string

func (f *multiFlag) String() string     { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(s string) error { *f = append(*f, s); return nil }

// ---------------------------------------------------------------------------
// Mapping — one proxied share
// ---------------------------------------------------------------------------

// mapping describes a single local-share → remote-share binding.
type mapping struct {
	localShare  string // name exposed to clients (e.g. "corp_c")
	remoteHost  string // target IP or hostname
	remoteShare string // share on the target (e.g. "C$")
	user        string
	domain      string
	hashArg     string // raw credential value from -map (32 hex or lm:nt pair)
	ntHex       string // normalised 32-char NTLM hash (lowercase)
}

// parseMapping parses one -map value: local:host:share:user:domain:hash
// SplitN with n=6 keeps any colon inside the hash field intact.
func parseMapping(s string) (mapping, error) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 {
		return mapping{}, fmt.Errorf(
			"-map value must be local_share:host:share:user:domain:hash, got %q", s)
	}
	for i, p := range parts[:5] {
		if p == "" {
			return mapping{}, fmt.Errorf(
				"-map field %d is empty in %q", i, s)
		}
	}
	ntHex := parts[5]
	if idx := strings.LastIndexByte(ntHex, ':'); idx >= 0 {
		ntHex = ntHex[idx+1:] // strip the LM-hash prefix
	}
	ntHex = strings.ToLower(ntHex)
	if len(ntHex) != 32 {
		return mapping{}, fmt.Errorf(
			"NTLM credential hash must be 32 hex chars; got %d chars in %q", len(ntHex), parts[5])
	}
	if _, err := hex.DecodeString(ntHex); err != nil {
		return mapping{}, fmt.Errorf("invalid NTLM credential hash in %q: %w", s, err)
	}
	return mapping{
		localShare:  parts[0],
		remoteHost:  parts[1],
		remoteShare: parts[2],
		user:        parts[3],
		domain:      parts[4],
		hashArg:     parts[5],
		ntHex:       ntHex,
	}, nil
}

// connKey identifies a unique upstream SMB session.
type connKey struct{ host, user, domain, ntHex string }

func (m mapping) key() connKey {
	return connKey{m.remoteHost, m.user, m.domain, m.ntHex}
}

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

// readAheadSize is the upstream batch size for the cache and prefetch.
// Matches MaxReadSize in ServerConfig so one client READ → one upstream batch.
const readAheadSize = 8 << 20 // 8 MiB

// ---------------------------------------------------------------------------
// upstream — shared connection + mutex
//
// Multiple proxyVFS instances that point to the same (host, user, hash) share
// one *upstream so that all their upstream calls are serialised by a single
// mutex rather than each VFS thinking it has exclusive access to the conn.
// ---------------------------------------------------------------------------

type upstream struct {
	conn *smb.Connection
	mu   sync.Mutex
}

// ---------------------------------------------------------------------------
// proxyHandle — implements server.Handle
// ---------------------------------------------------------------------------

type proxyHandle struct {
	info   server.FileInfo
	path   server.Path
	isDir  bool
	file   *smb.File
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

func (v *proxyVFS) Create(ctx context.Context, _ *server.Session, req server.CreateRequest) (result server.CreateResult, status uint32, err error) {
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

	var upFile *smb.File
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
			serve := avail
			if serve > need {
				serve = need
			}
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

		serve := len(data)
		if serve > need {
			serve = need
		}
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

	serve := totalN
	if serve > need {
		serve = need
	}
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

// ---------------------------------------------------------------------------
// Extended srvsvc service
//
// The library's srvsvc.Service only handles NetShareEnumAll (opnum 15).
// Windows Explorer calls NetServerGetInfo (opnum 21) first when browsing
// \\host\ — without a valid response the library returns a DCE/RPC fault
// and Explorer shows "The remote procedure call failed and didn't execute".
//
// extSrvsvcService wraps the base service, intercepts opnum 21, and
// delegates everything else to the inner handler.
// ---------------------------------------------------------------------------

type extSrvsvcService struct {
	inner      *srvsvc.Service
	serverName string
}

func (e *extSrvsvcService) InterfaceUUID() string              { return e.inner.InterfaceUUID() }
func (e *extSrvsvcService) InterfaceVersion() (uint16, uint16) { return e.inner.InterfaceVersion() }

func (e *extSrvsvcService) Dispatch(ctx context.Context, opnum uint16, in []byte) ([]byte, error) {
	if opnum == mssrvs.SrvSvcOpNetServerGetInfo {
		return e.handleNetServerGetInfo(in)
	}
	return e.inner.Dispatch(ctx, opnum, in)
}

// handleNetServerGetInfo responds to NetrServerGetInfo (opnum 21).
// Explorer uses this to learn the server type before calling NetShareEnumAll.
// We return a minimal SERVER_INFO_101 (or 100 if explicitly requested)
// advertising a generic Windows NT workstation/server — enough for Explorer
// to proceed and call NetShareEnumAll next.
func (e *extSrvsvcService) handleNetServerGetInfo(in []byte) ([]byte, error) {
	var req mssrvs.NetServerGetInfoRequest
	if err := req.Unmarshal(in); err != nil {
		return nil, fmt.Errorf("srvsvc NetServerGetInfo decode: %w", err)
	}

	level := req.Level
	if level != 100 && level != 101 {
		level = 101 // default for unknown levels
	}
	const (
		platformNT = uint32(500)    // PLATFORM_ID_NT
		svType     = uint32(0x9003) // SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_SERVER_NT
	)
	name := e.serverName
	res := mssrvs.NetServerGetInfoResponse{WindowsError: mssrvs.ErrorSuccess}
	switch level {
	case 100:
		res.Info = mssrvs.ServerInfoUnion{
			Level:    100,
			Level100: &mssrvs.NetServerInfo100{PlatformId: platformNT, Name: name},
		}
	default: // 101
		res.Info = mssrvs.ServerInfoUnion{
			Level: 101,
			Level101: &mssrvs.NetServerInfo101{
				PlatformId:   platformNT,
				Name:         name,
				VersionMajor: 5,
				VersionMinor: 2,
				SvType:       svType,
				Comment:      "",
			},
		}
	}
	return res.Marshal()
}

// ---------------------------------------------------------------------------
// noopVFS — placeholder VFS for the IPC$ pipe share
//
// The server auto-creates IPC$ with VFS=nil. If any code path calls
// tree.Share.VFS.SomeMethod() on the IPC$ tree (e.g. queryFileInfo when
// Explorer sends QUERY_INFO on a pipe handle), a nil dereference panic
// occurs. Registering IPC$ explicitly with noopVFS gives the server a
// non-nil VFS that returns StatusNotSupported for every call, so the
// server falls through to its Stat()-driven default instead of panicking.
// ---------------------------------------------------------------------------

type noopVFS struct{}

func (v *noopVFS) Create(_ context.Context, _ *server.Session, _ server.CreateRequest) (server.CreateResult, uint32, error) {
	return server.CreateResult{}, smb.StatusObjectNameNotFound, nil
}
func (v *noopVFS) Close(_ context.Context, _ server.Handle) error { return nil }
func (v *noopVFS) Read(_ context.Context, _ server.Handle, _ int64, _ []byte) (int, uint32, error) {
	return 0, smb.StatusAccessDenied, nil
}
func (v *noopVFS) Write(_ context.Context, _ server.Handle, _ int64, _ []byte) (int, uint32, error) {
	return 0, smb.StatusAccessDenied, nil
}
func (v *noopVFS) Flush(_ context.Context, _ server.Handle) (uint32, error) { return 0, nil }
func (v *noopVFS) QueryDirectory(_ context.Context, _ server.Handle, _ string, _ bool) ([]server.DirEntry, uint32, error) {
	return nil, smb.StatusNoMoreFiles, nil
}
func (v *noopVFS) QueryFileInfo(_ context.Context, _ server.Handle, _ byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}
func (v *noopVFS) SetFileInfo(_ context.Context, _ server.Handle, _ byte, _ []byte) (uint32, error) {
	return smb.StatusAccessDenied, nil
}
func (v *noopVFS) QueryFSInfo(_ context.Context, _ byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}
func (v *noopVFS) QuerySecurity(_ context.Context, _ server.Handle, _ uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}
func (v *noopVFS) Ioctl(_ context.Context, _ server.Handle, _ uint32, _ []byte, _ uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// ---------------------------------------------------------------------------
// rpcPipe — PipeBackend wrapper adding DCE/RPC auth handling and a WRITE/READ
// transport on top of the library's Transceive-only dcesrv.PipeHandler.
// See the type doc below for details.
// ---------------------------------------------------------------------------

// DCE/RPC common-header packet types (MS-RPCE §2.2.2.4)
const (
	rpcTypeBind         = 11 // PacketTypeBind
	rpcTypeAlterContext = 14 // PacketTypeAlterContext
	rpcTypeAuth3        = 16 // PacketTypeAuth3
	rpcTypeRequest      = 0  // PacketTypeRequest
)

// stripRPCAuth removes the auth_verifier from a DCE/RPC PDU and updates
// the common header fields (FragLength, AuthLength) to match.
func stripRPCAuth(pdu []byte) []byte {
	if len(pdu) < 16 {
		return pdu
	}
	authLen := int(pdu[10]) | int(pdu[11])<<8 // bytes 10-11 LE
	if authLen == 0 {
		return pdu
	}
	fragLen := int(pdu[8]) | int(pdu[9])<<8 // bytes 8-9 LE
	if fragLen > len(pdu) {
		fragLen = len(pdu)
	}
	// The sec_trailer occupies 8 bytes before the auth_value blob.
	// New PDU body ends at: fragLen - authLen - 8 (the sec_trailer size).
	newLen := fragLen - authLen - 8
	if newLen < 16 || newLen >= fragLen {
		return pdu // malformed
	}
	out := make([]byte, newLen)
	copy(out, pdu[:newLen])
	out[8] = byte(newLen)      // FragLength low
	out[9] = byte(newLen >> 8) // FragLength high
	out[10] = 0                // AuthLength low  → 0
	out[11] = 0                // AuthLength high → 0
	return out
}

// rpcPipe wraps dcesrv.PipeHandler and supplies two things it lacks.
//
// Auth: the inner handler rejects any BIND carrying an auth_verifier
// (AuthLength > 0). Windows attaches NTLMSSP to the srvsvc bind, so process()
// strips the verifier from BIND/ALTER_CONTEXT/REQUEST PDUs and absorbs the
// one-way AUTH_3, leaving the inner handler a clean bind it accepts.
//
// Transport: the inner handler only answers FSCTL_PIPE_TRANSCEIVE (one IOCTL
// round trip); its Write/Read return STATUS_NOT_SUPPORTED. Windows Explorer on
// the observed target instead drives srvsvc over separate SMB2 WRITE then READ,
// so every bind failed before this. Write accumulates whole PDUs and runs them
// through the same processing as Transceive; Read returns the queued response.
type rpcPipe struct {
	inner server.PipeBackend

	mu  sync.Mutex
	in  []byte // WRITE bytes accumulated until a full PDU is present
	out []byte // response bytes awaiting the client's READ
}

// process handles one complete inbound PDU and returns the inner handler's
// response. AUTH_3 is one-way, so it yields no response body.
func (p *rpcPipe) process(ctx context.Context, pdu []byte) ([]byte, uint32, error) {
	if len(pdu) >= 16 {
		switch pdu[2] { // PDU type byte
		case rpcTypeBind, rpcTypeAlterContext, rpcTypeRequest:
			pdu = stripRPCAuth(pdu)
		case rpcTypeAuth3:
			return nil, smb.StatusOk, nil
		}
	}
	return p.inner.Transceive(ctx, pdu)
}

func (p *rpcPipe) Transceive(ctx context.Context, in []byte) ([]byte, uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out, status, err := p.process(ctx, in)
	if out == nil {
		out = []byte{}
	}
	return out, status, err
}

// Write buffers inbound bytes and processes each complete DCE/RPC PDU, whose
// length is frag_length at header bytes 8-9. A short tail is kept until the
// rest of the fragment arrives. Responses queue in p.out for the next READ.
func (p *rpcPipe) Write(_ context.Context, b []byte) (int, uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(b)
	p.in = append(p.in, b...)
	for len(p.in) >= 16 {
		fragLen := int(p.in[8]) | int(p.in[9])<<8
		if fragLen < 16 || fragLen > len(p.in) {
			break // incomplete fragment (or malformed) — wait for more
		}
		pdu := p.in[:fragLen]
		p.in = p.in[fragLen:]
		out, status, err := p.process(context.Background(), pdu)
		if err != nil || status != smb.StatusOk {
			return n, status, err // surface the failure on the write
		}
		p.out = append(p.out, out...)
	}
	return n, smb.StatusOk, nil
}

// Read drains the queued response in one shot. The library discards the data
// whenever a pipe Read returns a non-OK status (see smb/server/read.go), so a
// message-mode partial read via StatusBufferOverflow is not possible here;
// srvsvc enum responses are small enough to always fit a single client READ.
func (p *rpcPipe) Read(_ context.Context, _ int) ([]byte, uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.out
	p.out = nil
	return out, smb.StatusOk, nil
}

func (p *rpcPipe) Close(ctx context.Context) error { return p.inner.Close(ctx) }

// ---------------------------------------------------------------------------
// Upstream connection
// ---------------------------------------------------------------------------

// openUpstream dials the target and authenticates using the supplied NTLM credential hash.
func openUpstream(m mapping) (*upstream, error) {
	ntHex := m.hashArg
	if idx := strings.LastIndexByte(ntHex, ':'); idx >= 0 {
		ntHex = ntHex[idx+1:]
	}
	hashBytes, err := hex.DecodeString(ntHex)
	if err != nil {
		return nil, err
	}
	conn, err := smb.NewConnection(smb.Options{
		Host: m.remoteHost,
		Port: 445,
		// SMB2Only skips the SMB1 multi-protocol probe, sending a direct SMB2
		// NEGOTIATE that offers all dialects. The server picks the highest it
		// supports (typically 3.1.1 on modern Windows), which advertises
		// MaxReadSize = 8 MiB instead of the 64 KiB that SMB 2.1 returns.
		// This lets the cache fill in 1–2 upstream ReadFile calls rather than 128.
		SMB2Only: true,
		Initiator: &spnego.NTLMInitiator{
			User:   m.user,
			Domain: m.domain,
			Hash:   hashBytes,
		},
	})
	if err != nil {
		return nil, err
	}
	return &upstream{conn: conn}, nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	var maps multiFlag
	flag.Var(&maps, "map",
		"share mapping: local_share:host:remote_share:user:domain:credential\n"+
			"\t  credential = 32 hex chars (NTLM hash) OR lmhash:nthash pair\n"+
			"\t  repeat -map for multiple shares / multiple targets\n"+
			"\t  mappings with identical (host,user,domain,credential) share one upstream connection")

	listen := flag.String("l", "0.0.0.0:445", "local listen addr:port (port 445 needs root/CAP_NET_BIND_SERVICE)")
	localUser := flag.String("local-user", "guest", "username clients authenticate with")
	localPass := flag.String("local-pass", "guest", "password clients authenticate with")
	debugLog := flag.Bool("debug", false, "enable verbose go-smb debug logging (dialect, signing, session setup, DCE/RPC)")
	flag.Parse()

	// Verbose go-smb logging. Every go-smb package registers its own named
	// logger at init via golog.Get(...); SetAll raises the level on all of
	// them at once. Lshortfile adds file:line so a failing leg is easy to
	// trace. Without -debug the library stays at its default (Notice).
	if *debugLog {
		golog.SetAll(golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, os.Stdout, os.Stderr)
	}

	if len(maps) == 0 {
		flag.Usage()
		log.Fatal("\nat least one -map flag is required\n\n" +
			"Example:\n" +
			"  sudo ./smbproxy \\\n" +
			"    -map \"share:10.0.0.5:C$:Administrator:CORP:8846f7eaee8fb117ad06bdd830b7586c\"\n\n" +
			"Multiple shares:\n" +
			"  sudo ./smbproxy \\\n" +
			"    -map \"corp_c:10.0.0.5:C$:Administrator:CORP:8846...86c\" \\\n" +
			"    -map \"corp_d:10.0.0.5:D$:Administrator:CORP:8846...86c\" \\\n" +
			"    -map \"dev:10.0.0.6:Builds:svc_build:CORP:dead...beef\"")
	}

	// ---- Parse and validate all mappings ----
	mappings := make([]mapping, 0, len(maps))
	seen := map[string]bool{}
	for _, raw := range maps {
		m, err := parseMapping(raw)
		if err != nil {
			log.Fatalf("[!] invalid -map %q: %v", raw, err)
		}
		if seen[m.localShare] {
			log.Fatalf("[!] duplicate local share name %q", m.localShare)
		}
		seen[m.localShare] = true
		mappings = append(mappings, m)
	}

	// ---- Open upstream connections (deduplicated by connKey) ----
	upstreams := map[connKey]*upstream{}
	for _, m := range mappings {
		k := m.key()
		if _, ok := upstreams[k]; ok {
			continue // already connected with these credentials
		}
		log.Printf("[*] connecting to \\\\%s\\%s as %s\\%s ...",
			m.remoteHost, m.remoteShare, m.domain, m.user)
		up, err := openUpstream(m)
		if err != nil {
			log.Fatalf("[!] upstream connect \\\\%s as %s\\%s failed: %v\n"+
				"    STATUS_LOGON_FAILURE  → wrong credential\n"+
				"    STATUS_ACCESS_DENIED  → wrong credential or account restrictions\n"+
				"    'signing required'    → target mandates SMB signing; NTLM hash auth not supported",
				m.remoteHost, m.domain, m.user, err)
		}
		upstreams[k] = up
		log.Printf("[+] authenticated as %s\\%s on %s", m.domain, m.user, m.remoteHost)
	}
	defer func() {
		for _, up := range upstreams {
			up.conn.Close()
		}
	}()

	// ---- Build the local server ----
	auth := &server.MapAuthenticator{
		Accounts: map[string]*server.Account{
			strings.ToLower(*localUser): {NTHash: ntlmssp.Ntowfv1(*localPass)},
		},
	}

	cfg := &server.ServerConfig{
		NetBIOSName:    "SMBPROXY",
		MinDialect:     smb.DialectSmb_2_1,
		MaxDialect:     smb.DialectSmb_2_1,
		Authenticator:  auth,
		AllowAnonymous: true,
		MaxReadSize:    readAheadSize,
	}

	srv := &server.Server{Config: cfg}

	// ---- Register IPC$ with a no-op VFS ----
	// Without this the server auto-provides IPC$ with VFS=nil, which causes
	// a nil dereference panic in queryFileInfo when Explorer sends QUERY_INFO
	// on a pipe handle (e.g. during the initial IPC$ tree setup).
	srv.RegisterShare("IPC$", server.Share{
		Name: "IPC$",
		Type: smb.ShareTypePipe,
		VFS:  &noopVFS{},
	})

	// ---- Register each proxied share ----
	for _, m := range mappings {
		up := upstreams[m.key()]
		vfs := &proxyVFS{up: up, share: m.remoteShare}
		srv.RegisterShare(m.localShare, server.Share{
			Name:          m.localShare,
			Type:          smb.ShareTypeDisk,
			VFS:           vfs,
			MaximalAccess: 0x001f01ff,
		})
		log.Printf("[+] share \\\\<host>\\%s  →  \\\\%s\\%s  (as %s\\%s)",
			m.localShare, m.remoteHost, m.remoteShare, m.domain, m.user)
	}

	// ---- Wire srvsvc so Explorer can enumerate shares at \\host level ----
	// extSrvsvcService adds NetServerGetInfo (opnum 21) handling on top of
	// the library's NetShareEnumAll (opnum 15) so that browsing \\host\
	// works: Explorer calls opnum 21 first and would fault without it.
	shareEntries := srvsvc.FromConfig(cfg)
	innerSvc := &srvsvc.Service{Shares: shareEntries}
	extSvc := &extSrvsvcService{inner: innerSvc, serverName: cfg.NetBIOSName}
	cfg.PipeOpener = &server.MapPipeOpener{
		Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			"srvsvc": func(_ *server.Session) (server.PipeBackend, error) {
				return &rpcPipe{
					inner: dcesrv.NewPipeHandler("srvsvc", extSvc),
				}, nil
			},
		},
	}

	log.Printf("[*] listening on %s", *listen)
	log.Printf("[*] local credentials: user=%s  pass=%s", *localUser, *localPass)
	log.Printf("[*] browse \\\\<this-host>  or connect directly to \\\\<this-host>\\<share>")

	// ---- Graceful shutdown ----
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
