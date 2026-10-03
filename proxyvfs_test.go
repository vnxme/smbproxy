package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ---------------------------------------------------------------------------
// Fakes satisfying the upstreamConn / upstreamFile seams (see upstream.go).
// All mutable state is mutex-guarded so the async prefetch goroutine can read
// it without racing the test goroutine.
// ---------------------------------------------------------------------------

type fakeFile struct {
	mu      sync.Mutex
	data    []byte           // backing bytes served by ReadFile
	readErr error            // if set, ReadFile returns (0, readErr)
	reads   int              // ReadFile call count
	dirs    []smb.SharedFile // entries the directory enumeration yields
	dirPage int              // entries per QueryDirectory batch (0 = all in one)
	dirPos  int              // enumeration cursor into dirs
	dirErr  error            // if set, QueryDirectory returns it
	dirCall int              // QueryDirectory call count
	secData []byte           // security descriptor QuerySecurity returns
	secErr  error            // if set, QuerySecurity returns it
	secInfo uint32           // additionalInformation of the last QuerySecurity call
	stall   bool             // ReadFile and QueryDirectory block until their context ends

	writeErr     error                            // if set, WriteFile returns it
	flushes      int                              // Flush call count
	setInfoClass byte                             // class of the last SetInfo
	setInfoBuf   []byte                           // payload of the last SetInfo
	setInfoErr   error                            // if set, SetInfo returns it
	fsData       []byte                           // reply QueryFSInfo returns
	fsErr        error                            // if set, QueryFSInfo returns it
	fsFn         func(class byte) ([]byte, error) // if set, answers QueryFSInfo instead
	fsClass      byte                             // class of the last QueryFSInfo
	fsQueries    int                              // QueryFSInfo call count
	isDir        bool
	metaVal      fileMeta
	closed       bool
}

// waitStalled blocks until ctx is done when the fake is stalled, standing in
// for a target that stopped answering, and returns ctx's error; it returns nil
// at once otherwise.
func (f *fakeFile) waitStalled(ctx context.Context) error {
	f.mu.Lock()
	stalled := f.stall
	f.mu.Unlock()
	if !stalled {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeFile) ReadFile(ctx context.Context, b []byte, off uint64) (int, error) {
	if err := f.waitStalled(ctx); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.readErr != nil {
		return 0, f.readErr
	}
	if off >= uint64(len(f.data)) {
		return 0, io.EOF
	}
	return copy(b, f.data[off:]), nil
}

func (f *fakeFile) WriteFile(ctx context.Context, data []byte, off uint64) (int, error) {
	if err := f.waitStalled(ctx); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if end := int(off) + len(data); end > len(f.data) {
		f.data = append(f.data, make([]byte, end-len(f.data))...)
	}
	return copy(f.data[off:], data), nil
}

func (f *fakeFile) Flush(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	return nil
}

func (f *fakeFile) SetInfo(class byte, buf []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setInfoClass, f.setInfoBuf = class, append([]byte(nil), buf...)
	return f.setInfoErr
}

func (f *fakeFile) QueryDirectory(ctx context.Context, _ string, flags byte, _ uint32, _ uint32) ([]smb.SharedFile, error) {
	if err := f.waitStalled(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirCall++
	if flags&smb.RestartScans != 0 {
		f.dirPos = 0
	}
	if f.dirErr != nil {
		return nil, f.dirErr
	}
	// Like a real target: each call yields the next batch, and an exhausted
	// enumeration yields nothing until restarted.
	end := len(f.dirs)
	if f.dirPage > 0 {
		end = min(f.dirPos+f.dirPage, end)
	}
	batch := f.dirs[f.dirPos:end]
	f.dirPos = end
	return batch, nil
}

func (f *fakeFile) CloseFile() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeFile) QuerySecurity(additionalInformation uint32) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secInfo = additionalInformation
	if f.secErr != nil {
		return nil, f.secErr
	}
	return f.secData, nil
}

func (f *fakeFile) QueryFSInfo(class byte, _ uint32) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fsClass = class
	f.fsQueries++
	if f.fsFn != nil {
		return f.fsFn(class)
	}
	return f.fsData, f.fsErr
}

func (f *fakeFile) IsDir() bool    { return f.isDir }
func (f *fakeFile) meta() fileMeta { return f.metaVal }

func (f *fakeFile) setReadErr(err error) {
	f.mu.Lock()
	f.readErr = err
	f.mu.Unlock()
}

func (f *fakeFile) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

type fakeConn struct {
	mu         sync.Mutex
	openFn     func(tree, filepath string, opts *smb.CreateReqOpts) (upstreamFile, error)
	treeErr    error
	listResult []smb.SharedFile
	listErr    error
	listDir    string // dir arg of the most recent ListDirectory call
	opens      []string
	closed     bool
	lookupFn   func(sids []string) (mslsad.SidTranslations, error) // answers LookupSids
	lookups    [][]string                                          // the SIDs of each LookupSids call
}

func (c *fakeConn) OpenFileExt(tree, filepath string, opts *smb.CreateReqOpts) (upstreamFile, error) {
	c.mu.Lock()
	c.opens = append(c.opens, filepath)
	c.mu.Unlock()
	if c.openFn != nil {
		return c.openFn(tree, filepath, opts)
	}
	return nil, smb.StatusMap[smb.StatusObjectNameNotFound]
}

func (c *fakeConn) TreeConnect(string) error { return c.treeErr }

func (c *fakeConn) LookupSids(sids []string) (mslsad.SidTranslations, error) {
	c.mu.Lock()
	c.lookups = append(c.lookups, sids)
	c.mu.Unlock()
	if c.lookupFn == nil {
		return mslsad.SidTranslations{}, &dcerpc.StatusError{Code: mslsad.StatusNoneMapped}
	}
	return c.lookupFn(sids)
}

func (c *fakeConn) ListDirectory(_, dir, _ string) ([]smb.SharedFile, error) {
	c.mu.Lock()
	c.listDir = dir
	c.mu.Unlock()
	return c.listResult, c.listErr
}

func (c *fakeConn) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func newVFS(c *fakeConn) *proxyVFS {
	return &proxyVFS{up: &upstream{t: testTarget(), conn: c}, share: "C$"}
}

// fileHandle returns an open-file handle on ff whose size, as captured at open
// time, is that of ff's data, so reads are clamped and prefetched against it.
func fileHandle(ff *fakeFile) *proxyHandle {
	return &proxyHandle{file: ff, info: server.FileInfo{Size: int64(len(ff.data))}}
}

// drainPrefetch blocks until any in-flight prefetch goroutine has finished, so
// a test can mutate the fake without racing it.
func drainPrefetch(ph *proxyHandle) {
	ph.prefWG.Wait()
}

// ---------------------------------------------------------------------------
// Handle accessors and handleFromFile
// ---------------------------------------------------------------------------

func TestProxyHandleAccessors(t *testing.T) {
	h := &proxyHandle{info: server.FileInfo{Name: "z"}, path: "\\z", isDir: true}
	if st, err := h.Stat(); err != nil || st.Name != "z" {
		t.Errorf("Stat = (%+v, %v), want name z", st, err)
	}
	if h.Path() != "\\z" {
		t.Errorf("Path = %q, want \\z", h.Path())
	}
	if !h.IsDir() {
		t.Errorf("IsDir = false, want true")
	}
}

func TestHandleFromFileDefaultAttrs(t *testing.T) {
	// attributes == 0 is derived from IsDir.
	dir := handleFromFile(server.CreateRequest{Path: "\\d"}, &fakeFile{isDir: true}, "C$")
	if dir.info.Attributes != server.FileAttributeDirectory {
		t.Errorf("dir default attr = 0x%x, want FileAttributeDirectory", dir.info.Attributes)
	}
	file := handleFromFile(server.CreateRequest{Path: "\\f"}, &fakeFile{}, "C$")
	if file.info.Attributes != server.FileAttributeNormal {
		t.Errorf("file default attr = 0x%x, want FileAttributeNormal", file.info.Attributes)
	}
	// A path whose base is the root falls back to the share name.
	root := handleFromFile(server.CreateRequest{Path: "\\"}, &fakeFile{}, "SHARE")
	if root.info.Name != "SHARE" {
		t.Errorf("root-base name = %q, want SHARE", root.info.Name)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestProxyCreateSyntheticRoot(t *testing.T) {
	v := newVFS(&fakeConn{})
	res, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: "\\"})
	if err != nil || status != 0 {
		t.Fatalf("Create root: status=0x%08x err=%v", status, err)
	}
	ph := res.Handle.(*proxyHandle)
	if !ph.isRoot || !ph.isDir || ph.file != nil {
		t.Errorf("root handle = %+v, want isRoot && isDir && nil file", ph)
	}
	if res.Info.Name != "C$" || res.Info.Attributes != server.FileAttributeDirectory {
		t.Errorf("root info = %+v, want name C$ and directory attr", res.Info)
	}
}

func TestProxyCreateFileSuccess(t *testing.T) {
	ff := &fakeFile{metaVal: fileMeta{endOfFile: 1234, attributes: server.FileAttributeNormal}}
	c := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) {
		return ff, nil
	}}
	v := newVFS(c)

	res, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: "\\dir\\a.txt"})
	if err != nil || status != 0 {
		t.Fatalf("Create file: status=0x%08x err=%v", status, err)
	}
	if res.CreateAction != smb.FileOpened {
		t.Errorf("CreateAction = %d, want FileOpened", res.CreateAction)
	}
	ph := res.Handle.(*proxyHandle)
	if ph.file != upstreamFile(ff) || ph.info.Name != "a.txt" || ph.info.Size != 1234 {
		t.Errorf("handle info = %+v (file set=%v), want name a.txt size 1234", ph.info, ph.file != nil)
	}
	if c.opens[0] != "dir\\a.txt" {
		t.Errorf("opened remote path %q, want dir\\a.txt (leading backslash stripped)", c.opens[0])
	}
}

func TestProxyCreateOpenError(t *testing.T) {
	c := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) {
		return nil, smb.StatusMap[smb.StatusAccessDenied]
	}}
	v := newVFS(c)

	res, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: "\\secret"})
	if err != nil {
		t.Fatalf("Create: unexpected err %v", err)
	}
	if status != smb.StatusAccessDenied || res.Handle != nil {
		t.Errorf("Create = (handle=%v, 0x%08x), want (nil, StatusAccessDenied)", res.Handle, status)
	}
	// A non-dir open is retried once (file opts, then dir opts) before failing.
	if len(c.opens) != 2 {
		t.Errorf("OpenFileExt called %d times, want 2 (open + fallback)", len(c.opens))
	}
}

const statusSharingViolation uint32 = 0xc0000043 // STATUS_SHARING_VIOLATION

// A file the target refuses to open (here: held exclusively by another
// client) is reported with the target's reason, not with the "not a
// directory" from the directory retry that follows.
func TestProxyCreateKeepsFileOpenError(t *testing.T) {
	c := &fakeConn{openFn: func(_, _ string, opts *smb.CreateReqOpts) (upstreamFile, error) {
		if opts.CreateOpts&smb.FileDirectoryFile != 0 {
			return nil, &smb.NTStatusError{Status: smb.StatusNotADirectory}
		}
		return nil, &smb.NTStatusError{Status: statusSharingViolation}
	}}
	v := newVFS(c)

	_, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: "\\busy.pdf"})
	if err != nil || status != statusSharingViolation {
		t.Errorf("Create = (0x%08x, %v), want STATUS_SHARING_VIOLATION", status, err)
	}
}

// An open asking only for metadata opens the target file for metadata alone,
// so sharing modes cannot refuse it; any other read open asks for the data.
func TestProxyCreateTargetAccess(t *testing.T) {
	const defaultAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileReadEA |
		smb.FAccMaskFileReadAttributes | smb.FAccMaskReadControl | smb.FAccMaskSynchronize
	tests := []struct {
		name         string
		asked, wants uint32
	}{
		{"read attributes", smb.FAccMaskFileReadAttributes, smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize},
		{"security", smb.FAccMaskReadControl | smb.FAccMaskFileReadAttributes,
			smb.FAccMaskReadControl | smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize},
		{"nothing", 0, smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize},
		{"read data", 0x00120089, defaultAccess},
		{"generic read", smb.FAccMaskGenericRead, defaultAccess},
		{"maximum allowed", smb.FAccMaskMaximumAllowed, defaultAccess},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got uint32
			c := &fakeConn{openFn: func(_, _ string, opts *smb.CreateReqOpts) (upstreamFile, error) {
				got = opts.DesiredAccess
				return &fakeFile{}, nil
			}}
			req := server.CreateRequest{Path: "\\a.pdf", DesiredAccess: tt.asked}
			if _, status, err := newVFS(c).Create(context.Background(), nil, req); err != nil || status != 0 {
				t.Fatalf("Create: status=0x%08x err=%v", status, err)
			}
			if got != tt.wants {
				t.Errorf("target access = 0x%08x, want 0x%08x", got, tt.wants)
			}
		})
	}
}

// A file is opened on the target with the client's share mode; a directory
// is always fully shared, as its open asks for more than a client asking only
// for attributes.
func TestProxyCreateShareAccess(t *testing.T) {
	const all = smb.FileShareRead | smb.FileShareWrite | smb.FileShareDelete
	tests := []struct {
		name         string
		req          server.CreateRequest
		asked, wants uint32
	}{
		{"file, all", server.CreateRequest{DesiredAccess: 0x00120089}, all, all},
		{"file, read only", server.CreateRequest{DesiredAccess: 0x00120089}, smb.FileShareRead, smb.FileShareRead},
		{"file, exclusive", server.CreateRequest{DesiredAccess: 0x00120089}, 0, 0},
		{"directory", server.CreateRequest{DesiredAccess: 0x00100080, CreateOptions: smb.FileDirectoryFile}, 0, all},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got uint32
			c := &fakeConn{openFn: func(_, _ string, opts *smb.CreateReqOpts) (upstreamFile, error) {
				got = opts.ShareAccess
				return &fakeFile{}, nil
			}}
			req := tt.req
			req.Path, req.ShareAccess = `\x`, tt.asked
			if _, status, err := newVFS(c).Create(context.Background(), nil, req); err != nil || status != 0 {
				t.Fatalf("Create: status=0x%08x err=%v", status, err)
			}
			if got != tt.wants {
				t.Errorf("target share access = %d, want %d", got, tt.wants)
			}
		})
	}
}

func TestProxyCreateDirFallback(t *testing.T) {
	ff := &fakeFile{isDir: true, metaVal: fileMeta{attributes: server.FileAttributeDirectory}}
	var calls int
	c := &fakeConn{openFn: func(_, _ string, opts *smb.CreateReqOpts) (upstreamFile, error) {
		calls++
		// First attempt uses FileDirectoryFile and fails; the fallback clears
		// CreateOpts and succeeds.
		if opts.CreateOpts&smb.FileDirectoryFile != 0 {
			return nil, errors.New("dir open rejected")
		}
		return ff, nil
	}}
	v := newVFS(c)

	req := server.CreateRequest{Path: "\\somedir", CreateOptions: smb.FileDirectoryFile}
	res, status, err := v.Create(context.Background(), nil, req)
	if err != nil || status != 0 {
		t.Fatalf("Create dir: status=0x%08x err=%v", status, err)
	}
	if calls != 2 {
		t.Errorf("open attempts = %d, want 2", calls)
	}
	if ph := res.Handle.(*proxyHandle); !ph.isDir {
		t.Errorf("handle isDir = false, want true")
	}
}

// Create must transparently recover when the upstream link has dropped: the
// first open fails as a transport error, do() redials, and the retry succeeds.
func TestProxyCreateReconnects(t *testing.T) {
	ff := &fakeFile{metaVal: fileMeta{endOfFile: 5, attributes: server.FileAttributeNormal}}
	conn1 := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) {
		return nil, connDown
	}}
	conn2 := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) {
		return ff, nil
	}}
	u := &upstream{t: testTarget(), conn: conn1, dial: func() (upstreamConn, error) {
		return conn2, nil
	}}
	v := &proxyVFS{up: u, share: "C$"}

	res, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: "\\a.txt"})
	if err != nil || status != 0 {
		t.Fatalf("Create after drop = (0x%08x, %v), want success", status, err)
	}
	if res.Handle.(*proxyHandle).file != upstreamFile(ff) {
		t.Errorf("handle not backed by the reconnected file")
	}
}

// An open handle (Create) must pin the connection so the reaper cannot close it
// mid-use; Close must drop the pin so an idle connection is then reaped.
func TestProxyHandlePinsConnectionAgainstReap(t *testing.T) {
	ff := &fakeFile{metaVal: fileMeta{endOfFile: 3}}
	conn := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) {
		return ff, nil
	}}
	u := &upstream{t: testTarget(), conn: conn, idle: time.Minute,
		dial: func() (upstreamConn, error) { return conn, nil }}
	v := &proxyVFS{up: u, share: "C$"}
	ctx := context.Background()

	res, status, err := v.Create(ctx, nil, server.CreateRequest{Path: "\\a.txt"})
	if err != nil || status != 0 {
		t.Fatalf("Create = (0x%08x, %v), want success", status, err)
	}

	// Even far past the idle window, an open handle keeps the connection.
	u.mu.Lock()
	u.lastUse = time.Now().Add(-time.Hour)
	u.mu.Unlock()
	if u.reapIfIdle(time.Now()) || u.conn == nil {
		t.Errorf("connection reaped while a handle was open")
	}

	if err := v.Close(ctx, res.Handle); err != nil {
		t.Fatalf("Close: %v", err)
	}
	u.mu.Lock()
	u.lastUse = time.Now().Add(-time.Hour)
	u.mu.Unlock()
	if !u.reapIfIdle(time.Now()) || u.conn != nil {
		t.Errorf("connection not reaped after the handle closed")
	}
}

func TestProxyQueryDirectoryRootReconnects(t *testing.T) {
	conn1 := &fakeConn{treeErr: connDown}
	conn2 := &fakeConn{listResult: []smb.SharedFile{{Name: "f"}}}
	u := &upstream{t: testTarget(), conn: conn1, dial: func() (upstreamConn, error) {
		return conn2, nil
	}}
	v := &proxyVFS{up: u, share: "C$"}
	ph := &proxyHandle{isRoot: true, isDir: true}

	entries, status, err := v.QueryDirectory(context.Background(), ph, "*", false)
	if err != nil || status != 0 || len(entries) != 1 || entries[0].Name != "f" {
		t.Fatalf("root list after drop = (%d entries, 0x%08x, %v), want 1 entry 'f'", len(entries), status, err)
	}
}

// ---------------------------------------------------------------------------
// Inner-folder (base) mappings
// ---------------------------------------------------------------------------

// With a base set, a client path must be opened under base on the target, the
// synthetic root still represents the client root, and the root listing must
// enumerate base.
func TestProxyCreateWithBase(t *testing.T) {
	ff := &fakeFile{metaVal: fileMeta{endOfFile: 1}}
	c := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) {
		return ff, nil
	}}
	v := &proxyVFS{up: &upstream{t: testTarget(), conn: c}, share: "C$", base: "Users\\Public"}
	ctx := context.Background()

	if _, status, err := v.Create(ctx, nil, server.CreateRequest{Path: "\\sub\\a.txt"}); err != nil || status != 0 {
		t.Fatalf("Create under base = (0x%08x, %v), want success", status, err)
	}
	if c.opens[0] != "Users\\Public\\sub\\a.txt" {
		t.Errorf("opened %q, want Users\\Public\\sub\\a.txt (base prepended)", c.opens[0])
	}

	// The client root stays synthetic (no upstream open) even with a base.
	res, _, _ := v.Create(ctx, nil, server.CreateRequest{Path: "\\"})
	if ph := res.Handle.(*proxyHandle); !ph.isRoot || ph.file != nil {
		t.Errorf("root under base = %+v, want synthetic root with nil file", ph)
	}
	if len(c.opens) != 1 {
		t.Errorf("root open hit the upstream (%d opens total), want it served synthetically", len(c.opens))
	}
}

// A client path written with forward slashes must be normalized to backslashes
// before being joined onto the base and sent upstream.
func TestProxyCreateNormalizesClientSlashes(t *testing.T) {
	ff := &fakeFile{metaVal: fileMeta{endOfFile: 1}}
	c := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) {
		return ff, nil
	}}
	v := &proxyVFS{up: &upstream{t: testTarget(), conn: c}, share: "data", base: "Users\\Public"}

	if _, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: "/sub/a.txt"}); err != nil || status != 0 {
		t.Fatalf("Create with slash path = (0x%08x, %v), want success", status, err)
	}
	if c.opens[0] != "Users\\Public\\sub\\a.txt" {
		t.Errorf("opened %q, want Users\\Public\\sub\\a.txt (slashes normalized, base prepended)", c.opens[0])
	}
}

func TestProxyQueryDirectoryRootWithBase(t *testing.T) {
	c := &fakeConn{listResult: []smb.SharedFile{{Name: "f"}}}
	v := &proxyVFS{up: &upstream{t: testTarget(), conn: c}, share: "C$", base: "Users\\Public"}
	ph := &proxyHandle{isRoot: true, isDir: true}

	if _, status, err := v.QueryDirectory(context.Background(), ph, "*", false); err != nil || status != 0 {
		t.Fatalf("root list with base = (0x%08x, %v), want success", status, err)
	}
	if c.listDir != "Users\\Public" {
		t.Errorf("ListDirectory dir = %q, want the base Users\\Public", c.listDir)
	}
}

func TestProxyCreateRejectsTraversal(t *testing.T) {
	c := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) {
		t.Fatal("upstream opened despite a traversal path")
		return nil, nil
	}}
	v := &proxyVFS{up: &upstream{t: testTarget(), conn: c}, share: "C$", base: "Users\\Public"}

	_, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: "\\..\\..\\Windows"})
	if err != nil || status != smb.StatusAccessDenied {
		t.Errorf("Create with .. = (0x%08x, %v), want StatusAccessDenied", status, err)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestProxyReadClosedHandle(t *testing.T) {
	v := newVFS(&fakeConn{})
	buf := make([]byte, 8)

	_, status, _ := v.Read(context.Background(), &proxyHandle{}, 0, buf)
	if status != smb.StatusFileClosed {
		t.Errorf("Read nil file = 0x%08x, want StatusFileClosed", status)
	}
	_, rootStatus, _ := v.Read(context.Background(), &proxyHandle{isRoot: true}, 0, buf)
	if rootStatus != smb.StatusAccessDenied {
		t.Errorf("Read root = 0x%08x, want StatusAccessDenied", rootStatus)
	}
}

// Exercises tier 3 (synchronous fetch), tier 1 (cache hit, partial serve), and
// tier 2 (prefetch hit returning EOF) over a small file in one sequence.
func TestProxyReadTiers(t *testing.T) {
	data := []byte("0123456789") // 10 bytes
	ff := &fakeFile{data: data}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()
	buf := make([]byte, 4)

	// tier 3: cache empty -> fetch whole file, serve first 4 bytes.
	n, status, err := v.Read(ctx, ph, 0, buf)
	if err != nil || status != smb.StatusOk || n != 4 || !bytes.Equal(buf, data[0:4]) {
		t.Fatalf("tier3 read = (%d, 0x%08x, %v, %q), want (4, Ok, nil, 0123)", n, status, err, buf[:n])
	}

	// tier 1: cache hit, offset mid-file, partial serve. offset+serve crosses
	// the half-way trigger (5), so a prefetch at offset 10 starts.
	n, status, _ = v.Read(ctx, ph, 4, buf)
	if status != smb.StatusOk || n != 4 || !bytes.Equal(buf, data[4:8]) {
		t.Fatalf("tier1 read = (%d, 0x%08x, %q), want (4, Ok, 4567)", n, status, buf[:n])
	}

	// tail of the cache: only 2 bytes remain.
	n, status, _ = v.Read(ctx, ph, 8, buf)
	if status != smb.StatusOk || n != 2 || !bytes.Equal(buf[:2], data[8:10]) {
		t.Fatalf("tier1 tail = (%d, 0x%08x, %q), want (2, Ok, 89)", n, status, buf[:n])
	}

	// tier 2: read at offset 10 consumes the queued prefetch, which hit EOF.
	n, status, _ = v.Read(ctx, ph, 10, buf)
	if status != smb.StatusEndOfFile || n != 0 {
		t.Fatalf("tier2 EOF read = (%d, 0x%08x), want (0, StatusEndOfFile)", n, status)
	}
	drainPrefetch(ph)
}

// tier 2 returning data: the file is larger than one read-ahead batch, so the
// prefetch started after the first read holds the next region.
func TestProxyReadPrefetchData(t *testing.T) {
	data := make([]byte, readAheadSize+100)
	for i := range data {
		data[i] = byte(i)
	}
	ff := &fakeFile{data: data}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()

	// tier 3 fills the cache with the first readAheadSize bytes and launches a
	// prefetch at offset readAheadSize.
	big := make([]byte, readAheadSize)
	n, status, err := v.Read(ctx, ph, 0, big)
	if err != nil || status != smb.StatusOk || n != readAheadSize {
		t.Fatalf("first read = (%d, 0x%08x, %v), want (%d, Ok, nil)", n, status, err, readAheadSize)
	}

	// tier 2: the prefetched tail (100 bytes) is served from the queue.
	tail := make([]byte, 200)
	n, status, err = v.Read(ctx, ph, readAheadSize, tail)
	if err != nil || status != smb.StatusOk || n != 100 {
		t.Fatalf("prefetch read = (%d, 0x%08x, %v), want (100, Ok, nil)", n, status, err)
	}
	if !bytes.Equal(tail[:100], data[readAheadSize:]) {
		t.Errorf("prefetched bytes mismatch")
	}
	drainPrefetch(ph)
}

// After a seek away from the queued read-ahead, the stale prefetch is replaced
// by one following the new position, so sequential reads from there are
// prefetched again rather than all falling through to synchronous fetches.
func TestProxyReadPrefetchFollowsSeek(t *testing.T) {
	data := make([]byte, 3*readAheadSize)
	for i := range data {
		data[i] = byte(i)
	}
	ff := &fakeFile{data: data}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()
	buf := make([]byte, 4096)

	// Sequential start: the cache holds [0, R) and a prefetch is queued at R.
	if _, status, _ := v.Read(ctx, ph, 0, buf); status != smb.StatusOk {
		t.Fatalf("first read status 0x%08x", status)
	}
	drainPrefetch(ph)

	// Seek past both the cache and the queued prefetch, far enough from the
	// end that the next read-ahead still starts inside the file.
	seek := int64(readAheadSize + readAheadSize/2)
	n, status, _ := v.Read(ctx, ph, seek, buf)
	if status != smb.StatusOk || n != len(buf) || !bytes.Equal(buf, data[seek:seek+int64(n)]) {
		t.Fatalf("seek read = (%d, 0x%08x), want (%d, Ok) with matching bytes", n, status, len(buf))
	}
	drainPrefetch(ph)

	ph.prefMu.Lock()
	p := ph.pref
	ph.prefMu.Unlock()
	if want := seek + readAheadSize; p == nil || p.off != want {
		t.Fatalf("queued prefetch = %+v, want one at offset %d", p, want)
	}
}

// A target that stops answering fails a read or listing with STATUS_IO_TIMEOUT
// once the I/O timeout passes, rather than holding the upstream lock (and so
// every other client of the connection) indefinitely.
func TestProxyIOTimeout(t *testing.T) {
	ff := &fakeFile{data: []byte("0123456789"), isDir: true, stall: true}
	v := newVFS(&fakeConn{})
	v.up.ioTimeout = 20 * time.Millisecond
	ctx := context.Background()

	n, status, err := v.Read(ctx, fileHandle(ff), 0, make([]byte, 4))
	if err != nil || n != 0 || status != statusIoTimeout {
		t.Errorf("stalled read = (%d, 0x%08x, %v), want (0, STATUS_IO_TIMEOUT, nil)", n, status, err)
	}
	entries, status, err := v.QueryDirectory(ctx, &proxyHandle{file: ff, isDir: true, path: "\\sub"}, "*", false)
	if err != nil || entries != nil || status != statusIoTimeout {
		t.Errorf("stalled listing = (%d entries, 0x%08x, %v), want (0, STATUS_IO_TIMEOUT, nil)", len(entries), status, err)
	}
	if !v.up.mu.TryLock() {
		t.Fatal("upstream lock still held after the timed-out requests")
	}
	v.up.mu.Unlock()
}

// A small file costs a buffer of its own size, not a full read-ahead batch,
// and reading it whole queues no read-ahead past its end.
func TestProxyReadClampsToFileSize(t *testing.T) {
	data := []byte("0123456789")
	ff := &fakeFile{data: data}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)

	buf := make([]byte, 64)
	n, status, _ := v.Read(context.Background(), ph, 0, buf)
	if status != smb.StatusOk || n != len(data) || !bytes.Equal(buf[:n], data) {
		t.Fatalf("read = (%d, 0x%08x, %q), want (10, Ok, %q)", n, status, buf[:n], data)
	}
	if c := cap(ph.cacheData); c != len(data) {
		t.Errorf("cache buffer cap = %d, want %d", c, len(data))
	}
	if ph.pref != nil {
		t.Errorf("prefetch queued at %d, want none past the end of file", ph.pref.off)
	}
	if r := ff.readCount(); r != 1 {
		t.Errorf("upstream ReadFile called %d times, want 1", r)
	}
}

// A file that grew after it was opened is still readable past the size seen
// at open time: such reads go upstream with a small probe buffer.
func TestProxyReadPastOpenTimeSize(t *testing.T) {
	data := []byte("0123456789abcdef")
	ff := &fakeFile{data: data}
	v := newVFS(&fakeConn{})
	ph := &proxyHandle{file: ff, info: server.FileInfo{Size: 10}} // grew to 16 since

	buf := make([]byte, 64)
	n, status, _ := v.Read(context.Background(), ph, 10, buf)
	if status != smb.StatusOk || n != 6 || !bytes.Equal(buf[:n], data[10:]) {
		t.Fatalf("read = (%d, 0x%08x, %q), want (6, Ok, %q)", n, status, buf[:n], data[10:])
	}
	if c := cap(ph.cacheData); c != probeSize {
		t.Errorf("cache buffer cap = %d, want probeSize %d", c, probeSize)
	}
}

func TestReadBufPool(t *testing.T) {
	if b := getReadBuf(100); len(b) != 100 || cap(b) != 100 {
		t.Errorf("small buffer len/cap = %d/%d, want 100/100", len(b), cap(b))
	}
	full := getReadBuf(readAheadSize)
	if len(full) != readAheadSize {
		t.Fatalf("full buffer len = %d, want %d", len(full), readAheadSize)
	}
	// Recycling a resliced full buffer, a small one, or nil must not panic.
	putReadBuf(full[:10])
	putReadBuf(make([]byte, 100))
	putReadBuf(nil)
}

// A cached region must be served without touching the upstream again.
func TestProxyReadServesFromCache(t *testing.T) {
	data := []byte("0123456789")
	ff := &fakeFile{data: data}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()
	buf := make([]byte, 4)

	if _, status, _ := v.Read(ctx, ph, 0, buf); status != smb.StatusOk {
		t.Fatalf("priming read status = 0x%08x", status)
	}
	drainPrefetch(ph) // let the read-triggered prefetch settle before mutating

	ff.setReadErr(errors.New("upstream must not be called"))
	before := ff.readCount()
	n, status, _ := v.Read(ctx, ph, 0, buf)
	if status != smb.StatusOk || n != 4 || !bytes.Equal(buf, data[0:4]) {
		t.Errorf("cached read = (%d, 0x%08x, %q), want (4, Ok, 0123)", n, status, buf[:n])
	}
	if after := ff.readCount(); after != before {
		t.Errorf("upstream ReadFile called %d extra times, want 0 for a cache hit", after-before)
	}
}

func TestProxyReadError(t *testing.T) {
	ff := &fakeFile{readErr: smb.StatusMap[smb.StatusAccessDenied]}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)

	n, status, err := v.Read(context.Background(), ph, 0, make([]byte, 8))
	if err != nil || n != 0 || status != smb.StatusAccessDenied {
		t.Errorf("Read error = (%d, 0x%08x, %v), want (0, StatusAccessDenied, nil)", n, status, err)
	}
}

// ---------------------------------------------------------------------------
// QueryDirectory
// ---------------------------------------------------------------------------

func TestProxyQueryDirectoryRoot(t *testing.T) {
	c := &fakeConn{listResult: []smb.SharedFile{
		{Name: "docs", IsDir: true},
		{Name: "readme.txt", Size: 42},
	}}
	v := newVFS(c)
	ph := &proxyHandle{isRoot: true, isDir: true, path: "\\"}
	ctx := context.Background()

	entries, status, err := v.QueryDirectory(ctx, ph, "*", false)
	if err != nil || status != 0 || len(entries) != 2 {
		t.Fatalf("root list = (%d entries, 0x%08x, %v), want 2 entries", len(entries), status, err)
	}
	if entries[0].Name != "docs" || entries[1].Name != "readme.txt" {
		t.Errorf("entries = %q/%q, want docs/readme.txt", entries[0].Name, entries[1].Name)
	}

	// Second call with the same pattern exhausts the listing.
	entries, status, _ = v.QueryDirectory(ctx, ph, "*", false)
	if status != smb.StatusNoMoreFiles || entries != nil {
		t.Errorf("second root list = (%v, 0x%08x), want (nil, StatusNoMoreFiles)", entries, status)
	}
}

func TestProxyQueryDirectoryRootTreeConnectError(t *testing.T) {
	c := &fakeConn{treeErr: smb.StatusMap[smb.StatusAccessDenied]}
	v := newVFS(c)
	ph := &proxyHandle{isRoot: true, isDir: true}

	_, status, err := v.QueryDirectory(context.Background(), ph, "*", false)
	if err != nil || status != smb.StatusAccessDenied {
		t.Errorf("TreeConnect error -> (0x%08x, %v), want StatusAccessDenied", status, err)
	}
}

func TestProxyQueryDirectoryFile(t *testing.T) {
	ff := &fakeFile{isDir: true, dirs: []smb.SharedFile{{Name: "x"}}}
	v := newVFS(&fakeConn{})
	ph := &proxyHandle{file: ff, isDir: true, path: "\\sub"}
	ctx := context.Background()

	entries, status, err := v.QueryDirectory(ctx, ph, "*", false)
	if err != nil || status != 0 || len(entries) != 1 || entries[0].Name != "x" {
		t.Fatalf("file list = (%d, 0x%08x, %v), want 1 entry 'x'", len(entries), status, err)
	}
	if entries, status, _ := v.QueryDirectory(ctx, ph, "*", false); status != smb.StatusNoMoreFiles || entries != nil {
		t.Errorf("exhausted list = (%v, 0x%08x), want (nil, StatusNoMoreFiles)", entries, status)
	}
	// One batch, then the empty batch that ends the enumeration; the second
	// client call is served from the handle without touching the upstream.
	if ff.dirCall != 2 {
		t.Errorf("upstream QueryDirectory called %d times, want 2", ff.dirCall)
	}

	// A restart re-lists from the beginning.
	entries, _, err = v.QueryDirectory(ctx, ph, "*", true)
	if err != nil || len(entries) != 1 || entries[0].Name != "x" {
		t.Fatalf("restart list = (%d entries, %v), want 1 entry 'x'", len(entries), err)
	}
}

// A directory larger than one upstream batch is listed in full, not truncated
// to the first batch.
func TestProxyQueryDirectoryAllBatches(t *testing.T) {
	dirs := make([]smb.SharedFile, 25)
	for i := range dirs {
		dirs[i] = smb.SharedFile{Name: fmt.Sprintf("f%02d", i)}
	}
	ff := &fakeFile{isDir: true, dirs: dirs, dirPage: 10}
	v := newVFS(&fakeConn{})
	ph := &proxyHandle{file: ff, isDir: true, path: "\\big"}
	ctx := context.Background()

	entries, status, err := v.QueryDirectory(ctx, ph, "*", false)
	if err != nil || status != 0 || len(entries) != len(dirs) {
		t.Fatalf("list = (%d entries, 0x%08x, %v), want %d entries", len(entries), status, err, len(dirs))
	}
	for i, e := range entries {
		if e.Name != dirs[i].Name {
			t.Fatalf("entry %d = %q, want %q", i, e.Name, dirs[i].Name)
		}
	}

	// A new pattern without restart still lists everything: the exhausted
	// upstream enumeration is restarted, not resumed.
	entries, _, _ = v.QueryDirectory(ctx, ph, "f*", false)
	if len(entries) != len(dirs) {
		t.Errorf("re-list under new pattern = %d entries, want %d", len(entries), len(dirs))
	}
}

func TestProxyQueryDirectoryNoMoreFiles(t *testing.T) {
	ff := &fakeFile{dirErr: smb.StatusMap[smb.StatusNoMoreFiles]}
	v := newVFS(&fakeConn{})
	ph := &proxyHandle{file: ff, path: "\\sub"}

	entries, status, err := v.QueryDirectory(context.Background(), ph, "*", false)
	if err != nil || status != smb.StatusNoMoreFiles || entries != nil {
		t.Errorf("empty dir = (%v, 0x%08x, %v), want (nil, StatusNoMoreFiles, nil)", entries, status, err)
	}
	if !ph.listed {
		t.Errorf("handle not marked listed after StatusNoMoreFiles")
	}
}

func TestProxyQueryDirectoryClosedFile(t *testing.T) {
	v := newVFS(&fakeConn{})
	ph := &proxyHandle{path: "\\sub"} // non-root, file == nil

	_, status, _ := v.QueryDirectory(context.Background(), ph, "*", false)
	if status != smb.StatusFileClosed {
		t.Errorf("closed-file list = 0x%08x, want StatusFileClosed", status)
	}
}

// ---------------------------------------------------------------------------
// Close and the read-only method stubs
// ---------------------------------------------------------------------------

func TestProxyClose(t *testing.T) {
	ff := &fakeFile{data: []byte("0123456789")}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()

	// A read populates the cache and starts a prefetch; Close must drain it,
	// close the upstream file, and clear the handle.
	if _, status, _ := v.Read(ctx, ph, 0, make([]byte, 4)); status != smb.StatusOk {
		t.Fatalf("priming read status 0x%08x", status)
	}
	if err := v.Close(ctx, ph); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ff.mu.Lock()
	closed := ff.closed
	ff.mu.Unlock()
	if !closed || ph.file != nil || ph.cacheData != nil || ph.pref != nil {
		t.Errorf("after Close: fileClosed=%v file=%v cache=%v pref=%v, want closed and all cleared",
			closed, ph.file, ph.cacheData, ph.pref)
	}
}

// Queries the proxy leaves to go-smb's own defaults.
func TestProxyUnsupportedQueries(t *testing.T) {
	v := newVFS(&fakeConn{})
	ctx := context.Background()

	if _, status, _ := v.QueryFileInfo(ctx, nil, 0); status != smb.StatusNotSupported {
		t.Errorf("QueryFileInfo = 0x%08x, want StatusNotSupported", status)
	}
	if _, status, _ := v.QueryFSInfo(ctx, 0); status != smb.StatusNotSupported {
		t.Errorf("QueryFSInfo = 0x%08x, want StatusNotSupported", status)
	}
	if _, status, _ := v.Ioctl(ctx, nil, 0, nil, 0); status != smb.StatusNotSupported {
		t.Errorf("Ioctl = 0x%08x, want StatusNotSupported", status)
	}
}

func TestProxyQuerySecurity(t *testing.T) {
	sd := []byte{0x01, 0x00, 0x04, 0x80, 0xde, 0xad} // stand-in self-relative SD bytes
	ff := &fakeFile{secData: sd}
	v := newVFS(&fakeConn{})
	ph := &proxyHandle{file: ff}

	// A real descriptor is proxied back verbatim, and the client's requested
	// components are forwarded to the target.
	const want = smb.OwnerSecurityInformation | smb.GroupSecurityInformation | smb.DACLSecurityInformation
	buf, status, err := v.QuerySecurity(context.Background(), ph, want)
	if err != nil || status != smb.StatusOk || !bytes.Equal(buf, sd) {
		t.Fatalf("QuerySecurity = (%x, 0x%08x, %v), want the upstream SD bytes", buf, status, err)
	}
	if ff.secInfo != want {
		t.Errorf("forwarded additionalInformation = 0x%x, want 0x%x", ff.secInfo, want)
	}
}

// The share's root shows the mapped folder's descriptor: the folder is opened
// for reading its descriptor alone, queried and closed.
func TestProxyQuerySecurityRoot(t *testing.T) {
	sd := []byte{1, 0, 4, 0x80, 0, 0, 0, 0}
	ff := &fakeFile{isDir: true, secData: sd}
	var gotPath string
	var gotOpts *smb.CreateReqOpts
	c := &fakeConn{openFn: func(_, p string, opts *smb.CreateReqOpts) (upstreamFile, error) {
		gotPath, gotOpts = p, opts
		return ff, nil
	}}
	v := &proxyVFS{up: &upstream{t: testTarget(), conn: c}, share: "C$", base: "Users"}

	const dacl = 0x4
	buf, status, err := v.QuerySecurity(context.Background(), syntheticRootHandle("C$"), dacl)
	if err != nil || status != smb.StatusOk || !bytes.Equal(buf, sd) {
		t.Fatalf("QuerySecurity root = (% x, 0x%08x, %v), want the mapped folder's descriptor", buf, status, err)
	}
	if gotPath != "Users" || ff.secInfo != dacl || !ff.closed {
		t.Errorf("opened %q, asked 0x%x, closed %t; want Users, 0x%x, closed", gotPath, ff.secInfo, ff.closed, dacl)
	}
	if want := uint32(smb.FAccMaskReadControl | smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize); gotOpts.DesiredAccess != want {
		t.Errorf("opened with access 0x%08x, want 0x%08x", gotOpts.DesiredAccess, want)
	}
}

func TestProxyQuerySecurityFallbacks(t *testing.T) {
	v := newVFS(&fakeConn{})

	// Closed handle: no upstream file -> let the library supply its default
	// descriptor.
	if _, status, _ := v.QuerySecurity(context.Background(), &proxyHandle{}, 0); status != smb.StatusNotSupported {
		t.Errorf("QuerySecurity on fileless handle = 0x%08x, want StatusNotSupported", status)
	}
	// So does a root whose mapped folder cannot be opened.
	if _, status, _ := v.QuerySecurity(context.Background(), syntheticRootHandle("C$"), 0); status != smb.StatusNotSupported {
		t.Errorf("QuerySecurity on root, folder unopenable = 0x%08x, want StatusNotSupported", status)
	}

	// An upstream error must not fail the client's query; fall back to default.
	ph := &proxyHandle{file: &fakeFile{secErr: errors.New("access denied")}}
	buf, status, err := v.QuerySecurity(context.Background(), ph, 0)
	if err != nil || status != smb.StatusNotSupported || buf != nil {
		t.Errorf("QuerySecurity upstream error = (%x, 0x%08x, %v), want (nil, StatusNotSupported, nil)", buf, status, err)
	}
}

// ---------------------------------------------------------------------------
// QueryFileInfo classes answered by the proxy, and synthetic file IDs
// ---------------------------------------------------------------------------

// openFile opens path through v, backed by ff, and returns its handle.
func openFile(t *testing.T, v *proxyVFS, path string) *proxyHandle {
	t.Helper()
	res, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: path})
	if err != nil || status != 0 {
		t.Fatalf("Create %q: status=0x%08x err=%v", path, status, err)
	}
	return res.Handle.(*proxyHandle)
}

func TestProxyQueryFileInfoInternal(t *testing.T) {
	ff := &fakeFile{metaVal: fileMeta{endOfFile: 10}}
	c := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) { return ff, nil }}
	v := newVFS(c)
	ctx := context.Background()

	idOf := func(ph *proxyHandle) uint64 {
		t.Helper()
		out, status, err := v.QueryFileInfo(ctx, ph, smb.FileInternalInformation)
		buf, _ := out.([]byte)
		if err != nil || status != smb.StatusOk || len(buf) != 8 {
			t.Fatalf("FileInternalInformation = (%v, 0x%08x, %v), want 8 bytes, Ok", out, status, err)
		}
		return binary.LittleEndian.Uint64(buf)
	}

	a := idOf(openFile(t, v, "\\dir\\a.txt"))
	if a == 0 {
		t.Fatal("file ID is 0, want nonzero")
	}
	if again := idOf(openFile(t, v, "/DIR/A.TXT")); again != a {
		t.Errorf("same file under another case/slash style: ID %x, want %x", again, a)
	}
	if b := idOf(openFile(t, v, "\\dir\\b.txt")); b == a {
		t.Errorf("different files share ID %x", a)
	}
	if root := idOf(openFile(t, v, "\\")); root != v.fileID("") || root == a {
		t.Errorf("root ID = %x, want fileID(\"\") = %x, distinct from a file's", root, v.fileID(""))
	}
}

// A file's ID in a directory listing matches the one its open handle reports,
// and "." / ".." resolve to the directory and its parent.
func TestProxyQueryDirectoryFileIDs(t *testing.T) {
	ff := &fakeFile{isDir: true, dirs: []smb.SharedFile{{Name: "."}, {Name: ".."}, {Name: "a.txt"}}}
	c := &fakeConn{openFn: func(_, _ string, _ *smb.CreateReqOpts) (upstreamFile, error) { return ff, nil }}
	v := newVFS(c)

	dir := openFile(t, v, "\\top\\dir")
	entries, status, err := v.QueryDirectory(context.Background(), dir, "*", false)
	if err != nil || status != 0 || len(entries) != 3 {
		t.Fatalf("list = (%d entries, 0x%08x, %v), want 3", len(entries), status, err)
	}
	want := map[string]uint64{
		".":     v.fileID("top\\dir"),
		"..":    v.fileID("top"),
		"a.txt": v.fileID("top\\dir\\a.txt"),
	}
	for _, e := range entries {
		if e.FileID != want[e.Name] {
			t.Errorf("entry %q FileID = %x, want %x", e.Name, e.FileID, want[e.Name])
		}
	}
	if got := openFile(t, v, "\\top\\dir\\a.txt").info.FileID; got != want["a.txt"] {
		t.Errorf("handle FileID = %x, listing FileID = %x; want equal", got, want["a.txt"])
	}
}

func TestProxyQueryFileInfoStreams(t *testing.T) {
	v := newVFS(&fakeConn{})
	ctx := context.Background()

	file := &proxyHandle{info: server.FileInfo{Size: 1000, AllocationSize: 4096}}
	out, status, err := v.QueryFileInfo(ctx, file, smb.FileStreamInformation)
	buf, _ := out.([]byte)
	if err != nil || status != smb.StatusOk {
		t.Fatalf("file streams = (0x%08x, %v), want Ok", status, err)
	}
	name := "::$DATA"
	if len(buf) != 24+2*len(name) {
		t.Fatalf("stream info is %d bytes, want %d", len(buf), 24+2*len(name))
	}
	le := binary.LittleEndian
	if next, nameLen := le.Uint32(buf[0:]), le.Uint32(buf[4:]); next != 0 || nameLen != uint32(2*len(name)) {
		t.Errorf("NextEntryOffset/StreamNameLength = %d/%d, want 0/%d", next, nameLen, 2*len(name))
	}
	if size, alloc := le.Uint64(buf[8:]), le.Uint64(buf[16:]); size != 1000 || alloc != 4096 {
		t.Errorf("StreamSize/AllocationSize = %d/%d, want 1000/4096", size, alloc)
	}
	for i, r := range name {
		if got := le.Uint16(buf[24+2*i:]); got != uint16(r) {
			t.Fatalf("stream name char %d = %q, want %q", i, rune(got), r)
		}
	}

	dir := &proxyHandle{isDir: true}
	out, status, _ = v.QueryFileInfo(ctx, dir, smb.FileStreamInformation)
	if b, _ := out.([]byte); status != smb.StatusOk || len(b) != 0 {
		t.Errorf("dir streams = (%d bytes, 0x%08x), want (0 bytes, Ok)", len(b), status)
	}
}

func TestProxyQueryFSInfo(t *testing.T) {
	v := newVFS(&fakeConn{})
	le := binary.LittleEndian
	query := func(class byte, size int) []byte {
		t.Helper()
		out, status, err := v.QueryFSInfo(context.Background(), class)
		buf, _ := out.([]byte)
		if err != nil || status != smb.StatusOk || len(buf) != size {
			t.Fatalf("class 0x%02x = (%d bytes, 0x%08x, %v), want (%d bytes, Ok)", class, len(buf), status, err, size)
		}
		return buf
	}

	if dev := query(fsDeviceInformation, 8); le.Uint32(dev[0:]) != 7 {
		t.Errorf("DeviceType = %d, want FILE_DEVICE_DISK (7)", le.Uint32(dev[0:]))
	}
	// The volume object ID is the BirthVolumeId in every file's object ID.
	if obj := query(fsObjectIDInformation, 64); !bytes.Equal(obj[0:16], v.objectID("x")[16:32]) {
		t.Errorf("volume ObjectId = %x, want the files' BirthVolumeId %x", obj[0:16], v.objectID("x")[16:32])
	}

	// Volume info must fit the 24-byte buffer GetFileInformationByHandle
	// passes: the 18-byte fixed part, an empty label, a per-share serial.
	vol := query(fsVolumeInformation, 18)
	if le.Uint32(vol[12:]) != 0 {
		t.Errorf("VolumeLabelLength = %d, want 0", le.Uint32(vol[12:]))
	}
	if !bytes.Equal(vol[8:12], v.objectID("")[16:20]) || bytes.Equal(vol[8:12], make([]byte, 4)) {
		t.Errorf("VolumeSerialNumber = %x, want the nonzero per-share volume ID prefix", vol[8:12])
	}
	other := &proxyVFS{up: &upstream{t: testTarget(), conn: &fakeConn{}}, share: "D$"}
	if otherVol, _, _ := other.QueryFSInfo(context.Background(), fsVolumeInformation); bytes.Equal(otherVol.([]byte)[8:12], vol[8:12]) {
		t.Errorf("shares C$ and D$ report the same volume serial %x", vol[8:12])
	}

	// Attribute information the target cannot give is left to go-smb's
	// fallback.
	if _, status, _ := v.QueryFSInfo(context.Background(), fsAttributeInformation); status != smb.StatusNotSupported {
		t.Errorf("attribute info (0x05) = 0x%08x, want StatusNotSupported (library fallback)", status)
	}
}

// fsAttributes builds FileFsAttributeInformation: flags, a 255-character name
// limit and the file system's name, followed by extra.
func fsAttributes(flags uint32, name string, extra ...byte) []byte {
	le := binary.LittleEndian
	units := utf16.Encode([]rune(name))
	buf := le.AppendUint32(nil, flags)
	buf = le.AppendUint32(buf, 255)
	buf = le.AppendUint32(buf, uint32(2*len(units)))
	for _, u := range units {
		buf = le.AppendUint16(buf, u)
	}
	return append(buf, extra...)
}

// The target's file system attributes are passed on, its name included, with
// only the flags the proxy honours: Explorer shows the Security tab for
// FILE_PERSISTENT_ACLS, and must not count on the rest.
func TestProxyQueryFSInfoAttributes(t *testing.T) {
	const ntfs = 0x03e700ff // what Windows reports for an NTFS volume
	for _, tt := range []struct {
		name  string
		reply []byte
		want  []byte // nil: left to go-smb's fallback
	}{
		{"NTFS", fsAttributes(ntfs, "NTFS", 0xee, 0xee), fsAttributes(0x0f, "NTFS")},
		{"Samba", fsAttributes(0x0001800f, "NTFS"), fsAttributes(0x0f, "NTFS")},
		{"no ACLs", fsAttributes(0x00000003, "FAT32"), fsAttributes(0x03, "FAT32")},
		{"short", []byte{0x0f, 0, 0, 0, 255, 0, 0}, nil},
		{"name overruns", fsAttributes(0x0f, "NTFS")[:14], nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ff := &fakeFile{isDir: true, fsData: tt.reply}
			v := newVFS(&fakeConn{openFn: func(string, string, *smb.CreateReqOpts) (upstreamFile, error) { return ff, nil }})
			out, status, err := v.QueryFSInfo(context.Background(), fsAttributeInformation)
			if tt.want == nil {
				if status != smb.StatusNotSupported || err != nil {
					t.Errorf("= (0x%08x, %v), want StatusNotSupported (library fallback)", status, err)
				}
				return
			}
			if err != nil || status != smb.StatusOk || !bytes.Equal(out.([]byte), tt.want) {
				t.Errorf("= (% x, 0x%08x, %v), want % x", out, status, err, tt.want)
			}
			if ff.fsClass != fsAttributeInformation {
				t.Errorf("target asked for class 0x%02x", ff.fsClass)
			}
		})
	}
}

// The volume size classes come from the target: the mapped folder is opened
// for attributes alone, queried and closed, and the reply is cut to the
// class's structure.
func TestProxyQueryFSInfoSizes(t *testing.T) {
	reply := make([]byte, 40) // longer than either structure
	for i := range reply {
		reply[i] = byte(i + 1)
	}
	ff := &fakeFile{isDir: true, fsData: reply}
	var gotPath string
	var gotOpts *smb.CreateReqOpts
	c := &fakeConn{openFn: func(_, p string, opts *smb.CreateReqOpts) (upstreamFile, error) {
		gotPath, gotOpts = p, opts
		return ff, nil
	}}
	v := &proxyVFS{up: &upstream{t: testTarget(), conn: c}, share: "C$", base: `Users\Public`}

	for _, tt := range []struct {
		class byte
		size  int
	}{{fsSizeInformation, 24}, {fsFullSizeInformation, 32}, {fsSectorSizeInformation, 28}} {
		out, status, err := v.QueryFSInfo(context.Background(), tt.class)
		if err != nil || status != smb.StatusOk || !bytes.Equal(out.([]byte), reply[:tt.size]) {
			t.Errorf("class 0x%02x = (% x, 0x%08x, %v), want the target's first %d bytes", tt.class, out, status, err, tt.size)
		}
		if ff.fsClass != tt.class {
			t.Errorf("target queried for class 0x%02x, want 0x%02x", ff.fsClass, tt.class)
		}
	}
	if gotPath != `Users\Public` {
		t.Errorf(`opened %q, want the mapped folder Users\Public`, gotPath)
	}
	if gotOpts.DesiredAccess != smb.FAccMaskFileReadAttributes|smb.FAccMaskSynchronize {
		t.Errorf("opened with access 0x%08x, want read attributes and synchronize", gotOpts.DesiredAccess)
	}
	if !ff.closed {
		t.Errorf("the folder opened to query the volume was left open")
	}

	// A repeat within fsCacheTTL is answered from the cache.
	if _, status, _ := v.QueryFSInfo(context.Background(), fsFullSizeInformation); status != smb.StatusOk || ff.fsQueries != 3 {
		t.Errorf("repeat = 0x%08x after %d target queries, want Ok after 3", status, ff.fsQueries)
	}
	v.fsCache[fsFullSizeInformation] = fsCached{at: time.Now().Add(-fsCacheTTL), buf: reply[:32]}
	if _, _, _ = v.QueryFSInfo(context.Background(), fsFullSizeInformation); ff.fsQueries != 4 {
		t.Errorf("expired entry: %d target queries, want 4", ff.fsQueries)
	}
}

// A target without FileFsSectorSizeInformation gets the sector size it
// reports in FileFsSizeInformation, and is not asked for the class again.
func TestProxyQueryFSInfoSectorFallback(t *testing.T) {
	le := binary.LittleEndian
	var sectorQueries int
	ff := &fakeFile{isDir: true, fsFn: func(class byte) ([]byte, error) {
		if class == fsSectorSizeInformation {
			sectorQueries++
			return nil, &smb.NTStatusError{Status: statusInvalidInfoClass}
		}
		size := make([]byte, 24)
		le.PutUint32(size[16:], 8)    // SectorsPerAllocationUnit
		le.PutUint32(size[20:], 4096) // BytesPerSector
		return size, nil
	}}
	v := newVFS(&fakeConn{openFn: func(string, string, *smb.CreateReqOpts) (upstreamFile, error) { return ff, nil }})

	for range 2 {
		out, status, err := v.QueryFSInfo(context.Background(), fsSectorSizeInformation)
		buf, _ := out.([]byte)
		if err != nil || status != smb.StatusOk || !bytes.Equal(buf, sectorSizeInfo(4096)) {
			t.Fatalf("sector info = (% x, 0x%08x, %v), want 4096-byte sectors", buf, status, err)
		}
	}
	if sectorQueries != 1 {
		t.Errorf("target asked for sector info %d times, want once", sectorQueries)
	}
	if b := sectorSizeInfo(0); le.Uint32(b[0:]) != fsBytesPerSector || le.Uint32(b[12:]) != fsBytesPerSector {
		t.Errorf("no sector size reported: % x, want %d-byte sectors", b, fsBytesPerSector)
	}

	// Any other failure is passed on, and the class is asked for again.
	ff.fsFn = func(byte) ([]byte, error) { return nil, &smb.NTStatusError{Status: smb.StatusAccessDenied} }
	v = newVFS(&fakeConn{openFn: func(string, string, *smb.CreateReqOpts) (upstreamFile, error) { return ff, nil }})
	if _, status, _ := v.QueryFSInfo(context.Background(), fsSectorSizeInformation); status != smb.StatusAccessDenied || v.noSectorInfo {
		t.Errorf("denied = 0x%08x (noSectorInfo %t), want STATUS_ACCESS_DENIED and asking again", status, v.noSectorInfo)
	}
}

// A target's refusal is passed on, except "not supported", which would make
// go-smb invent sizes; a short reply is an error.
func TestProxyQueryFSInfoSizeErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
		err  error
		want uint32
	}{
		{"access denied", nil, &smb.NTStatusError{Status: smb.StatusAccessDenied}, smb.StatusAccessDenied},
		{"not supported", nil, &smb.NTStatusError{Status: smb.StatusNotSupported}, statusInvalidDeviceRequest},
		{"short reply", make([]byte, 31), nil, statusUnexpectedNetworkError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ff := &fakeFile{isDir: true, fsData: tt.data, fsErr: tt.err}
			v := newVFS(&fakeConn{openFn: func(string, string, *smb.CreateReqOpts) (upstreamFile, error) { return ff, nil }})
			out, status, err := v.QueryFSInfo(context.Background(), fsFullSizeInformation)
			if err != nil || status != tt.want || out != nil {
				t.Errorf("QueryFSInfo = (%v, 0x%08x, %v), want (nil, 0x%08x)", out, status, err, tt.want)
			}
			if len(v.fsCache) != 0 {
				t.Errorf("a failure was cached: %v", v.fsCache)
			}
		})
	}
}

func TestProxyIoctlObjectID(t *testing.T) {
	v := newVFS(&fakeConn{})
	ctx := context.Background()
	objID := func(path string, code, maxOut uint32) ([]byte, uint32) {
		t.Helper()
		out, status, err := v.Ioctl(ctx, &proxyHandle{path: path}, code, nil, maxOut)
		if err != nil {
			t.Fatalf("Ioctl 0x%08x: %v", code, err)
		}
		return out, status
	}

	a, status := objID("dir\\a.txt", fsctlCreateOrGetObjectID, 64)
	if status != smb.StatusOk || len(a) != 64 {
		t.Fatalf("CREATE_OR_GET_OBJECT_ID = (%d bytes, 0x%08x), want (64, Ok)", len(a), status)
	}
	if !bytes.Equal(a[0:16], a[32:48]) || bytes.Equal(a[0:16], make([]byte, 16)) {
		t.Errorf("ObjectId %x / BirthObjectId %x: want equal and nonzero", a[0:16], a[32:48])
	}
	if !bytes.Equal(a[48:64], make([]byte, 16)) {
		t.Errorf("DomainId = %x, want zero", a[48:64])
	}

	if same, _ := objID("DIR/A.TXT", fsctlGetObjectID, 64); !bytes.Equal(same, a) {
		t.Errorf("same file via GET_OBJECT_ID under another case/slash style: %x, want %x", same, a)
	}
	b, _ := objID("dir\\b.txt", fsctlCreateOrGetObjectID, 64)
	if bytes.Equal(b[0:16], a[0:16]) {
		t.Errorf("different files share ObjectId %x", a[0:16])
	}
	if !bytes.Equal(b[16:32], a[16:32]) {
		t.Errorf("files on one share have BirthVolumeId %x and %x, want equal", a[16:32], b[16:32])
	}

	if _, status := objID("dir\\a.txt", fsctlCreateOrGetObjectID, 16); status != smb.StatusBufferTooSmall {
		t.Errorf("maxOut 16 -> 0x%08x, want StatusBufferTooSmall", status)
	}
}
