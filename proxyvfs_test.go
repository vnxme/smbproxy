package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

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
	dirs    []smb.SharedFile // entries QueryDirectory returns (once)
	dirErr  error            // if set, QueryDirectory returns it
	dirCall int              // QueryDirectory call count
	isDir   bool
	metaVal fileMeta
	closed  bool
}

func (f *fakeFile) ReadFile(b []byte, off uint64) (int, error) {
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

func (f *fakeFile) QueryDirectory(_ string, flags byte, _ uint32, _ uint32) ([]smb.SharedFile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirCall++
	if flags&smb.RestartScans != 0 {
		f.dirCall = 1
	}
	if f.dirErr != nil {
		return nil, f.dirErr
	}
	return f.dirs, nil
}

func (f *fakeFile) CloseFile() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
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

func newVFS(c *fakeConn) *proxyVFS {
	return &proxyVFS{up: &upstream{conn: c}, share: "C$"}
}

// drainPrefetch blocks until any in-flight prefetch goroutine has finished, so
// a test can mutate the fake without racing it.
func drainPrefetch(ph *proxyHandle) {
	ph.prefMu.Lock()
	done := ph.prefDone
	ph.prefMu.Unlock()
	if done != nil {
		<-done
	}
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
	u := &upstream{m: mapping{remoteHost: "h"}, conn: conn1, dial: func(mapping) (upstreamConn, error) {
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
	u := &upstream{m: mapping{remoteHost: "h"}, conn: conn, idle: time.Minute,
		dial: func(mapping) (upstreamConn, error) { return conn, nil }}
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
	u := &upstream{m: mapping{remoteHost: "h"}, conn: conn1, dial: func(mapping) (upstreamConn, error) {
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
	v := &proxyVFS{up: &upstream{conn: c}, share: "C$", base: "Users\\Public"}
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
	v := &proxyVFS{up: &upstream{conn: c}, share: "data", base: "Users\\Public"}

	if _, status, err := v.Create(context.Background(), nil, server.CreateRequest{Path: "/sub/a.txt"}); err != nil || status != 0 {
		t.Fatalf("Create with slash path = (0x%08x, %v), want success", status, err)
	}
	if c.opens[0] != "Users\\Public\\sub\\a.txt" {
		t.Errorf("opened %q, want Users\\Public\\sub\\a.txt (slashes normalized, base prepended)", c.opens[0])
	}
}

func TestProxyQueryDirectoryRootWithBase(t *testing.T) {
	c := &fakeConn{listResult: []smb.SharedFile{{Name: "f"}}}
	v := &proxyVFS{up: &upstream{conn: c}, share: "C$", base: "Users\\Public"}
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
	v := &proxyVFS{up: &upstream{conn: c}, share: "C$", base: "Users\\Public"}

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
	ph := &proxyHandle{file: ff}
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
	ph := &proxyHandle{file: ff}
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

// A cached region must be served without touching the upstream again.
func TestProxyReadServesFromCache(t *testing.T) {
	data := []byte("0123456789")
	ff := &fakeFile{data: data}
	v := newVFS(&fakeConn{})
	ph := &proxyHandle{file: ff}
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
	ph := &proxyHandle{file: ff}

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
	if ff.dirCall != 1 {
		t.Errorf("upstream QueryDirectory called %d times, want 1 (second served from cache)", ff.dirCall)
	}

	// A restart re-queries the upstream.
	if _, _, err := v.QueryDirectory(ctx, ph, "*", true); err != nil {
		t.Fatalf("restart list: %v", err)
	}
	if ff.dirCall != 1 {
		// RestartScans resets the fake's counter to 1 on that call.
		t.Errorf("restart dirCall = %d, want 1", ff.dirCall)
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
	ph := &proxyHandle{file: ff}
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
	if !closed || ph.file != nil || ph.cacheData != nil || ph.prefDone != nil {
		t.Errorf("after Close: fileClosed=%v file=%v cache=%v pref=%v, want closed and all cleared",
			closed, ph.file, ph.cacheData, ph.prefDone)
	}
}

func TestProxyReadOnlyStubs(t *testing.T) {
	v := newVFS(&fakeConn{})
	ctx := context.Background()

	if n, status, _ := v.Write(ctx, nil, 0, []byte("x")); n != 0 || status != smb.StatusAccessDenied {
		t.Errorf("Write = (%d, 0x%08x), want (0, StatusAccessDenied)", n, status)
	}
	if status, err := v.Flush(ctx, nil); status != 0 || err != nil {
		t.Errorf("Flush = (0x%08x, %v), want (0, nil)", status, err)
	}
	if status, err := v.SetFileInfo(ctx, nil, 0, nil); status != smb.StatusAccessDenied || err != nil {
		t.Errorf("SetFileInfo = (0x%08x, %v), want (StatusAccessDenied, nil)", status, err)
	}
	if _, status, _ := v.QueryFileInfo(ctx, nil, 0); status != smb.StatusNotSupported {
		t.Errorf("QueryFileInfo = 0x%08x, want StatusNotSupported", status)
	}
	if _, status, _ := v.QueryFSInfo(ctx, 0); status != smb.StatusNotSupported {
		t.Errorf("QueryFSInfo = 0x%08x, want StatusNotSupported", status)
	}
	if _, status, _ := v.QuerySecurity(ctx, nil, 0); status != smb.StatusNotSupported {
		t.Errorf("QuerySecurity = 0x%08x, want StatusNotSupported", status)
	}
	if _, status, _ := v.Ioctl(ctx, nil, 0, nil, 0); status != smb.StatusNotSupported {
		t.Errorf("Ioctl = 0x%08x, want StatusNotSupported", status)
	}
}
