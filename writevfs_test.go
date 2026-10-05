package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

func TestWriteIntent(t *testing.T) {
	cases := []struct {
		name string
		req  server.CreateRequest
		want bool
	}{
		{"plain read", server.CreateRequest{CreateDisposition: smb.FileOpen, DesiredAccess: 0x00120089}, false},
		{"attributes only", server.CreateRequest{CreateDisposition: smb.FileOpen, DesiredAccess: 0x00000080}, false},
		{"write data", server.CreateRequest{CreateDisposition: smb.FileOpen, DesiredAccess: accessWriteData}, true},
		{"generic write", server.CreateRequest{CreateDisposition: smb.FileOpen, DesiredAccess: accessGenericWrite}, true},
		{"maximum allowed", server.CreateRequest{CreateDisposition: smb.FileOpen, DesiredAccess: accessMaximumAllowed}, true},
		{"delete", server.CreateRequest{CreateDisposition: smb.FileOpen, DesiredAccess: accessDelete}, true},
		{"create", server.CreateRequest{CreateDisposition: smb.FileCreate, DesiredAccess: 0x00120089}, true},
		{"open or create", server.CreateRequest{CreateDisposition: smb.FileOpenIf}, true},
		{"delete on close", server.CreateRequest{CreateDisposition: smb.FileOpen, CreateOptions: smb.FileDeleteOnClose}, true},
	}
	for _, c := range cases {
		if got := writeIntent(c.req); got != c.want {
			t.Errorf("%s: writeIntent = %t, want %t", c.name, got, c.want)
		}
	}
}

// A writer's write-style open reaches the target exactly as the client sent
// it, and reports what the target did; anyone else's keeps the read path.
func TestCreateForWrite(t *testing.T) {
	var got *smb.CreateReqOpts
	ff := &fakeFile{metaVal: fileMeta{createAction: smb.FileCreated}}
	c := &fakeConn{openFn: func(_, _ string, opts *smb.CreateReqOpts) (upstreamFile, error) {
		got = opts
		return ff, nil
	}}
	writer := &server.Session{Username: "alice"}
	reader := &server.Session{Username: "bob"}
	v := newVFS(c)
	v.base = "inner"
	v.canWrite = func(s *server.Session) bool { return s == writer }
	req := server.CreateRequest{
		Path: `dir\new.txt`, DesiredAccess: 0x0013019f, FileAttributes: 0x20,
		ShareAccess: 0x1, CreateDisposition: smb.FileCreate, CreateOptions: 0x44,
	}

	res, status, err := v.Create(context.Background(), writer, req)
	if err != nil || status != smb.StatusOk || res.CreateAction != smb.FileCreated {
		t.Fatalf("writer Create = (action %d, 0x%08x, %v), want (FileCreated, Ok)", res.CreateAction, status, err)
	}
	if got.DesiredAccess != req.DesiredAccess || got.FileAttr != req.FileAttributes || got.ShareAccess != req.ShareAccess ||
		got.CreateDisp != req.CreateDisposition || got.CreateOpts != req.CreateOptions {
		t.Errorf("target create options %+v, want the client's request %+v", got, req)
	}
	if c.opens[0] != `inner\dir\new.txt` {
		t.Errorf("opened %q on the target, want inner\\dir\\new.txt", c.opens[0])
	}

	// A non-writer's create with write intent takes the read path (go-smb's
	// write gate refuses the mutating dispositions before this point).
	req.CreateDisposition = smb.FileOpen
	if _, _, err := v.Create(context.Background(), reader, req); err != nil {
		t.Fatal(err)
	}
	if got.CreateDisp != smb.FileOpen || got.DesiredAccess == req.DesiredAccess {
		t.Errorf("reader's open used %+v, want the read path's own options", got)
	}
}

func TestProxyWrite(t *testing.T) {
	ff := &fakeFile{data: []byte("0123456789")}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()

	// Prime the read-ahead, then write through the same handle: the next
	// read must see the new bytes, not the cached ones.
	if _, status, _ := v.Read(ctx, ph, 0, make([]byte, 4)); status != smb.StatusOk {
		t.Fatalf("priming read status 0x%08x", status)
	}
	drainPrefetch(ph)
	n, status, err := v.Write(ctx, ph, 8, []byte("ABCDEF"))
	if err != nil || status != smb.StatusOk || n != 6 {
		t.Fatalf("Write = (%d, 0x%08x, %v), want (6, Ok)", n, status, err)
	}
	if fi, _ := ph.Stat(); fi.Size != 14 {
		t.Errorf("handle size %d after extending write, want 14", fi.Size)
	}
	// The read writes the pending data to the target first.
	buf := make([]byte, 14)
	if n, _, _ := v.Read(ctx, ph, 0, buf); n != 14 || !bytes.Equal(buf, []byte("01234567ABCDEF")) {
		t.Errorf("read after write = %q, want 01234567ABCDEF (stale read-ahead?)", buf[:n])
	}
	drainPrefetch(ph)
	if !bytes.Equal(ff.data, []byte("01234567ABCDEF")) {
		t.Errorf("target data %q, want 01234567ABCDEF", ff.data)
	}

	// A write the target refuses is acknowledged, then reported once, by
	// the next flush.
	const statusDiskFull = 0xc000007f // not named in go-smb; passed through exactly
	ff.writeErr = &smb.NTStatusError{Op: "Write", Status: statusDiskFull}
	if _, status, _ := v.Write(ctx, ph, 0, []byte("x")); status != smb.StatusOk {
		t.Errorf("write behind -> 0x%08x, want Ok", status)
	}
	if status, _ := v.Flush(ctx, ph); status != statusDiskFull {
		t.Errorf("Flush after a failing write -> 0x%08x, want the target's STATUS_DISK_FULL", status)
	}
	ff.writeErr = nil
	if _, status, _ := v.Write(ctx, &proxyHandle{path: `x`}, 0, []byte("x")); status != smb.StatusFileClosed {
		t.Errorf("write to a closed handle -> 0x%08x, want STATUS_FILE_CLOSED", status)
	}
	if _, status, _ := v.Write(ctx, syntheticRootHandle("C$"), 0, []byte("x")); status != smb.StatusAccessDenied {
		t.Errorf("write to the share root -> 0x%08x, want STATUS_ACCESS_DENIED", status)
	}
	if status, _ := v.Flush(ctx, ph); status != smb.StatusOk || ff.flushes != 1 {
		t.Errorf("Flush -> 0x%08x after %d target flushes, want Ok after 1", status, ff.flushes)
	}
}

// renameInfo builds a FILE_RENAME_INFORMATION payload for name.
func renameInfo(replace bool, name string) []byte {
	units := utf16.Encode([]rune(name))
	buf := make([]byte, 20+2*len(units))
	if replace {
		buf[0] = 1
	}
	binary.LittleEndian.PutUint32(buf[16:], uint32(2*len(units)))
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[20+2*i:], u)
	}
	return buf
}

func TestProxySetFileInfoRename(t *testing.T) {
	ff := &fakeFile{data: []byte("x")}
	v := newVFS(&fakeConn{})
	v.base = `inner`
	ph := fileHandle(ff)
	ph.path = `old.txt`
	ctx := context.Background()

	// The new name moves inside the mapped folder, keeping ReplaceIfExists.
	if status, err := v.SetFileInfo(ctx, ph, smb.FileRenameInformation, renameInfo(true, `sub/new.txt`)); err != nil || status != smb.StatusOk {
		t.Fatalf("rename -> (0x%08x, %v)", status, err)
	}
	if ff.setInfoClass != smb.FileRenameInformation || !bytes.Equal(ff.setInfoBuf, renameInfo(true, `inner\sub\new.txt`)) {
		t.Errorf("target got class 0x%02x payload % x, want the rename to inner\\sub\\new.txt", ff.setInfoClass, ff.setInfoBuf)
	}
	if ph.Path() != `sub\new.txt` {
		t.Errorf("handle path %q after rename, want sub\\new.txt", ph.Path())
	}
	if fi, _ := ph.Stat(); fi.Name != "new.txt" {
		t.Errorf("handle name %q after rename, want new.txt", fi.Name)
	}

	ff.setInfoBuf = nil
	for name, want := range map[string]uint32{
		`..\escaped.txt`: smb.StatusAccessDenied,
		`\`:              smb.StatusObjectNameInvalid,
	} {
		if status, _ := v.SetFileInfo(ctx, ph, smb.FileRenameInformation, renameInfo(false, name)); status != want {
			t.Errorf("rename to %q -> 0x%08x, want 0x%08x", name, status, want)
		}
	}
	if ff.setInfoBuf != nil {
		t.Error("a refused rename reached the target")
	}
	if status, _ := v.SetFileInfo(ctx, ph, smb.FileRenameInformation, []byte{1, 2}); status != smb.StatusInfoLengthMismatch {
		t.Errorf("short rename payload -> 0x%08x, want STATUS_INFO_LENGTH_MISMATCH", status)
	}
}

func TestProxySetFileInfoMetadata(t *testing.T) {
	ff := &fakeFile{data: []byte("0123456789")}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()

	eof := make([]byte, 8)
	binary.LittleEndian.PutUint64(eof, 4)
	if status, _ := v.SetFileInfo(ctx, ph, smb.FileEndOfFileInformation, eof); status != smb.StatusOk {
		t.Fatalf("end of file -> 0x%08x", status)
	}
	if fi, _ := ph.Stat(); fi.Size != 4 || ff.setInfoClass != smb.FileEndOfFileInformation || !bytes.Equal(ff.setInfoBuf, eof) {
		t.Errorf("after truncating: size %d, target class 0x%02x; want 4 and the payload passed through", fi.Size, ff.setInfoClass)
	}

	basic := make([]byte, 40)
	const ft = 133000000000000000 // a FILETIME in 2022
	binary.LittleEndian.PutUint64(basic[16:], ft)
	binary.LittleEndian.PutUint32(basic[32:], server.FileAttributeReadonly)
	before, _ := ph.Stat()
	if status, _ := v.SetFileInfo(ctx, ph, smb.FileBasicInformation, basic); status != smb.StatusOk {
		t.Fatalf("basic info -> 0x%08x", status)
	}
	fi, _ := ph.Stat()
	if !fi.LastWriteTime.Equal(filetimeToTime(ft)) || fi.Attributes != server.FileAttributeReadonly {
		t.Errorf("after basic info: write time %v, attrs 0x%x; want %v and READONLY", fi.LastWriteTime, fi.Attributes, filetimeToTime(ft))
	}
	if !fi.CreationTime.Equal(before.CreationTime) {
		t.Error("a zero creation time in basic info changed the handle's creation time")
	}

	for _, class := range []byte{smb.FileDispositionInformation, fileDispositionInformationEx, smb.FileAllocationInformation} {
		if status, _ := v.SetFileInfo(ctx, ph, class, make([]byte, 8)); status != smb.StatusOk || ff.setInfoClass != class {
			t.Errorf("class 0x%02x -> 0x%08x, reached target as 0x%02x", class, status, ff.setInfoClass)
		}
	}
	if status, _ := v.SetFileInfo(ctx, ph, smb.FilePositionInformation, make([]byte, 8)); status != smb.StatusOk {
		t.Errorf("position info -> 0x%08x, want Ok without the target", status)
	}
	if status, _ := v.SetFileInfo(ctx, ph, 0x27, nil); status != smb.StatusNotSupported {
		t.Errorf("an unknown class -> 0x%08x, want STATUS_NOT_SUPPORTED", status)
	}
	ff.setInfoErr = smb.StatusMap[smb.StatusAccessDenied]
	if status, _ := v.SetFileInfo(ctx, ph, smb.FileDispositionInformation, []byte{1}); status != smb.StatusAccessDenied {
		t.Errorf("target refusal -> 0x%08x, want its STATUS_ACCESS_DENIED", status)
	}
	if status, _ := v.SetFileInfo(ctx, syntheticRootHandle("C$"), smb.FileBasicInformation, basic); status != smb.StatusAccessDenied {
		t.Errorf("share root -> 0x%08x, want STATUS_ACCESS_DENIED", status)
	}
}
