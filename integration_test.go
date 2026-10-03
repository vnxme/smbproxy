package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	dcesrv "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// ---------------------------------------------------------------------------
// Integration tests: SMB client → proxy → target, all in process
//
// The target is a real go-smb server with an in-memory share; the proxy is
// built from a YAML configuration exactly as main builds it; the client is
// go-smb's. Requests travel over TCP on loopback through every layer.
// ---------------------------------------------------------------------------

// startTarget serves an in-memory share "data" as user admin (password x) on
// a loopback port, standing in for a target server.
func startTarget(t *testing.T) (port int) {
	t.Helper()
	return startTargetVFS(t, memvfs.New(memvfs.Options{}))
}

// startTargetVFS is startTarget with vfs as the share's file system.
func startTargetVFS(t *testing.T, vfs server.VFS) (port int) {
	t.Helper()
	srv := &server.Server{Config: &server.ServerConfig{
		Authenticator: &server.MapAuthenticator{Accounts: map[string]*server.Account{
			"admin": {NTHash: ntlmssp.Ntowfv1("x")},
		}},
		MaxReadSize:  1 << 20,
		MaxWriteSize: 1 << 20,
	}}
	srv.RegisterShare("data", server.Share{Name: "data", Type: smb.ShareTypeDisk, VFS: vfs})
	return serve(t, srv)
}

// startProxy builds the proxy from yamlConfig, as main does, and serves it on a
// loopback port. targetPort replaces the placeholder TARGET_PORT.
func startProxy(t *testing.T, yamlConfig string, targetPort int) (port int) {
	t.Helper()
	yamlConfig = strings.ReplaceAll(yamlConfig, "TARGET_PORT", fmt.Sprint(targetPort))
	cfg, _, err := parseConfig([]byte(yamlConfig), t.TempDir())
	if err != nil {
		t.Fatalf("proxy configuration: %v", err)
	}
	p := newProxy(cfg)
	t.Cleanup(p.close)
	return serve(t, p.srv)
}

func serve(t *testing.T, srv *server.Server) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return l.Addr().(*net.TCPAddr).Port
}

// connect logs in to the server on port and connects to share.
func connect(t *testing.T, port int, user, pass, share string) *smb.Connection {
	t.Helper()
	conn, err := smb.NewConnection(smb.Options{
		Host: "127.0.0.1", Port: port, SMB2Only: true,
		Initiator: &spnego.NTLMInitiator{User: user, Password: pass},
	})
	if err != nil {
		t.Fatalf("login as %s on port %d: %v", user, port, err)
	}
	t.Cleanup(conn.Close)
	if err := conn.TreeConnect(share); err != nil {
		t.Fatalf("connect to %s as %s: %v", share, user, err)
	}
	return conn
}

// putFile writes content to path on share over conn.
func putFile(t *testing.T, conn *smb.Connection, share, path string, content []byte) {
	t.Helper()
	r := bytes.NewReader(content)
	if err := conn.PutFile(share, path, 0, r.Read); err != nil {
		t.Fatalf("put %s: %v", path, err)
	}
}

// getFile reads all of path on share over conn.
func getFile(t *testing.T, conn *smb.Connection, share, path string) ([]byte, error) {
	t.Helper()
	var buf bytes.Buffer
	err := conn.RetrieveFile(share, path, 0, func(b []byte) (int, error) { return buf.Write(b) })
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf.Bytes(), nil
}

// listDir returns the sorted entry names (without . and ..) of dir on share.
func listDir(t *testing.T, conn *smb.Connection, share, dir string) []string {
	t.Helper()
	files, err := conn.ListDirectory(share, dir, "*")
	if err != nil {
		t.Fatalf("list %q: %v", dir, err)
	}
	var names []string
	for _, f := range files {
		if f.Name != "." && f.Name != ".." {
			names = append(names, f.Name)
		}
	}
	slices.Sort(names)
	return names
}

// proxyConfig fronts the target's share "data" as share "files", mapped to
// its folder "inner", for local user alice.
const proxyConfig = `
server:
  listen: 127.0.0.1:0
local:
  users:
    alice: {password: a}
targets:
  mem:
    host: 127.0.0.1
    port: TARGET_PORT
    user: admin
    password: x
shares:
  - name: files
    target: mem
    path: data/inner
`

// The read path, end to end: a file and a folder written on the target are
// listed and read back through the proxy, confined to the mapped folder.
func TestIntegrationRead(t *testing.T) {
	targetPort := startTarget(t)
	direct := connect(t, targetPort, "admin", "x", "data")
	if err := direct.Mkdir("data", `inner`); err != nil {
		t.Fatal(err)
	}
	if err := direct.Mkdir("data", `inner\sub`); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("smbproxy "), 100_000) // 900 KB: several reads
	putFile(t, direct, "data", `inner\big.txt`, content)
	putFile(t, direct, "data", `outside.txt`, []byte("not mapped"))

	proxyPort := startProxy(t, proxyConfig, targetPort)
	client := connect(t, proxyPort, "alice", "a", "files")

	if got := listDir(t, client, "files", ""); !slices.Equal(got, []string{"big.txt", "sub"}) {
		t.Errorf("share root lists %v, want [big.txt sub]", got)
	}
	got, err := getFile(t, client, "files", "big.txt")
	if err != nil || !bytes.Equal(got, content) {
		t.Errorf("read big.txt: %d bytes, err %v; want %d bytes matching", len(got), err, len(content))
	}
	if _, err := getFile(t, client, "files", `..\outside.txt`); err == nil {
		t.Error("read ..\\outside.txt through the proxy, want it refused")
	}
}

// writeConfig fronts the target folder "inner" twice: as "files", writable by
// alice and readable by bob too, and as "ro", read-only for everyone.
const writeConfig = `
server:
  listen: 127.0.0.1:0
local:
  users:
    alice: {password: a}
    bob: {password: b}
targets:
  mem:
    host: 127.0.0.1
    port: TARGET_PORT
    user: admin
    password: x
shares:
  - name: files
    target: mem
    path: data/inner
    read_only: false
    read_access: [alice, bob]
    write_access: [alice]
  - name: ro
    target: mem
    path: data/inner
`

// setInfo sends a SET_INFO for path on share over conn, the way a client
// renames or truncates; go-smb's client has no call for it.
func setInfo(t *testing.T, conn *smb.Connection, share, path string, access uint32, class byte, buf []byte) error {
	t.Helper()
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = access
	opts.ShareAccess = smb.FileShareRead | smb.FileShareWrite | smb.FileShareDelete
	opts.CreateDisp = smb.FileOpen
	f, err := conn.OpenFileExt(share, path, opts)
	if err != nil {
		return err
	}
	defer f.CloseFile()
	return smbFile{File: f, share: share}.SetInfo(class, buf)
}

// The write path, end to end, against a real SMB target.
func TestIntegrationWrite(t *testing.T) {
	targetPort := startTarget(t)
	direct := connect(t, targetPort, "admin", "x", "data")
	if err := direct.Mkdir("data", `inner`); err != nil {
		t.Fatal(err)
	}
	proxyPort := startProxy(t, writeConfig, targetPort)
	alice := connect(t, proxyPort, "alice", "a", "files")

	// Create a file through the proxy; it lands in the mapped folder.
	content := bytes.Repeat([]byte("written through smbproxy\n"), 50_000) // 1.25 MB: several writes
	putFile(t, alice, "files", `new.txt`, content)
	if got, err := getFile(t, direct, "data", `inner\new.txt`); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("target has %d bytes (err %v), want the %d written", len(got), err, len(content))
	}
	if got, err := getFile(t, alice, "files", `new.txt`); err != nil || !bytes.Equal(got, content) {
		t.Errorf("read back through the proxy: %d bytes, err %v", len(got), err)
	}

	// Overwrite with shorter content: the file is replaced, not left long.
	putFile(t, alice, "files", `new.txt`, []byte("short"))
	if got, _ := getFile(t, direct, "data", `inner\new.txt`); string(got) != "short" {
		t.Errorf("after overwrite the target has %q, want \"short\"", got)
	}

	// A new folder, and a file in it.
	if err := alice.Mkdir("files", `sub`); err != nil {
		t.Fatalf("mkdir through the proxy: %v", err)
	}
	putFile(t, alice, "files", `sub\a.txt`, []byte("in sub"))
	if got := listDir(t, direct, "data", `inner\sub`); !slices.Equal(got, []string{"a.txt"}) {
		t.Errorf("target inner\\sub lists %v, want [a.txt]", got)
	}

	// Rename into the subfolder: the new name is translated into the mapped
	// folder on the target.
	if err := setInfo(t, alice, "files", `new.txt`, accessDelete|0x00100080, smb.FileRenameInformation,
		renameInfo(false, `sub\renamed.txt`)); err != nil {
		t.Fatalf("rename through the proxy: %v", err)
	}
	if got := listDir(t, direct, "data", `inner\sub`); !slices.Equal(got, []string{"a.txt", "renamed.txt"}) {
		t.Errorf("after rename the target's inner\\sub lists %v, want [a.txt renamed.txt]", got)
	}
	if got := listDir(t, direct, "data", `inner`); !slices.Equal(got, []string{"sub"}) {
		t.Errorf("after rename the target's inner lists %v, want [sub]", got)
	}
	// A rename out of the mapped folder is refused, and changes nothing.
	if err := setInfo(t, alice, "files", `sub\a.txt`, accessDelete|0x00100080, smb.FileRenameInformation,
		renameInfo(false, `..\escaped.txt`)); err == nil {
		t.Error("rename to ..\\escaped.txt succeeded, want it refused")
	}
	if got := listDir(t, direct, "data", ``); slices.Contains(got, "escaped.txt") {
		t.Error("a file escaped the mapped folder")
	}

	// Truncate through SET_INFO end of file.
	eof := make([]byte, 8)
	binary.LittleEndian.PutUint64(eof, 2)
	if err := setInfo(t, alice, "files", `sub\a.txt`, accessWriteData|0x00100080, smb.FileEndOfFileInformation, eof); err != nil {
		t.Fatalf("truncate through the proxy: %v", err)
	}
	if got, _ := getFile(t, direct, "data", `inner\sub\a.txt`); string(got) != "in" {
		t.Errorf("after truncating the target has %q, want \"in\"", got)
	}

	// Delete (go-smb's client opens the file and sets its delete disposition).
	if err := alice.DeleteFile("files", `sub\a.txt`); err != nil {
		t.Fatalf("delete through the proxy: %v", err)
	}
	if got := listDir(t, direct, "data", `inner\sub`); !slices.Equal(got, []string{"renamed.txt"}) {
		t.Errorf("after delete the target's inner\\sub lists %v, want [renamed.txt]", got)
	}
}

// denied fails t unless err is STATUS_ACCESS_DENIED: a refusal for any other
// reason would not show that access control refused it.
func denied(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, smb.StatusMap[smb.StatusAccessDenied]) {
		t.Errorf("%s: got %v, want STATUS_ACCESS_DENIED", what, err)
	}
}

// Readers who are not writers, and read-only shares, change nothing.
func TestIntegrationWriteRefused(t *testing.T) {
	targetPort := startTarget(t)
	direct := connect(t, targetPort, "admin", "x", "data")
	if err := direct.Mkdir("data", `inner`); err != nil {
		t.Fatal(err)
	}
	putFile(t, direct, "data", `inner\keep.txt`, []byte("original"))
	proxyPort := startProxy(t, writeConfig, targetPort)

	for _, c := range []struct{ user, pass, share string }{
		{"bob", "b", "files"}, // a reader, not a writer
		{"alice", "a", "ro"},  // a writer elsewhere, on a read-only share
	} {
		conn := connect(t, proxyPort, c.user, c.pass, c.share)
		who := c.user + " on " + c.share
		if got, err := getFile(t, conn, c.share, `keep.txt`); err != nil || string(got) != "original" {
			t.Errorf("%s cannot read: %q, %v", who, got, err)
		}
		r := bytes.NewReader([]byte("changed"))
		denied(t, who+" overwriting keep.txt", conn.PutFile(c.share, `keep.txt`, 0, r.Read))
		r = bytes.NewReader([]byte("new"))
		denied(t, who+" creating new.txt", conn.PutFile(c.share, `new.txt`, 0, r.Read))
		denied(t, who+" making a folder", conn.Mkdir(c.share, `dir`))
		denied(t, who+" deleting keep.txt", conn.DeleteFile(c.share, `keep.txt`))
		denied(t, who+" renaming keep.txt", setInfo(t, conn, c.share, `keep.txt`, accessDelete|0x00100080,
			smb.FileRenameInformation, renameInfo(false, `moved.txt`)))
	}
	if got := listDir(t, direct, "data", `inner`); !slices.Equal(got, []string{"keep.txt"}) {
		t.Errorf("the target's inner lists %v, want only keep.txt", got)
	}
	if got, _ := getFile(t, direct, "data", `inner\keep.txt`); string(got) != "original" {
		t.Errorf("keep.txt is %q on the target, want \"original\"", got)
	}
}

// sizedVFS is a target file system reporting a volume of its own, unlike
// go-smb's default sizes, so a test can tell them apart.
type sizedVFS struct {
	server.VFS
}

func (sizedVFS) QueryFSInfo(_ context.Context, class byte) (any, uint32, error) {
	le := binary.LittleEndian
	switch class {
	case fsSizeInformation: // total, available, sectors per unit, bytes per sector
		buf := le.AppendUint64(nil, 1000)
		buf = le.AppendUint64(buf, 300)
		return le.AppendUint32(le.AppendUint32(buf, 2), 4096), smb.StatusOk, nil
	case fsFullSizeInformation: // total, caller available, actual available, ...
		buf := le.AppendUint64(nil, 1000)
		buf = le.AppendUint64(buf, 250)
		buf = le.AppendUint64(buf, 300)
		return le.AppendUint32(le.AppendUint32(buf, 2), 4096), smb.StatusOk, nil
	case fsSectorSizeInformation: // 512-byte logical sectors on a 4K-sector disk
		buf := le.AppendUint32(nil, 512)
		buf = le.AppendUint32(buf, 4096)
		buf = le.AppendUint32(buf, 4096)
		buf = le.AppendUint32(buf, 512)
		buf = le.AppendUint32(buf, 0x3)
		return le.AppendUint32(le.AppendUint32(buf, 0), 0), smb.StatusOk, nil
	}
	return nil, smb.StatusNotSupported, nil
}

// A mapped drive shows the target volume's size, free space and sector sizes,
// whether the share maps a folder or the target share's root.
func TestIntegrationVolumeSize(t *testing.T) {
	sized := startTargetVFS(t, sizedVFS{memvfs.New(memvfs.Options{})})
	direct := connect(t, sized, "admin", "x", "data")
	if err := direct.Mkdir("data", `inner`); err != nil {
		t.Fatal(err)
	}
	proxyPort := startProxy(t, proxyConfig+`  - name: whole
    target: mem
    path: data
`, sized)

	for _, share := range []string{"files", "whole"} {
		conn := connect(t, proxyPort, "alice", "a", share)
		opts := smb.NewCreateReqOpts()
		opts.DesiredAccess = smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize
		opts.ShareAccess = smb.FileShareRead | smb.FileShareWrite | smb.FileShareDelete
		opts.CreateOpts = smb.FileDirectoryFile
		f, err := conn.OpenFileExt(share, "", opts)
		if err != nil {
			t.Fatalf("%s: open root: %v", share, err)
		}
		root := smbFile{File: f, share: share}
		le := binary.LittleEndian
		size, err := root.QueryFSInfo(fsSizeInformation, 64)
		if err != nil || len(size) != 24 || le.Uint64(size[0:]) != 1000 || le.Uint64(size[8:]) != 300 ||
			le.Uint32(size[20:]) != 4096 {
			t.Errorf("%s: size info = (% x, %v), want 1000 units, 300 free, 4096-byte sectors", share, size, err)
		}
		full, err := root.QueryFSInfo(fsFullSizeInformation, 64)
		if err != nil || len(full) != 32 || le.Uint64(full[0:]) != 1000 || le.Uint64(full[8:]) != 250 ||
			le.Uint64(full[16:]) != 300 {
			t.Errorf("%s: full size info = (% x, %v), want 1000 units, 250 available, 300 free", share, full, err)
		}
		sector, err := root.QueryFSInfo(fsSectorSizeInformation, 64)
		if err != nil || len(sector) != 28 || le.Uint32(sector[0:]) != 512 || le.Uint32(sector[4:]) != 4096 {
			t.Errorf("%s: sector size info = (% x, %v), want 512-byte logical, 4096-byte physical sectors", share, sector, err)
		}
		_ = f.CloseFile()
	}
}

// sharingVFS enforces share modes on a target file system, as Windows does
// (memvfs ignores them): an open asking for rights that sharing governs must
// be admitted by every such open of the file already there, and admit them.
type sharingVFS struct {
	server.VFS
	mu    sync.Mutex
	opens map[server.Handle]sharingOpen
}

type sharingOpen struct {
	path          string
	access, share uint32
}

// sharedRights pairs the rights sharing modes govern with the flag admitting
// them.
var sharedRights = []struct{ access, share uint32 }{
	{smb.FAccMaskFileReadData | smb.FAccMaskFileExecute | smb.FAccMaskGenericRead | smb.FAccMaskGenericAll, smb.FileShareRead},
	{smb.FAccMaskFileWriteData | smb.FAccMaskFileAppendData | smb.FAccMaskGenericWrite | smb.FAccMaskGenericAll, smb.FileShareWrite},
	{smb.FAccMaskDelete | smb.FAccMaskGenericAll, smb.FileShareDelete},
}

// admits reports whether an open with share mode share admits another asking
// for access.
func admits(share, access uint32) bool {
	for _, r := range sharedRights {
		if access&r.access != 0 && share&r.share == 0 {
			return false
		}
	}
	return true
}

// governed reports whether sharing modes apply to an open asking for access.
func governed(access uint32) bool {
	return !admits(0, access)
}

func (v *sharingVFS) Create(ctx context.Context, sess *server.Session, req server.CreateRequest) (server.CreateResult, uint32, error) {
	path := strings.ToLower(req.Path)
	v.mu.Lock()
	defer v.mu.Unlock()
	if governed(req.DesiredAccess) {
		for _, o := range v.opens {
			if o.path == path && governed(o.access) &&
				(!admits(o.share, req.DesiredAccess) || !admits(req.ShareAccess, o.access)) {
				return server.CreateResult{}, statusSharingViolation, nil
			}
		}
	}
	res, status, err := v.VFS.Create(ctx, sess, req)
	if err == nil && status == smb.StatusOk {
		if v.opens == nil {
			v.opens = make(map[server.Handle]sharingOpen)
		}
		v.opens[res.Handle] = sharingOpen{path, req.DesiredAccess, req.ShareAccess}
	}
	return res, status, err
}

func (v *sharingVFS) Close(ctx context.Context, h server.Handle) error {
	v.mu.Lock()
	delete(v.opens, h)
	v.mu.Unlock()
	return v.VFS.Close(ctx, h)
}

// sharingViolation fails the test unless err is STATUS_SHARING_VIOLATION.
func sharingViolation(t *testing.T, what string, err error) {
	t.Helper()
	if code, ok := ntStatus(err); !ok || code != statusSharingViolation {
		t.Errorf("%s: got %v, want STATUS_SHARING_VIOLATION", what, err)
	}
}

// The share mode a client opens a file with reaches the target, which applies
// it between the proxy's clients as Windows does between processes.
func TestIntegrationShareModes(t *testing.T) {
	targetPort := startTargetVFS(t, &sharingVFS{VFS: memvfs.New(memvfs.Options{})})
	direct := connect(t, targetPort, "admin", "x", "data")
	if err := direct.Mkdir("data", `inner`); err != nil {
		t.Fatal(err)
	}
	putFile(t, direct, "data", `inner\a.txt`, []byte("shared"))
	proxyPort := startProxy(t, writeConfig, targetPort)
	reader := connect(t, proxyPort, "alice", "a", "files") // two clients
	other := connect(t, proxyPort, "alice", "a", "files")

	const read = smb.FAccMaskFileReadData | smb.FAccMaskFileReadAttributes | smb.FAccMaskSynchronize
	const all = smb.FileShareRead | smb.FileShareWrite | smb.FileShareDelete
	open := func(conn *smb.Connection, path string, access, share uint32) (*smb.File, error) {
		opts := smb.NewCreateReqOpts()
		opts.DesiredAccess, opts.ShareAccess, opts.CreateDisp = access, share, smb.FileOpen
		return conn.OpenFileExt("files", path, opts)
	}
	rename := func(from, to string) error {
		return setInfo(t, other, "files", from, accessDelete|smb.FAccMaskSynchronize,
			smb.FileRenameInformation, renameInfo(false, to))
	}

	// A reader that admits deletion, as Explorer's preview does: the other
	// client renames the file while it is open.
	r, err := open(reader, `a.txt`, read, all)
	if err != nil {
		t.Fatalf("open for reading: %v", err)
	}
	if err := rename(`a.txt`, `b.txt`); err != nil {
		t.Errorf("rename under a reader admitting deletion: %v", err)
	}
	_ = r.CloseFile()

	// A reader that admits only reading: others may read, but neither write
	// nor rename; asking for attributes alone is never refused.
	r, err = open(reader, `b.txt`, read, smb.FileShareRead)
	if err != nil {
		t.Fatalf("open for reading: %v", err)
	}
	if f, err := open(other, `b.txt`, read, all); err != nil {
		t.Errorf("read beside a reader admitting reading: %v", err)
	} else {
		_ = f.CloseFile()
	}
	_, err = open(other, `b.txt`, accessWriteData|smb.FAccMaskSynchronize, all)
	sharingViolation(t, "write beside a reader admitting only reading", err)
	sharingViolation(t, "rename under a reader admitting only reading", rename(`b.txt`, `c.txt`))
	if f, err := open(other, `b.txt`, smb.FAccMaskFileReadAttributes, 0); err != nil {
		t.Errorf("attributes beside a reader admitting only reading: %v", err)
	} else {
		_ = f.CloseFile()
	}
	_ = r.CloseFile()

	// Once it is closed, the rename goes through.
	if err := rename(`b.txt`, `c.txt`); err != nil {
		t.Errorf("rename after the reader closed: %v", err)
	}
	if got, err := getFile(t, direct, "data", `inner\c.txt`); err != nil || string(got) != "shared" {
		t.Errorf("renamed file holds (%q, %v), want %q", got, err, "shared")
	}
}

// lsaTarget is startTarget with an LSA service on \pipe\lsarpc that names one
// account of its domain, NAS: S-1-5-21-1-2-3-1000 is NAS\alice.
func lsaTarget(t *testing.T) (port int) {
	t.Helper()
	nas := mustSID("S-1-5-21-1-2-3")
	lsa := newLSAService(&config{netbiosName: "NAS", netbiosDomain: "WORKGROUP"})
	lsa.lookup = func(sids []sid) []sidName {
		out := (&sidNamer{}).name(nil, sids)
		for i, s := range sids {
			if s.String() == "S-1-5-21-1-2-3-1000" {
				out[i] = sidName{use: mslsad.SidTypeUser, name: "alice", domain: "NAS", domainSID: nas}
			}
		}
		return out
	}
	srv := &server.Server{Config: &server.ServerConfig{
		Authenticator: &server.MapAuthenticator{Accounts: map[string]*server.Account{
			"admin": {NTHash: ntlmssp.Ntowfv1("x")},
		}},
		PipeOpener: &server.MapPipeOpener{Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			"lsarpc": func(*server.Session) (server.PipeBackend, error) {
				return &rpcPipe{inner: dcesrv.NewPipeHandler("lsarpc", lsa)}, nil
			},
		}},
	}}
	srv.RegisterShare("IPC$", server.Share{Name: "IPC$", Type: smb.ShareTypePipe, VFS: &noopVFS{}})
	srv.RegisterShare("data", server.Share{Name: "data", Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
	return serve(t, srv)
}

const sidConfig = `
server:
  listen: 127.0.0.1:0
  resolve_sids: RESOLVE
local:
  users:
    alice: {password: a}
    bob: {password: b}
targets:
  nas:
    host: 127.0.0.1
    port: TARGET_PORT
    user: admin
    password: x
shares:
  - name: files
    target: nas
    path: data
    read_access: [alice]
`

// Explorer's owner and permission names, end to end: the client asks the
// proxy's LSA, which names well-known SIDs itself and, with resolve_sids, asks
// the target behind the shares the session may read.
func TestIntegrationSIDNames(t *testing.T) {
	targetPort := lsaTarget(t)
	sids := []string{"S-1-5-21-1-2-3-1000", "S-1-5-32-544", "S-1-5-21-1-2-3-1001"}
	lookup := func(proxyPort int, user, pass string) []string {
		t.Helper()
		conn := connect(t, proxyPort, user, pass, "IPC$")
		res, err := smbConn{conn}.LookupSids(sids)
		if err != nil {
			t.Fatalf("%s: LookupSids: %v", user, err)
		}
		var names []string
		for _, n := range res.TranslatedNames {
			switch {
			case n.Use == mslsad.SidTypeUnknown:
				names = append(names, "?")
			case res.ReferencedDomains[n.DomainIndex].Name == "":
				names = append(names, n.Name)
			default:
				names = append(names, res.ReferencedDomains[n.DomainIndex].Name+`\`+n.Name)
			}
		}
		return names
	}

	resolving := startProxy(t, strings.ReplaceAll(sidConfig, "RESOLVE", "true"), targetPort)
	if got, want := lookup(resolving, "alice", "a"), []string{`NAS\alice`, `BUILTIN\Administrators`, "?"}; !slices.Equal(got, want) {
		t.Errorf("alice with resolve_sids: %q, want %q", got, want)
	}
	// bob may read no share on the target: it is not asked for him.
	if got, want := lookup(resolving, "bob", "b"), []string{"?", `BUILTIN\Administrators`, "?"}; !slices.Equal(got, want) {
		t.Errorf("bob with resolve_sids: %q, want %q", got, want)
	}

	local := startProxy(t, strings.ReplaceAll(sidConfig, "RESOLVE", "false"), targetPort)
	if got, want := lookup(local, "alice", "a"), []string{"?", `BUILTIN\Administrators`, "?"}; !slices.Equal(got, want) {
		t.Errorf("alice without resolve_sids: %q, want %q", got, want)
	}
}
