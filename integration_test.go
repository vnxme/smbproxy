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
	"testing"
	"time"

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
	srv := &server.Server{Config: &server.ServerConfig{
		Authenticator: &server.MapAuthenticator{Accounts: map[string]*server.Account{
			"admin": {NTHash: ntlmssp.Ntowfv1("x")},
		}},
		MaxReadSize:  1 << 20,
		MaxWriteSize: 1 << 20,
	}}
	srv.RegisterShare("data", server.Share{Name: "data", Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
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
