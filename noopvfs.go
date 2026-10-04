package main

import (
	"context"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

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
