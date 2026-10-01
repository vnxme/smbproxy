package main

import (
	"context"
	"testing"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// noopVFS exists so IPC$ never has a nil VFS; every call must return a
// non-panicking refusal the server can fall back from.
func TestNoopVFS(t *testing.T) {
	v := &noopVFS{}
	ctx := context.Background()
	buf := make([]byte, 16)

	_, createSt, createErr := v.Create(ctx, nil, server.CreateRequest{})
	readN, readSt, readErr := v.Read(ctx, nil, 0, buf)
	writeN, writeSt, writeErr := v.Write(ctx, nil, 0, buf)
	flushSt, flushErr := v.Flush(ctx, nil)
	entries, dirSt, dirErr := v.QueryDirectory(ctx, nil, "*", false)
	fileInfo, fileInfoSt, fileInfoErr := v.QueryFileInfo(ctx, nil, 0)
	setSt, setErr := v.SetFileInfo(ctx, nil, 0, buf)
	fsInfo, fsSt, fsErr := v.QueryFSInfo(ctx, 0)
	sec, secSt, secErr := v.QuerySecurity(ctx, nil, 0)
	ioOut, ioSt, ioErr := v.Ioctl(ctx, nil, 0, buf, 0)

	cases := []struct {
		name   string
		status uint32
		want   uint32
		err    error
	}{
		{"Create", createSt, smb.StatusObjectNameNotFound, createErr},
		{"Read", readSt, smb.StatusAccessDenied, readErr},
		{"Write", writeSt, smb.StatusAccessDenied, writeErr},
		{"Flush", flushSt, smb.StatusOk, flushErr},
		{"QueryDirectory", dirSt, smb.StatusNoMoreFiles, dirErr},
		{"QueryFileInfo", fileInfoSt, smb.StatusNotSupported, fileInfoErr},
		{"SetFileInfo", setSt, smb.StatusAccessDenied, setErr},
		{"QueryFSInfo", fsSt, smb.StatusNotSupported, fsErr},
		{"QuerySecurity", secSt, smb.StatusNotSupported, secErr},
		{"Ioctl", ioSt, smb.StatusNotSupported, ioErr},
	}
	for _, c := range cases {
		if c.status != c.want || c.err != nil {
			t.Errorf("%s: status=0x%08x err=%v, want status=0x%08x err=nil", c.name, c.status, c.err, c.want)
		}
	}

	if readN != 0 || writeN != 0 {
		t.Errorf("Read/Write transferred %d/%d bytes, want 0/0", readN, writeN)
	}
	if entries != nil || fileInfo != nil || fsInfo != nil || sec != nil || ioOut != nil {
		t.Errorf("query methods returned data, want nil for all")
	}
	if err := v.Close(ctx, nil); err != nil {
		t.Errorf("Close: %v, want nil", err)
	}
}
