package main

import (
	"context"
	"log"

	"github.com/jfjallid/go-smb/smb/server"
)

// ---------------------------------------------------------------------------
// tracingVFS — -debug wrapper that logs every VFS call and its outcome
//
// go-smb logs only failed operations, so a reply that succeeds but carries
// something a client rejects leaves no trace. Wrapping each share's VFS under
// -debug logs every call with its result, showing exactly what a client asked
// for and what it got back.
// ---------------------------------------------------------------------------

type tracingVFS struct {
	share string
	inner server.VFS
}

// handlePath returns h's client path for logging; h may be nil.
func handlePath(h server.Handle) string {
	if h == nil {
		return "<nil>"
	}
	return h.Path()
}

func (t *tracingVFS) logf(format string, args ...any) {
	log.Printf("[vfs %s] "+format, append([]any{t.share}, args...)...)
}

func (t *tracingVFS) Create(ctx context.Context, sess *server.Session, req server.CreateRequest) (server.CreateResult, uint32, error) {
	res, status, err := t.inner.Create(ctx, sess, req)
	t.logf("Create %q access=0x%08x options=0x%08x disp=%d -> status=0x%08x err=%v size=%d attrs=0x%08x fileID=%x",
		req.Path, req.DesiredAccess, req.CreateOptions, req.CreateDisposition,
		status, err, res.Info.Size, res.Info.Attributes, res.Info.FileID)
	return res, status, err
}

func (t *tracingVFS) Close(ctx context.Context, h server.Handle) error {
	err := t.inner.Close(ctx, h)
	t.logf("Close %q -> err=%v", handlePath(h), err)
	return err
}

func (t *tracingVFS) Read(ctx context.Context, h server.Handle, offset int64, buf []byte) (int, uint32, error) {
	n, status, err := t.inner.Read(ctx, h, offset, buf)
	t.logf("Read %q off=%d len=%d -> n=%d status=0x%08x err=%v", handlePath(h), offset, len(buf), n, status, err)
	return n, status, err
}

func (t *tracingVFS) Write(ctx context.Context, h server.Handle, offset int64, data []byte) (int, uint32, error) {
	n, status, err := t.inner.Write(ctx, h, offset, data)
	t.logf("Write %q off=%d len=%d -> n=%d status=0x%08x err=%v", handlePath(h), offset, len(data), n, status, err)
	return n, status, err
}

func (t *tracingVFS) Flush(ctx context.Context, h server.Handle) (uint32, error) {
	status, err := t.inner.Flush(ctx, h)
	t.logf("Flush %q -> status=0x%08x err=%v", handlePath(h), status, err)
	return status, err
}

func (t *tracingVFS) QueryFileInfo(ctx context.Context, h server.Handle, class byte) (any, uint32, error) {
	out, status, err := t.inner.QueryFileInfo(ctx, h, class)
	b, _ := out.([]byte)
	t.logf("QueryFileInfo %q class=0x%02x -> status=0x%08x err=%v (%d bytes; 0xc00000bb = library fallback)",
		handlePath(h), class, status, err, len(b))
	return out, status, err
}

func (t *tracingVFS) SetFileInfo(ctx context.Context, h server.Handle, class byte, raw []byte) (uint32, error) {
	status, err := t.inner.SetFileInfo(ctx, h, class, raw)
	t.logf("SetFileInfo %q class=0x%02x len=%d -> status=0x%08x err=%v", handlePath(h), class, len(raw), status, err)
	return status, err
}

func (t *tracingVFS) QueryDirectory(ctx context.Context, h server.Handle, pattern string, restart bool) ([]server.DirEntry, uint32, error) {
	entries, status, err := t.inner.QueryDirectory(ctx, h, pattern, restart)
	t.logf("QueryDirectory %q pattern=%q restart=%t -> %d entries status=0x%08x err=%v",
		handlePath(h), pattern, restart, len(entries), status, err)
	for i, e := range entries {
		if i == 5 {
			t.logf("  ... %d more", len(entries)-5)
			break
		}
		t.logf("  %q size=%d attrs=0x%08x fileID=%x", e.Name, e.Size, e.Attributes, e.FileID)
	}
	return entries, status, err
}

func (t *tracingVFS) QueryFSInfo(ctx context.Context, class byte) (any, uint32, error) {
	out, status, err := t.inner.QueryFSInfo(ctx, class)
	b, _ := out.([]byte)
	t.logf("QueryFSInfo class=0x%02x -> status=0x%08x err=%v (%d bytes; 0xc00000bb = library fallback)",
		class, status, err, len(b))
	return out, status, err
}

func (t *tracingVFS) QuerySecurity(ctx context.Context, h server.Handle, addInfo uint32) ([]byte, uint32, error) {
	sd, status, err := t.inner.QuerySecurity(ctx, h, addInfo)
	t.logf("QuerySecurity %q info=0x%08x -> status=0x%08x err=%v (%d bytes)", handlePath(h), addInfo, status, err, len(sd))
	return sd, status, err
}

func (t *tracingVFS) Ioctl(ctx context.Context, h server.Handle, code uint32, in []byte, maxOut uint32) ([]byte, uint32, error) {
	out, status, err := t.inner.Ioctl(ctx, h, code, in, maxOut)
	t.logf("Ioctl %q code=0x%08x in=%d maxOut=%d -> status=0x%08x err=%v (%d bytes)",
		handlePath(h), code, len(in), maxOut, status, err, len(out))
	return out, status, err
}
