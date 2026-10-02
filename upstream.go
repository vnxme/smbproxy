package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

// ---------------------------------------------------------------------------
// upstream — shared connection + mutex
//
// Multiple proxyVFS instances that point to the same (host, user, domain,
// credential) target share one *upstream, so that all their upstream calls are
// serialized by a single mutex rather than each VFS thinking it has exclusive
// access to the conn.
// ---------------------------------------------------------------------------

// upstream is connected lazily: conn stays nil until a client first touches the
// share, and the idle reaper closes it again (resetting conn to nil) after a
// period with no open handles and no activity. The next client access redials.
// refs counts open upstream file handles; a connection with live handles is
// never reaped, since closing it would invalidate those handles mid-use.
type upstream struct {
	m         mapping                             // retained so the link can be (re)dialed on demand
	dial      func(mapping) (upstreamConn, error) // injectable for tests; dialConn in production
	idle      time.Duration                       // reap after this much inactivity (0 = never reap)
	ioTimeout time.Duration                       // bound on one request on an open file (0 = none)

	mu      sync.Mutex
	conn    upstreamConn // nil when not currently connected
	refs    int          // open upstream file handles
	lastUse time.Time    // updated on every operation and handle release
}

// upstreamTimeouts bounds how long the proxy waits on a target. A zero value
// disables the corresponding limit.
type upstreamTimeouts struct {
	idle    time.Duration // close an unused connection after this long
	connect time.Duration // connect and log in, as a whole
	io      time.Duration // one read or directory request on an open file
}

// newUpstream builds a lazily-connected upstream for mapping m. No network
// connection is made until the first operation; t bounds how long an unused
// connection is kept, connecting, and each request on an open file.
func newUpstream(m mapping, t upstreamTimeouts) *upstream {
	return &upstream{
		m:         m,
		dial:      func(m mapping) (upstreamConn, error) { return dialConn(m, t.connect) },
		idle:      t.idle,
		ioTimeout: t.io,
	}
}

// ioContext returns the context bounding one request on an open file: a
// deadline of u.ioTimeout, or none when that is zero. go-smb's server never
// passes a client's cancellation to the VFS, so this limit is what keeps a
// target that stops answering from holding u.mu, and with it every client of
// this connection, indefinitely.
func (u *upstream) ioContext() (context.Context, context.CancelFunc) {
	if u.ioTimeout <= 0 {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), u.ioTimeout)
}

// connectError marks a failure to establish the upstream connection, as
// opposed to a failure of an operation on an established one; errToStatus
// reports the two differently to the client.
type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }
func (e *connectError) Unwrap() error { return e.err }

// ensureConn dials the upstream if it is not currently connected. The caller
// must hold u.mu. A dial failure is logged (with a cause-specific hint) and
// returned, as a *connectError, so it surfaces to the client as the
// operation's status.
func (u *upstream) ensureConn() error {
	if u.conn != nil {
		return nil
	}
	log.Printf("[*] connecting to \\\\%s\\%s as %s\\%s ...",
		u.m.remoteHost, u.m.remoteShare, u.m.domain, u.m.user)
	c, err := u.dial(u.m)
	if err != nil {
		log.Printf("[!] upstream connect \\\\%s as %s\\%s failed: %v\n%s",
			u.m.remoteHost, u.m.domain, u.m.user, err, connectFailureHint(err))
		return &connectError{err}
	}
	u.conn = c
	log.Printf("[+] connected to %s as %s\\%s", u.m.remoteHost, u.m.domain, u.m.user)
	return nil
}

// hold records that a client opened an upstream file handle, pinning the
// connection open against the idle reaper until the matching release.
func (u *upstream) hold() {
	u.mu.Lock()
	u.refs++
	u.lastUse = time.Now()
	u.mu.Unlock()
}

// release drops one handle recorded by hold and restarts the idle clock, so the
// timeout is measured from the moment the last handle closed.
func (u *upstream) release() {
	u.mu.Lock()
	if u.refs > 0 {
		u.refs--
	}
	u.lastUse = time.Now()
	u.mu.Unlock()
}

// reapIfIdle closes the connection when it is open, has no live handles, and has
// been idle for at least u.idle; conn is reset to nil so the next access
// redials. It reports whether it closed one. A non-positive idle disables it.
func (u *upstream) reapIfIdle(now time.Time) bool {
	if u.idle <= 0 {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn == nil || u.refs > 0 || now.Sub(u.lastUse) < u.idle {
		return false
	}
	log.Printf("[*] upstream %s idle for %s; closing", u.m.remoteHost, now.Sub(u.lastUse).Round(time.Second))
	u.conn.Close()
	u.conn = nil
	return true
}

// close tears the connection down (if any) at shutdown; safe to call when not
// connected.
func (u *upstream) close() {
	u.mu.Lock()
	if u.conn != nil {
		u.conn.Close()
		u.conn = nil
	}
	u.mu.Unlock()
}

// do runs a connection-level operation under the upstream lock. If fn fails
// with what looks like a dead connection (see isTransportErr), it redials once
// and retries fn on the fresh connection. The lock is held across the redial
// so no other operation observes a half-swapped conn.
//
// Only connection-level entry points (opening a handle, enumerating the share
// root) go through do. Operations on an already-open file handle do not: a
// redial yields a new connection on which the old handle is invalid, so a
// retry there is pointless and a false-positive transport error must not tear
// down a handle that is still in use. Those paths recover when the client
// re-opens the handle, which routes back through do via Create.
func (u *upstream) do(fn func(c upstreamConn) error) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if err := u.ensureConn(); err != nil {
		return err
	}
	u.lastUse = time.Now()

	err := fn(u.conn)
	if !isTransportErr(err) {
		return err
	}
	log.Printf("[*] upstream %s connection error (%v); reconnecting...", u.m.remoteHost, err)
	if rerr := u.redial(); rerr != nil {
		log.Printf("[!] upstream %s reconnect failed: %v", u.m.remoteHost, rerr)
		return err // surface the original failure, not the reconnect error
	}
	log.Printf("[+] upstream %s reconnected", u.m.remoteHost)
	u.lastUse = time.Now()
	return fn(u.conn)
}

// redial opens a fresh authenticated connection and swaps it in, closing the
// old one. The caller must hold u.mu.
func (u *upstream) redial() error {
	c, err := u.dial(u.m)
	if err != nil {
		return err
	}
	if u.conn != nil {
		u.conn.Close()
	}
	u.conn = c
	return nil
}

// isNetworkError reports whether err is a TCP-level failure (connection
// refused, timeout, no route, DNS) rather than an SMB/auth error. The library
// returns net.DialTimeout's error unwrapped, so *net.OpError and *net.DNSError
// — both net.Error — are visible to errors.As. Used to tailor the connect
// failure hint: a refused dial means nothing is listening (SMB off / wrong
// host or port / firewall), not a credential problem.
func isNetworkError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr)
}

// isTransportErr reports whether err means the upstream connection is no
// longer usable, so do should redial. An NTSTATUS answer (see ntStatus) means
// the link is alive, except for the codes reporting that the target dropped
// this connection's session or tree (see sessionLost), which only a fresh
// connection cures. Anything else, a dead socket surfacing as a plain error
// ("remote connection has closed", a net error, a timeout), is a transport
// failure.
func isTransportErr(err error) bool {
	if err == nil {
		return false
	}
	if code, answered := ntStatus(err); answered {
		return sessionLost(code)
	}
	return true
}

// upstreamConn is the subset of *smb.Connection the proxy uses. Abstracting it
// behind an interface lets proxyVFS be driven by a fake in tests, without a
// live SMB server. *smb.Connection satisfies it via the smbConn adapter.
type upstreamConn interface {
	// OpenFileExt returns an upstreamFile rather than the library's concrete
	// *smb.File, so the whole handle path stays mockable.
	OpenFileExt(tree, filepath string, opts *smb.CreateReqOpts) (upstreamFile, error)
	TreeConnect(name string) error
	ListDirectory(share, dir, pattern string) ([]smb.SharedFile, error)
	Close()
}

// upstreamFile is the subset of *smb.File the proxy uses. *smb.File satisfies
// it via the smbFile adapter. Reads and directory queries take a context so
// they can be bounded (see upstream.ioContext); go-smb offers no context-aware
// variant of the other calls.
type upstreamFile interface {
	ReadFile(ctx context.Context, b []byte, offset uint64) (int, error)
	QueryDirectory(ctx context.Context, pattern string, flags byte, fileIndex uint32, bufferSize uint32) ([]smb.SharedFile, error)
	// QuerySecurity fetches the file's security descriptor from the target,
	// requesting the components named in additionalInformation, and returns it
	// as self-relative wire bytes ready to hand back to the client.
	QuerySecurity(additionalInformation uint32) ([]byte, error)
	CloseFile() error
	IsDir() bool
	// meta snapshots the metadata fields the proxy reads off a freshly opened
	// file; an interface cannot expose the library struct's fields directly.
	meta() fileMeta
}

// fileMeta is a snapshot of the smb.FileMetadata fields handleFromFile needs.
type fileMeta struct {
	attributes     uint32
	endOfFile      uint64
	creationTime   uint64
	lastAccessTime uint64
	lastWriteTime  uint64
	changeTime     uint64
}

// smbConn adapts *smb.Connection to upstreamConn. TreeConnect, ListDirectory
// and Close are promoted from the embedded pointer; only OpenFileExt needs an
// explicit wrapper to change its return type to the upstreamFile interface.
type smbConn struct{ *smb.Connection }

func (c smbConn) OpenFileExt(tree, filepath string, opts *smb.CreateReqOpts) (upstreamFile, error) {
	f, err := c.Connection.OpenFileExt(tree, filepath, opts)
	if err != nil {
		return nil, err
	}
	return smbFile{f}, nil
}

// smbFile adapts *smb.File to upstreamFile. CloseFile and IsDir are promoted
// from the embedded pointer; ReadFile and QueryDirectory map to the library's
// context-aware variants.
type smbFile struct{ *smb.File }

func (f smbFile) ReadFile(ctx context.Context, b []byte, offset uint64) (int, error) {
	return f.File.ReadFileContext(ctx, b, offset)
}

func (f smbFile) QueryDirectory(ctx context.Context, pattern string, flags byte, fileIndex, bufferSize uint32) ([]smb.SharedFile, error) {
	return f.File.QueryDirectoryContext(ctx, pattern, flags, fileIndex, bufferSize)
}

func (f smbFile) meta() fileMeta {
	return fileMeta{
		attributes:     f.Attributes,
		endOfFile:      f.EndOfFile,
		creationTime:   f.CreationTime,
		lastAccessTime: f.LastAccessTime,
		lastWriteTime:  f.LastWriteTime,
		changeTime:     f.ChangeTime,
	}
}

// QuerySecurity queries the target for the file's security descriptor and
// re-serializes it to self-relative wire bytes. A zero bufferSize lets the
// library pick a default and grow it if the DACL overflows.
func (f smbFile) QuerySecurity(additionalInformation uint32) ([]byte, error) {
	sd, err := f.File.QueryInfoSecurityRaw(additionalInformation, 0)
	if err != nil {
		return nil, err
	}
	return sd.MarshalBinary()
}

// dialConn opens one authenticated connection to the target in mapping m,
// giving up after timeout (0 = no limit). It is the production dial func
// stored on upstream; tests substitute their own.
func dialConn(m mapping, timeout time.Duration) (upstreamConn, error) {
	hashBytes, err := hex.DecodeString(m.ntHex)
	if err != nil {
		return nil, err
	}
	opts := smb.Options{
		Host:        m.remoteHost,
		Port:        445,
		DialTimeout: timeout, // the TCP connect; connectWithin bounds the rest
		// SMB2Only skips the SMB1 multiprotocol probe, sending a direct SMB2
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
	}
	return connectWithin(timeout, func() (upstreamConn, error) {
		conn, err := smb.NewConnection(opts)
		if err != nil {
			return nil, err
		}
		return smbConn{conn}, nil
	})
}

// connectWithin runs connect, giving up after timeout (0 = wait indefinitely).
// go-smb bounds only the TCP connect (Options.DialTimeout): its negotiation
// and login take no context, so a target that accepts the connection but
// never answers would block forever. On timeout connect keeps running in the
// background, and a connection it still establishes is closed. The timeout
// error wraps os.ErrDeadlineExceeded, a net.Error, so connectFailureHint
// reports it as a reachability problem.
func connectWithin(timeout time.Duration, connect func() (upstreamConn, error)) (upstreamConn, error) {
	if timeout <= 0 {
		return connect()
	}
	type result struct {
		conn upstreamConn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := connect()
		done <- result{c, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-timer.C:
		go func() {
			if r := <-done; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, fmt.Errorf("no answer within %s: %w", timeout, os.ErrDeadlineExceeded)
	}
}

// dialectByName maps the -max-dialect flag value to the go-smb constant.
var dialectByName = map[string]uint16{
	"2.1":   smb.DialectSmb_2_1,
	"3.0":   smb.DialectSmb_3_0,
	"3.0.2": smb.DialectSmb_3_0_2,
	"3.1.1": smb.DialectSmb_3_1_1,
}
