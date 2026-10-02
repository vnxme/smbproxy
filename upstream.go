package main

import (
	"encoding/hex"
	"errors"
	"log"
	"net"
	"sync"

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

type upstream struct {
	m    mapping                             // retained so a dropped link can be redialed
	dial func(mapping) (upstreamConn, error) // injectable for tests; dialConn in production
	conn upstreamConn
	mu   sync.Mutex
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

// isTransportErr reports whether err indicates a broken connection rather than
// a protocol response. The library returns every server NTSTATUS as a sentinel
// from smb.StatusMap, so anything wrapping one of those means the link is alive
// and answered; a dead socket surfaces as a plain error ("remote connection
// has closed", a net error, etc.), which is what we redial on.
func isTransportErr(err error) bool {
	if err == nil {
		return false
	}
	for _, sentinel := range smb.StatusMap {
		if errors.Is(err, sentinel) {
			return false
		}
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
// it via the smbFile adapter.
type upstreamFile interface {
	ReadFile(b []byte, offset uint64) (int, error)
	QueryDirectory(pattern string, flags byte, fileIndex uint32, bufferSize uint32) ([]smb.SharedFile, error)
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

// smbFile adapts *smb.File to upstreamFile. All methods but meta are promoted
// from the embedded pointer.
type smbFile struct{ *smb.File }

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

// openUpstream dials the target and authenticates using the NT hash derived
// from the mapping's credential (a supplied hash, or one computed from a
// password at parse time).
func openUpstream(m mapping) (*upstream, error) {
	conn, err := dialConn(m)
	if err != nil {
		return nil, err
	}
	return &upstream{m: m, dial: dialConn, conn: conn}, nil
}

// dialConn opens one authenticated connection to the target in mapping m. It is
// the production dial func stored on upstream; tests substitute their own.
func dialConn(m mapping) (upstreamConn, error) {
	hashBytes, err := hex.DecodeString(m.ntHex)
	if err != nil {
		return nil, err
	}
	conn, err := smb.NewConnection(smb.Options{
		Host: m.remoteHost,
		Port: 445,
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
	})
	if err != nil {
		return nil, err
	}
	return smbConn{conn}, nil
}

// dialectByName maps the -max-dialect flag value to the go-smb constant.
var dialectByName = map[string]uint16{
	"2.1":   smb.DialectSmb_2_1,
	"3.0":   smb.DialectSmb_3_0,
	"3.0.2": smb.DialectSmb_3_0_2,
	"3.1.1": smb.DialectSmb_3_1_1,
}
