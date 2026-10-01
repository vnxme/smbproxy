package main

import (
	"encoding/hex"
	"sync"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

// ---------------------------------------------------------------------------
// upstream — shared connection + mutex
//
// Multiple proxyVFS instances that point to the same (host, user, hash) share
// one *upstream so that all their upstream calls are serialized by a single
// mutex rather than each VFS thinking it has exclusive access to the conn.
// ---------------------------------------------------------------------------

type upstream struct {
	conn upstreamConn
	mu   sync.Mutex
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
	return &upstream{conn: smbConn{conn}}, nil
}

// dialectByName maps the -max-dialect flag value to the go-smb constant.
var dialectByName = map[string]uint16{
	"2.1":   smb.DialectSmb_2_1,
	"3.0":   smb.DialectSmb_3_0,
	"3.0.2": smb.DialectSmb_3_0_2,
	"3.1.1": smb.DialectSmb_3_1_1,
}
