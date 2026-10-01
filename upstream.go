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
	conn *smb.Connection
	mu   sync.Mutex
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
	return &upstream{conn: conn}, nil
}

// dialectByName maps the -max-dialect flag value to the go-smb constant.
var dialectByName = map[string]uint16{
	"2.0.2": smb.DialectSmb_2_0_2,
	"2.1":   smb.DialectSmb_2_1,
	"3.0":   smb.DialectSmb_3_0,
	"3.0.2": smb.DialectSmb_3_0_2,
	"3.1.1": smb.DialectSmb_3_1_1,
}
