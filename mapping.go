package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/ntlmssp"
)

// ---------------------------------------------------------------------------
// Flag helpers
// ---------------------------------------------------------------------------

// multiFlag is a repeatable string flag.
type multiFlag []string

func (f *multiFlag) String() string     { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(s string) error { *f = append(*f, s); return nil }

// ---------------------------------------------------------------------------
// Mapping — one proxied share
// ---------------------------------------------------------------------------

// mapping describes a single local-share → remote-share binding.
type mapping struct {
	localShare  string // name exposed to clients (e.g. "corp_c")
	remoteHost  string // target IP or hostname
	remoteShare string // share on the target (e.g. "C$")
	user        string
	domain      string
	ntHex       string // normalized 32-char NTLM hash (lowercase)
}

// isNTHash reports whether s is exactly 32 hexadecimal characters — i.e. a
// bare NT hash with no LM-hash prefix.
func isNTHash(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// parseMapping parses one -map value: local:host:share:user:domain:credential
// SplitN with n=6 keeps any colon inside the credential field intact.
//
// The credential field is interpreted as follows:
//   - "pass:<password>"   → explicit password (everything after the first
//     colon, so a password may contain ':' or even be 32 hex chars without
//     being mistaken for a hash)
//   - 32 hex chars        → NT hash (pass-the-hash)
//   - "<lmhash>:<nthash>" → LM:NT pair; only the NT half is used
//   - anything else       → password
//
// Passwords are converted to their NT hash via NTOWFv1 up front, so the rest
// of the proxy (dedup keying, openUpstream) only ever deals with a 32-char
// hash; from the target's perspective password and pass-the-hash auth are
// equivalent for NTLM.
func parseMapping(s string) (mapping, error) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 {
		return mapping{}, fmt.Errorf(
			"-map value must be local_share:host:share:user:domain:credential, got %q", s)
	}
	for i, p := range parts[:5] {
		if p == "" {
			return mapping{}, fmt.Errorf(
				"-map field %d is empty in %q", i, s)
		}
	}
	cred := parts[5]
	if cred == "" {
		return mapping{}, fmt.Errorf("-map credential field is empty in %q", s)
	}

	var ntHex string
	switch {
	case strings.HasPrefix(cred, "pass:"):
		// Explicit password; everything after "pass:" is taken verbatim.
		ntHex = hex.EncodeToString(ntlmssp.Ntowfv1(cred[len("pass:"):]))
	default:
		// Auto-detect: a bare NT hash, or the NT half of a "lmhash:nthash"
		// pair, is used as-is; everything else is treated as a password.
		h := cred
		if idx := strings.LastIndexByte(h, ':'); idx >= 0 {
			h = h[idx+1:] // strip the LM-hash prefix, if any
		}
		if isNTHash(h) {
			ntHex = strings.ToLower(h)
		} else {
			ntHex = hex.EncodeToString(ntlmssp.Ntowfv1(cred))
		}
	}

	return mapping{
		localShare:  parts[0],
		remoteHost:  parts[1],
		remoteShare: parts[2],
		user:        parts[3],
		domain:      parts[4],
		ntHex:       ntHex,
	}, nil
}

// connKey identifies a unique upstream SMB session.
type connKey struct{ host, user, domain, ntHex string }

func (m mapping) key() connKey {
	return connKey{m.remoteHost, m.user, m.domain, m.ntHex}
}
