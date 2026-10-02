package main

import (
	"encoding/hex"
	"fmt"
	"os"
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
	remoteSub   string // optional inner directory within the share (empty = share root)
	user        string
	domain      string
	ntHex       string // normalized 32-char NTLM hash (lowercase)
}

// splitSharePath separates the remote-share field into the SMB share name and
// an optional inner directory, split on the first backslash:
//
//	"C$"               → ("C$", "")
//	"C$\Users\Public"  → ("C$", "Users\Public")
//
// This lets a local share map to a subfolder of the target share rather than
// its root. Surrounding backslashes on the subpath are trimmed; SMB share names
// contain no backslash, so the first one always begins the subpath.
func splitSharePath(s string) (share, sub string) {
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		return s[:i], strings.Trim(s[i+1:], "\\")
	}
	return s, ""
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
// The share field may carry an inner directory after the share name, e.g.
// "C$\Users\Public", which maps the local share to that subfolder of the target
// share instead of its root (see splitSharePath).
//
// The credential is the secret used to reach that target, interpreted as:
//   - "pass:<password>"   → explicit password (everything after the first
//     colon, so a password may contain ':' or even be 32 hex chars without
//     being mistaken for a hash)
//   - 32 hex chars        → an NTLM hash, used directly
//   - "<lmhash>:<nthash>" → an LM:NT pair; only the NT half is used
//   - anything else       → a password
//
// Passwords are converted to their NT hash via NTOWFv1 up front, so the rest
// of the proxy (dedup keying, openUpstream) only ever handles a 32-char NT
// hash; every credential form is equivalent from the target's point of view.
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

	rshare, rsub := splitSharePath(parts[2])
	if rshare == "" {
		return mapping{}, fmt.Errorf("-map remote share name is empty in %q", s)
	}

	return mapping{
		localShare:  parts[0],
		remoteHost:  parts[1],
		remoteShare: rshare,
		remoteSub:   rsub,
		user:        parts[3],
		domain:      parts[4],
		ntHex:       ntHex,
	}, nil
}

// readMapFile reads map-formatted lines from a file supplied via -mapfile.
// Each kept line has the same syntax as a -map value, so credentials can live
// in a file (with restricted permissions) instead of the process argument
// list. Lines are returned in file order; parseMapping validates them later.
func readMapFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseMapLines(string(data)), nil
}

// parseMapLines splits map-file content into raw map strings. Surrounding
// whitespace is trimmed (so CRLF files work), and blank lines and lines whose
// first non-space character is '#' are dropped. A '#' elsewhere is left intact,
// since a password may legitimately contain one.
func parseMapLines(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// connKey identifies a unique upstream SMB session.
type connKey struct{ host, user, domain, ntHex string }

func (m mapping) key() connKey {
	return connKey{m.remoteHost, m.user, m.domain, m.ntHex}
}
