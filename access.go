package main

import (
	"slices"
	"strings"

	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ---------------------------------------------------------------------------
// Share access control — who may open which share (a share's read_access)
// ---------------------------------------------------------------------------

// Reserved read_access entries for sessions that are not a local user.
const (
	accessGuests    = "@guests"    // guest sessions (local.allow_guest)
	accessAnonymous = "@anonymous" // null sessions (local.allow_anonymous)
)

// principal is who a session acts as: a local user, a guest, or anonymous.
type principal struct {
	user      string // lower-cased local user name; "" for guests and anonymous
	guest     bool
	anonymous bool
}

// principalOf returns who session s acts as. The guest and null flags are
// checked first: a guest session keeps whatever user name the client sent, so
// a failed login as a real user that falls back to guest must not count as
// that user.
func principalOf(s *server.Session) principal {
	switch {
	case s.Flags&smb.SessionFlagIsNull != 0:
		return principal{anonymous: true}
	case s.Flags&smb.SessionFlagIsGuest != 0:
		return principal{guest: true}
	}
	return principal{user: strings.ToLower(s.Username)}
}

func (p principal) String() string {
	switch {
	case p.anonymous:
		return "anonymous"
	case p.guest:
		return "guest"
	}
	return "user " + p.user
}

// accessList is a share's resolved read_access: the local users who may open
// it, with groups expanded, and whether guests and anonymous sessions may.
type accessList struct {
	users     map[string]bool // lower-cased user names
	guests    bool
	anonymous bool
	spec      []string // the read_access entries as configured, for logs
}

// String describes the list for logs: the configured entries, or "everyone"
// for a nil list.
func (a *accessList) String() string {
	if a == nil {
		return "everyone"
	}
	if len(a.spec) == 0 {
		return "no one"
	}
	return strings.Join(a.spec, ", ")
}

// allows reports whether p may open a share with access list a. A nil list (no
// read_access) admits everyone who can log in.
func (a *accessList) allows(p principal) bool {
	switch {
	case a == nil:
		return true
	case p.anonymous:
		return a.anonymous
	case p.guest:
		return a.guests
	}
	return a.users[p.user]
}

// readAllowed reports whether p may open the share named name (compared
// case-insensitively, as SMB does). Names that are not proxied shares, such
// as IPC$, are left to go-smb.
func (c *config) readAllowed(name string, p principal) bool {
	for i := range c.shares {
		if strings.EqualFold(c.shares[i].name, name) {
			return c.shares[i].readAccess.allows(p)
		}
	}
	return true
}

// localUserNames returns the local users' names as configured, sorted.
func (c *config) localUserNames() []string {
	names := make([]string, 0, len(c.localUsers))
	for _, u := range c.localUsers {
		names = append(names, u.name)
	}
	slices.Sort(names)
	return names
}

// visibleShares filters a share listing down to the shares p may open, for
// server.hide_inaccessible_shares; entries that are not proxied shares, such
// as IPC$, stay listed.
func (c *config) visibleShares(entries []srvsvc.ShareEntry, p principal) []srvsvc.ShareEntry {
	var out []srvsvc.ShareEntry
	for _, e := range entries {
		if c.readAllowed(e.Name, p) {
			out = append(out, e)
		}
	}
	return out
}
