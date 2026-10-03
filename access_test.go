package main

import (
	"maps"
	"slices"
	"strings"
	"testing"

	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// accessConfig has three users, a group, and one share per kind of
// read_access, with guest and anonymous logins enabled.
const accessConfig = `
local:
  allow_guest: true
  allow_anonymous: true
  users:
    alice: {password: a}
    bob:   {password: b}
    carol: {password: c}
  groups:
    finance: [alice, Bob]
targets:
  t1:
    host: 10.0.0.5
    user: admin
    password: x
shares:
  - {name: open,     target: t1, path: A$}
  - {name: alice,    target: t1, path: B$, read_access: [ALICE]}
  - {name: finance,  target: t1, path: C$, read_access: ["@Finance"]}
  - {name: guests,   target: t1, path: D$, read_access: ["@guests", carol]}
  - {name: anon,     target: t1, path: E$, read_access: ["@anonymous"]}
  - {name: nobody,   target: t1, path: F$, read_access: []}
`

func session(user string, flags uint16) *server.Session {
	return &server.Session{Username: user, Flags: flags, Authenticated: true}
}

var (
	asAlice     = session("Alice", 0) // names compare case-insensitively
	asBob       = session("bob", 0)
	asCarol     = session("carol", 0)
	asGuest     = session("alice", smb.SessionFlagIsGuest) // failed login as alice, fallen back to guest
	asAnonymous = session("", smb.SessionFlagIsNull)
)

// The tree-connect hook, as go-smb calls it, admits each session exactly to
// the shares its read_access names.
func TestReadAccessEnforced(t *testing.T) {
	cfg, warnings := mustParse(t, accessConfig)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "no one can open it") {
		t.Errorf("warnings = %v, want one about the empty list of share nobody", warnings)
	}
	hook := cfg.serverConfig().OnTreeConnect
	cases := []struct {
		share   string
		allowed []*server.Session
	}{
		{"open", []*server.Session{asAlice, asBob, asCarol, asGuest, asAnonymous}},
		{"ALICE", []*server.Session{asAlice}}, // share names compare case-insensitively too
		{"finance", []*server.Session{asAlice, asBob}},
		{"guests", []*server.Session{asCarol, asGuest}},
		{"anon", []*server.Session{asAnonymous}},
		{"nobody", nil},
		{"IPC$", []*server.Session{asAlice, asBob, asCarol, asGuest, asAnonymous}}, // left to go-smb
	}
	names := map[*server.Session]string{asAlice: "alice", asBob: "bob", asCarol: "carol", asGuest: "guest", asAnonymous: "anonymous"}
	for _, c := range cases {
		for _, s := range []*server.Session{asAlice, asBob, asCarol, asGuest, asAnonymous} {
			want := false
			for _, a := range c.allowed {
				want = want || a == s
			}
			st, err := hook(nil, s, c.share, &smb.TreeConnectReq{}, &smb.TreeConnectRes{})
			if err != nil {
				t.Fatalf("hook: %v", err)
			}
			if got := st == nil; got != want {
				t.Errorf("%s opening %s: allowed=%t, want %t", names[s], c.share, got, want)
			}
			if st != nil && st.Code != smb.StatusAccessDenied {
				t.Errorf("%s opening %s: status 0x%08x, want STATUS_ACCESS_DENIED", names[s], c.share, st.Code)
			}
		}
	}
}

// A guest session keeps the user name the client sent; it must still count as
// a guest, not as that user.
func TestPrincipalOfGuestIgnoresName(t *testing.T) {
	if p := principalOf(asGuest); !p.guest || p.user != "" {
		t.Errorf("guest session as %+v, want a guest with no user", p)
	}
	if p := principalOf(asAnonymous); !p.anonymous {
		t.Errorf("null session as %+v, want anonymous", p)
	}
	if p := principalOf(asAlice); p.user != "alice" || p.guest || p.anonymous {
		t.Errorf("user session as %+v, want user alice", p)
	}
}

// Reserved names that can never match are flagged.
func TestReadAccessReservedWarnings(t *testing.T) {
	yaml := minimalConfig + "    read_access: [\"@guests\", \"@Anonymous\"]\n"
	_, warnings := mustParse(t, yaml)
	if len(warnings) != 2 || !strings.Contains(warnings[0], "allow_guest is off") ||
		!strings.Contains(warnings[1], "allow_anonymous is off") {
		t.Errorf("warnings = %v, want one each for @guests and @anonymous", warnings)
	}
}

// With hide_inaccessible_shares, a session's share listing leaves out the
// shares it may not open, but keeps entries that are not proxied shares.
func TestVisibleShares(t *testing.T) {
	cfg, _ := mustParse(t, accessConfig)
	all := []srvsvc.ShareEntry{{Name: "IPC$"}, {Name: "open"}, {Name: "alice"}, {Name: "finance"},
		{Name: "guests"}, {Name: "anon"}, {Name: "nobody"}}
	listed := func(s *server.Session) string {
		var names []string
		for _, e := range cfg.visibleShares(all, principalOf(s)) {
			names = append(names, e.Name)
		}
		return strings.Join(names, ",")
	}
	for s, want := range map[*server.Session]string{
		asAlice:     "IPC$,open,alice,finance",
		asBob:       "IPC$,open,finance",
		asCarol:     "IPC$,open,guests",
		asGuest:     "IPC$,open,guests",
		asAnonymous: "IPC$,open,anon",
	} {
		if got := listed(s); got != want {
			t.Errorf("%s sees %s, want %s", principalOf(s), got, want)
		}
	}
}

func TestAccessListString(t *testing.T) {
	cfg, _ := mustParse(t, accessConfig)
	got := map[string]string{}
	for _, s := range cfg.shares {
		got[s.name] = s.readAccess.String()
	}
	want := map[string]string{"open": "everyone", "alice": "ALICE", "finance": "@Finance", "nobody": "no one"}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("share %s read_access logged as %q, want %q", name, got[name], w)
		}
	}
}

// writeAccessConfig covers each way write access can be set.
const writeAccessConfig = `
local:
  allow_guest: true
  users:
    alice: {password: a}
    bob:   {password: b}
targets:
  t1: {host: 10.0.0.5, user: admin, password: x}
shares:
  - {name: ro,       target: t1, path: A$}
  - {name: all,      target: t1, path: B$, read_only: false}
  - {name: readers,  target: t1, path: C$, read_only: false, read_access: [alice, "@guests"]}
  - {name: listed,   target: t1, path: D$, read_only: false, read_access: [alice, bob], write_access: [alice]}
`

func TestWriteAccess(t *testing.T) {
	cfg, warnings := mustParse(t, writeAccessConfig)
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	cases := []struct {
		share   string
		writers []*server.Session
		users   map[string]bool // go-smb's WritableUsers; nil = every logged-in user
		guests  bool
	}{
		{"ro", nil, map[string]bool{}, false},
		{"all", []*server.Session{asAlice, asBob, asGuest}, nil, true},
		{"readers", []*server.Session{asAlice, asGuest}, map[string]bool{"alice": true}, true},
		{"listed", []*server.Session{asAlice}, map[string]bool{"alice": true}, false},
	}
	hook := cfg.serverConfig().OnTreeConnect
	for _, c := range cases {
		sh := cfg.shareNamed(c.share)
		for _, s := range []*server.Session{asAlice, asBob, asGuest} {
			want := slices.Contains(c.writers, s)
			if got := sh.canWrite(principalOf(s)); got != want {
				t.Errorf("%s writing to %s: %t, want %t", principalOf(s), c.share, got, want)
			}
			// Admitted clients are told their real maximal access.
			res := &smb.TreeConnectRes{}
			if st, _ := hook(nil, s, c.share, &smb.TreeConnectReq{}, res); st == nil {
				wantAccess := uint32(readOnlyAccess)
				if want {
					wantAccess = fullAccess
				}
				if res.MaximalAccess != wantAccess {
					t.Errorf("%s on %s: maximal access 0x%08x, want 0x%08x", principalOf(s), c.share, res.MaximalAccess, wantAccess)
				}
			}
		}
		users, guests, _ := sh.libraryWriters()
		if (users == nil) != (c.users == nil) || !maps.Equal(users, c.users) || guests != c.guests {
			t.Errorf("%s: go-smb writers %v (guests %t), want %v (guests %t)", c.share, users, guests, c.users, c.guests)
		}
	}
}
