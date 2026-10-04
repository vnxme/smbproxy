package main

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mslsad"
)

// ---------------------------------------------------------------------------
// Naming SIDs for clients
//
// Explorer shows a file's owner (Properties > Details) and its permissions
// (the Security tab) by asking the server's LSA to name the SIDs in the file's
// security descriptor. The descriptors come from the targets, so most SIDs are
// the targets' own accounts (S-1-5-21-..., or Samba's S-1-22-... Unix users),
// which only a target can name. Well-known SIDs are named from a built-in
// table; the rest, with server.resolve_sids, by the targets themselves.
// ---------------------------------------------------------------------------

// String returns the SID in its S-1-... form.
func (s sid) String() string {
	var b strings.Builder
	b.WriteString("S-1-")
	if s.authority >= 1<<32 {
		fmt.Fprintf(&b, "0x%012X", s.authority)
	} else {
		b.WriteString(strconv.FormatUint(s.authority, 10))
	}
	for _, v := range s.subAuthorities {
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// parseSID reads a SID in its S-1-... form.
func parseSID(str string) (sid, error) {
	parts := strings.Split(str, "-")
	if len(parts) < 3 || len(parts) > 3+maxSubAuthorities || !strings.EqualFold(parts[0], "S") || parts[1] != "1" {
		return sid{}, fmt.Errorf("SID %q: not S-1-<authority>[-<sub-authority>...]", str)
	}
	var s sid
	var err error
	if hex, ok := strings.CutPrefix(strings.ToLower(parts[2]), "0x"); ok {
		s.authority, err = strconv.ParseUint(hex, 16, 48)
	} else {
		s.authority, err = strconv.ParseUint(parts[2], 10, 48)
	}
	if err != nil {
		return sid{}, fmt.Errorf("SID %q: authority: %w", str, err)
	}
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return sid{}, fmt.Errorf("SID %q: sub-authority: %w", str, err)
		}
		s.subAuthorities = append(s.subAuthorities, uint32(v))
	}
	return s, nil
}

// maxSubAuthorities is the most sub-authorities a SID has (MS-DTYP 2.4.2).
const maxSubAuthorities = 15

// sidName is what a SID names: an account, group or alias in a domain. A zero
// use means the SID is not named.
type sidName struct {
	use       mslsad.SidNameUse
	name      string
	domain    string // "" for a SID outside any domain, such as Everyone
	domainSID *sid   // nil if unknown
}

func mustSID(s string) *sid {
	v, err := parseSID(s)
	if err != nil {
		panic(err)
	}
	return &v
}

// wellKnownSIDs are the SIDs named the same on every Windows system, as
// Windows names them in English.
var wellKnownSIDs = func() map[string]sidName {
	type entry struct {
		sid, name string
		use       mslsad.SidNameUse
	}
	world, creator := mustSID("S-1-1"), mustSID("S-1-3")
	ntAuthority, builtin := mustSID("S-1-5"), mustSID("S-1-5-32")
	m := map[string]sidName{}
	add := func(domain string, domainSID *sid, entries ...entry) {
		for _, e := range entries {
			m[e.sid] = sidName{use: e.use, name: e.name, domain: domain, domainSID: domainSID}
		}
	}
	add("", world, entry{"S-1-1-0", "Everyone", mslsad.SidTypeWellKnownGroup})
	add("", creator,
		entry{"S-1-3-0", "CREATOR OWNER", mslsad.SidTypeWellKnownGroup},
		entry{"S-1-3-1", "CREATOR GROUP", mslsad.SidTypeWellKnownGroup})
	add("NT AUTHORITY", ntAuthority,
		entry{"S-1-5-2", "NETWORK", mslsad.SidTypeWellKnownGroup},
		entry{"S-1-5-4", "INTERACTIVE", mslsad.SidTypeWellKnownGroup},
		entry{"S-1-5-7", "ANONYMOUS LOGON", mslsad.SidTypeWellKnownGroup},
		entry{"S-1-5-11", "Authenticated Users", mslsad.SidTypeWellKnownGroup},
		entry{"S-1-5-18", "SYSTEM", mslsad.SidTypeWellKnownGroup},
		entry{"S-1-5-19", "LOCAL SERVICE", mslsad.SidTypeWellKnownGroup},
		entry{"S-1-5-20", "NETWORK SERVICE", mslsad.SidTypeWellKnownGroup})
	add("BUILTIN", builtin,
		entry{"S-1-5-32-544", "Administrators", mslsad.SidTypeAlias},
		entry{"S-1-5-32-545", "Users", mslsad.SidTypeAlias},
		entry{"S-1-5-32-546", "Guests", mslsad.SidTypeAlias},
		entry{"S-1-5-32-547", "Power Users", mslsad.SidTypeAlias},
		entry{"S-1-5-32-551", "Backup Operators", mslsad.SidTypeAlias})
	return m
}()

// sidCacheTTL is how long a target's answer for a SID, named or not, is
// reused. Accounts are renamed rarely; Explorer asks again for every file.
const sidCacheTTL = 10 * time.Minute

// sidNamer names SIDs for the LSA service.
type sidNamer struct {
	resolve bool // ask the targets (server.resolve_sids)

	mu     sync.Mutex
	cache  map[*upstream]map[string]cachedSIDName
	failed map[*upstream]bool // a failure has been logged
}

type cachedSIDName struct {
	at time.Time
	n  sidName
}

// name names sids for a session that may read shares on the targets behind
// ups, given in configuration order. Well-known SIDs are named locally; with
// resolve, every other SID is asked of the targets in turn, each one only for
// the SIDs those before it did not name. A session asks no target whose
// shares it may not read: their descriptors never reach it.
func (n *sidNamer) name(ups []*upstream, sids []sid) []sidName {
	out := make([]sidName, len(sids))
	var pending []int
	for i, s := range sids {
		if wk, ok := wellKnownSIDs[s.String()]; ok {
			out[i] = wk
		} else {
			pending = append(pending, i)
		}
	}
	if !n.resolve {
		return out
	}
	for _, up := range ups {
		if len(pending) == 0 {
			break
		}
		pending = n.fromTarget(up, sids, pending, out)
	}
	return out
}

// fromTarget names the SIDs at pending from up's answers, cached or fresh,
// and returns the indices it did not name.
func (n *sidNamer) fromTarget(up *upstream, sids []sid, pending []int, out []sidName) (unnamed []int) {
	var ask []int
	now := time.Now()
	n.mu.Lock()
	for _, i := range pending {
		c, ok := n.cache[up][sids[i].String()]
		switch {
		case !ok || now.Sub(c.at) >= sidCacheTTL:
			ask = append(ask, i)
		case c.n.use == 0:
			unnamed = append(unnamed, i)
		default:
			out[i] = c.n
		}
	}
	n.mu.Unlock()
	if len(ask) == 0 {
		return unnamed
	}

	strs := make([]string, len(ask))
	for j, i := range ask {
		strs[j] = sids[i].String()
	}
	res, err := up.lookupSids(strs)
	if err != nil && !noneMapped(err) {
		n.mu.Lock()
		if !n.failed[up] {
			if n.failed == nil {
				n.failed = map[*upstream]bool{}
			}
			n.failed[up] = true
			log.Printf("[!] target %s: naming SIDs failed (%v); they are shown unnamed", up.t.name, err)
		}
		n.mu.Unlock()
		return append(unnamed, ask...) // a failure is not an answer: not cached
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cache == nil {
		n.cache = map[*upstream]map[string]cachedSIDName{}
	}
	if n.cache[up] == nil {
		n.cache[up] = map[string]cachedSIDName{}
	}
	for j, i := range ask {
		var nm sidName
		if j < len(res.TranslatedNames) {
			nm = translated(res, res.TranslatedNames[j])
		}
		n.cache[up][strs[j]] = cachedSIDName{at: now, n: nm}
		if nm.use == 0 {
			unnamed = append(unnamed, i)
		} else {
			out[i] = nm
		}
	}
	return unnamed
}

// translated converts a target's name for a SID, or none if it did not name
// it.
func translated(res mslsad.SidTranslations, t mslsad.SidNameTranslation) sidName {
	if t.Use == 0 || t.Use == mslsad.SidTypeInvalid || t.Use == mslsad.SidTypeUnknown {
		return sidName{}
	}
	nm := sidName{use: t.Use, name: t.Name}
	if t.DomainIndex >= 0 && int(t.DomainIndex) < len(res.ReferencedDomains) {
		d := res.ReferencedDomains[t.DomainIndex]
		nm.domain = d.Name
		if s, err := parseSID(d.Sid); err == nil {
			nm.domainSID = &s
		}
	}
	return nm
}

// noneMapped reports whether err is a target's answer that it names none of
// the SIDs asked.
func noneMapped(err error) bool {
	se, ok := errors.AsType[*dcerpc.StatusError](err)
	return ok && se.Code == mslsad.StatusNoneMapped
}

// lookupSids asks the target to name sids. An answer from its LSA, a refusal
// or fault included, says nothing about the connection, so it does not make
// do redial; it is returned as the error.
func (u *upstream) lookupSids(sids []string) (mslsad.SidTranslations, error) {
	var res mslsad.SidTranslations
	var answer error
	err := u.do(func(c upstreamConn) error {
		var e error
		res, e = c.LookupSids(sids)
		answer = nil
		_, status := errors.AsType[*dcerpc.StatusError](e)
		_, fault := errors.AsType[*dcerpc.FaultError](e)
		if status || fault {
			answer = e
			return nil
		}
		return e
	})
	if err != nil {
		return res, err
	}
	return res, answer
}
