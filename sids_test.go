package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/mstypes"
	"github.com/jfjallid/ndr"
)

func TestSIDString(t *testing.T) {
	for _, str := range []string{"S-1-1-0", "S-1-5-21-1-2-3-1000", "S-1-5", "S-1-0x123456789ABC-1", "S-1-22-1-4294967295"} {
		s, err := parseSID(str)
		if err != nil {
			t.Errorf("parse %s: %v", str, err)
			continue
		}
		if got := s.String(); got != str {
			t.Errorf("parse %s, String = %s", str, got)
		}
	}
	for _, bad := range []string{
		"", "S-1", "S-2-5-1", "X-1-5-1", "S-1-5-x", "S-1-5-4294967296", "S-1-0x1000000000000-1",
		"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
	} {
		if _, err := parseSID(bad); err == nil {
			t.Errorf("parse %q accepted, want an error", bad)
		}
	}
}

// lookupRequest builds an LsarLookupSids2 request with go-smb's client type.
// LsarLookupSids sends the same policy handle and SID buffer first, and its
// remaining fields are ignored, so it serves for both opnums.
func lookupRequest(t *testing.T, sids ...string) []byte {
	t.Helper()
	infos := make([]mslsad.LsaprSidInformation, 0, len(sids))
	for _, s := range sids {
		v, err := mstypes.ConvertStrToSID(s)
		if err != nil {
			t.Fatal(err)
		}
		infos = append(infos, mslsad.LsaprSidInformation{Sid: *v})
	}
	req := mslsad.LsarLookupSids2Req{
		PolicyHandle:  make([]byte, 20),
		SidEnumBuffer: mslsad.LsaprSidEnumBuffer{Entries: uint32(len(infos)), SidInfo: infos},
		LookupLevel:   mslsad.LsapLookupWksta,
	}
	in, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// fixedNames names one account of a NAS's domain, as a target would.
func fixedNames(sids []sid) []sidName {
	nas := mustSID("S-1-5-21-1-2-3")
	out := (&sidNamer{}).name(nil, sids)
	for i, s := range sids {
		if s.String() == "S-1-5-21-1-2-3-1000" {
			out[i] = sidName{use: mslsad.SidTypeUser, name: "alice", domain: "NAS", domainSID: nas}
		}
	}
	return out
}

// LsarLookupSids2, decoded by go-smb's own client type: a well-known SID, a
// target's account and an unknown SID.
func TestLSALookupSids2(t *testing.T) {
	s := newTestLSA()
	s.lookup = fixedNames
	out, err := s.Dispatch(context.Background(), lsarLookupSids2,
		lookupRequest(t, "S-1-1-0", "S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1001"))
	if err != nil {
		t.Fatal(err)
	}
	var res mslsad.LsarLookupSids2Res
	if err := res.Unmarshal(out); err != nil {
		t.Fatalf("decode: %v (% x)", err, out)
	}
	if res.ReturnCode != ntStatusSomeNotMapped || res.MappedCount != 2 {
		t.Errorf("status 0x%08x, %d mapped; want STATUS_SOME_NOT_MAPPED, 2", res.ReturnCode, res.MappedCount)
	}
	domains := res.ReferencedDomains.Domains
	names := res.TranslatedNames.Names
	if len(domains) != 2 || len(names) != 3 {
		t.Fatalf("%d domains, %d names; want 2, 3", len(domains), len(names))
	}
	type got struct {
		use          mslsad.SidNameUse
		name, domain string
		domainSID    string
	}
	describe := func(n mslsad.LsaprTranslatedNameEx) got {
		g := got{use: n.Use, name: n.Name.Value}
		if n.DomainIndex >= 0 {
			d := domains[n.DomainIndex]
			g.domain, g.domainSID = d.Name.Value, d.Sid.String()
		}
		return g
	}
	want := []got{
		{mslsad.SidTypeWellKnownGroup, "Everyone", "", "S-1-1"},
		{mslsad.SidTypeUser, "alice", "NAS", "S-1-5-21-1-2-3"},
		{mslsad.SidTypeUnknown, "", "", ""},
	}
	for i, n := range names {
		if g := describe(n); g != want[i] {
			t.Errorf("name %d = %+v, want %+v", i, g, want[i])
		}
	}
	if names[2].DomainIndex != -1 {
		t.Errorf("unknown SID's DomainIndex = %d, want -1", names[2].DomainIndex)
	}
}

// Test-only decoding types for LsarLookupSids (opnum 15), whose names lack
// LsarLookupSids2's Flags, declared like go-smb's types for opnum 57.
type testLookupSidsRes struct {
	ReferencedDomains mslsad.PlsaprReferencedDomainList `ndr:"toplevel"`
	TranslatedNames   testTranslatedNames               `ndr:"toplevel"`
	MappedCount       uint32                            `ndr:"toplevel"`
	ReturnCode        uint32
}

type testTranslatedNames struct {
	Entries uint32
	Names   []testTranslatedName `ndr:"fullpointer,conformant"`
}

type testTranslatedName struct {
	Use         mslsad.SidNameUse
	Name        mstypes.RPCUnicodeString
	DomainIndex int32
}

func TestLSALookupSids(t *testing.T) {
	s := newTestLSA() // no lookup: well-known SIDs only
	out, err := s.Dispatch(context.Background(), lsarLookupSids,
		lookupRequest(t, "S-1-5-32-544", "S-1-5-18", "S-1-5-21-1-2-3-1000"))
	if err != nil {
		t.Fatal(err)
	}
	var res testLookupSidsRes
	if err := ndr.NewDecoder(bytes.NewReader(out), false).Decode(&res); err != nil {
		t.Fatalf("decode: %v (% x)", err, out)
	}
	if res.ReturnCode != ntStatusSomeNotMapped || res.MappedCount != 2 || len(res.TranslatedNames.Names) != 3 {
		t.Fatalf("status 0x%08x, %d mapped, %d names; want STATUS_SOME_NOT_MAPPED, 2, 3",
			res.ReturnCode, res.MappedCount, len(res.TranslatedNames.Names))
	}
	domains := res.ReferencedDomains.Domains
	for i, want := range []struct{ name, domain string }{{"Administrators", "BUILTIN"}, {"SYSTEM", "NT AUTHORITY"}} {
		n := res.TranslatedNames.Names[i]
		if n.Name.Value != want.name || n.DomainIndex < 0 || domains[n.DomainIndex].Name.Value != want.domain {
			t.Errorf("name %d = %+v, want %s\\%s", i, n, want.domain, want.name)
		}
	}
	if n := res.TranslatedNames.Names[2]; n.Use != mslsad.SidTypeUnknown || n.DomainIndex != -1 {
		t.Errorf("target's account without lookup = %+v, want unknown", n)
	}
}

// The status says how much was named, and nothing named leaves no domains.
func TestLSALookupSidsStatus(t *testing.T) {
	s := newTestLSA()
	for _, tt := range []struct {
		sids   []string
		status uint32
		mapped uint32
	}{
		{[]string{"S-1-1-0", "S-1-5-18"}, ntStatusSuccess, 2},
		{[]string{"S-1-5-21-9-9-9-500"}, ntStatusNoneMapped, 0},
	} {
		out, err := s.Dispatch(context.Background(), lsarLookupSids2, lookupRequest(t, tt.sids...))
		if err != nil {
			t.Fatal(err)
		}
		var res mslsad.LsarLookupSids2Res
		if err := res.Unmarshal(out); err != nil {
			t.Fatalf("%v: decode: %v", tt.sids, err)
		}
		if res.ReturnCode != tt.status || res.MappedCount != tt.mapped {
			t.Errorf("%v: status 0x%08x, %d mapped; want 0x%08x, %d", tt.sids, res.ReturnCode, res.MappedCount, tt.status, tt.mapped)
		}
		if tt.mapped == 0 && res.ReferencedDomains.Entries != 0 {
			t.Errorf("%v: %d referenced domains, want none", tt.sids, res.ReferencedDomains.Entries)
		}
	}
}

// Malformed requests fault instead of being answered.
func TestLSALookupSidsBadRequests(t *testing.T) {
	s := newTestLSA()
	good := lookupRequest(t, "S-1-5-21-1-2-3-1000")
	if got := binary.LittleEndian.Uint32(good[20:]); got != 1 {
		t.Fatalf("request layout: entries %d after the handle, want 1", got)
	}
	nullSID := slices.Clone(good)
	binary.LittleEndian.PutUint32(nullSID[32:], 0) // the SID's pointer
	badRevision := slices.Clone(good)
	badRevision[40] = 2 // after the pointer, the conformance count, then Revision
	tooMany := slices.Clone(good)
	binary.LittleEndian.PutUint32(tooMany[20:], maxLookupSids+1)
	for name, in := range map[string][]byte{
		"truncated":  good[:len(good)-30],
		"short":      good[:22],
		"NULL SID":   nullSID,
		"revision 2": badRevision,
		"too many":   tooMany,
		"count differs": func() []byte {
			b := slices.Clone(good)
			binary.LittleEndian.PutUint32(b[28:], 2)
			return b
		}(),
	} {
		if _, err := s.Dispatch(context.Background(), lsarLookupSids2, in); err == nil {
			t.Errorf("%s request answered, want a fault", name)
		}
	}
}

// ---------------------------------------------------------------------------
// sidNamer
// ---------------------------------------------------------------------------

// namingConn is a target naming the SIDs in names (SID → "DOMAIN\name").
func namingConn(names map[string][2]string) *fakeConn {
	return &fakeConn{lookupFn: func(sids []string) (mslsad.SidTranslations, error) {
		var res mslsad.SidTranslations
		domains := map[string]int32{}
		mapped := 0
		for _, s := range sids {
			n, ok := names[s]
			if !ok {
				res.TranslatedNames = append(res.TranslatedNames, mslsad.SidNameTranslation{Use: mslsad.SidTypeUnknown, DomainIndex: -1, Sid: s})
				continue
			}
			mapped++
			idx, ok := domains[n[0]]
			if !ok {
				idx = int32(len(res.ReferencedDomains))
				domains[n[0]] = idx
				res.ReferencedDomains = append(res.ReferencedDomains, mslsad.DomainTranslation{Name: n[0], Sid: "S-1-5-21-7-7-7"})
			}
			res.TranslatedNames = append(res.TranslatedNames, mslsad.SidNameTranslation{Use: mslsad.SidTypeUser, Name: n[1], DomainIndex: idx, Sid: s})
		}
		if mapped == 0 {
			return mslsad.SidTranslations{}, &dcerpc.StatusError{Code: mslsad.StatusNoneMapped}
		}
		return res, nil
	}}
}

func sidsOf(t *testing.T, strs ...string) []sid {
	t.Helper()
	out := make([]sid, len(strs))
	for i, s := range strs {
		v, err := parseSID(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = v
	}
	return out
}

func fullName(n sidName) string {
	if n.use == 0 {
		return "?"
	}
	if n.domain == "" {
		return n.name
	}
	return n.domain + `\` + n.name
}

// Without resolve_sids no target is asked: only well-known SIDs are named.
func TestSIDNamerLocal(t *testing.T) {
	c := namingConn(map[string][2]string{"S-1-5-21-7-7-7-1000": {"NAS", "alice"}})
	up := &upstream{t: testTarget(), conn: c}
	got := (&sidNamer{}).name([]*upstream{up}, sidsOf(t, "S-1-1-0", "S-1-5-21-7-7-7-1000"))
	if fullName(got[0]) != "Everyone" || got[1].use != 0 || len(c.lookups) != 0 {
		t.Errorf("names %q, %q after %d lookups; want Everyone, unnamed, none", fullName(got[0]), fullName(got[1]), len(c.lookups))
	}
}

// With resolve_sids each target in turn is asked for what the targets before
// it did not name; answers, named or not, are cached.
func TestSIDNamerTargets(t *testing.T) {
	a := namingConn(map[string][2]string{"S-1-5-21-7-7-7-1000": {"NAS", "alice"}})
	b := namingConn(map[string][2]string{"S-1-5-21-7-7-7-1001": {"FS", "bob"}})
	ups := []*upstream{{t: testTarget(), conn: a}, {t: testTarget(), conn: b}}
	n := &sidNamer{resolve: true}
	sids := sidsOf(t, "S-1-5-21-7-7-7-1000", "S-1-5-18", "S-1-5-21-7-7-7-1001", "S-1-5-21-7-7-7-1002")

	for round := range 2 {
		got := n.name(ups, sids)
		names := make([]string, 0, len(got))
		for _, g := range got {
			names = append(names, fullName(g))
		}
		if want := []string{`NAS\alice`, `NT AUTHORITY\SYSTEM`, `FS\bob`, "?"}; !slices.Equal(names, want) {
			t.Errorf("round %d: names %q, want %q", round, names, want)
		}
		if got[0].domainSID == nil || got[0].domainSID.String() != "S-1-5-21-7-7-7" {
			t.Errorf("round %d: alice's domain SID %v, want S-1-5-21-7-7-7", round, got[0].domainSID)
		}
	}
	wantA := [][]string{{"S-1-5-21-7-7-7-1000", "S-1-5-21-7-7-7-1001", "S-1-5-21-7-7-7-1002"}}
	wantB := [][]string{{"S-1-5-21-7-7-7-1001", "S-1-5-21-7-7-7-1002"}}
	if !slices.EqualFunc(a.lookups, wantA, slices.Equal) || !slices.EqualFunc(b.lookups, wantB, slices.Equal) {
		t.Errorf("asked first target %q and second %q; want %q and %q (once each)", a.lookups, b.lookups, wantA, wantB)
	}
}

// A target that fails to answer is not cached: it is asked again next time.
func TestSIDNamerFailure(t *testing.T) {
	c := &fakeConn{lookupFn: func([]string) (mslsad.SidTranslations, error) {
		return mslsad.SidTranslations{}, &dcerpc.FaultError{Code: 0x1c010002} // nca_op_rng_error
	}}
	up := &upstream{t: testTarget(), conn: c}
	n := &sidNamer{resolve: true}
	for range 2 {
		if got := n.name([]*upstream{up}, sidsOf(t, "S-1-5-21-7-7-7-1000")); got[0].use != 0 {
			t.Errorf("named %q by a failing target", fullName(got[0]))
		}
	}
	if len(c.lookups) != 2 || !n.failed[up] {
		t.Errorf("%d lookups, failure noted %t; want 2, true", len(c.lookups), n.failed[up])
	}
	// An RPC answer does not make the upstream redial: the connection stays.
	if c.isClosed() {
		t.Error("an RPC fault closed the upstream connection")
	}
}

func TestNoneMapped(t *testing.T) {
	if !noneMapped(&dcerpc.StatusError{Code: mslsad.StatusNoneMapped}) {
		t.Error("STATUS_NONE_MAPPED not recognised")
	}
	if noneMapped(&dcerpc.StatusError{Code: mslsad.StatusAccessDenied}) || noneMapped(errors.New("x")) || noneMapped(nil) {
		t.Error("another error taken for STATUS_NONE_MAPPED")
	}
}
