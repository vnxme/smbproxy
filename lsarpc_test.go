package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/mstypes"
	"github.com/jfjallid/ndr"
)

func newTestLSA() *lsaService {
	return newLSAService(&config{netbiosName: "PROXY1", netbiosDomain: "WORKGROUP"})
}

// openPolicy opens a policy handle as a client would, decoding the reply with
// go-smb's client-side LSA types.
func openPolicy(t *testing.T, s *lsaService) [20]byte {
	t.Helper()
	req := mslsad.LsarOpenPolicy2Req{SystemName: `\\PROXY1`, DesiredAccess: 0x00000801}
	in, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal OpenPolicy2: %v", err)
	}
	out, err := s.Dispatch(context.Background(), lsarOpenPolicy2, in)
	if err != nil {
		t.Fatalf("OpenPolicy2: %v", err)
	}
	var res mslsad.LsarOpenPolicy2Res
	if err := res.UnmarshalBinary(out); err != nil {
		t.Fatalf("decode OpenPolicy2: %v", err)
	}
	if res.ReturnCode != ntStatusSuccess {
		t.Fatalf("OpenPolicy2 status 0x%08x", res.ReturnCode)
	}
	return res.PolicyHandle
}

// queryPolicy sends a QueryInformationPolicy request, built with go-smb's
// client-side type, and returns the raw reply.
func queryPolicy(t *testing.T, s *lsaService, opnum uint16, handle [20]byte, class uint16) []byte {
	t.Helper()
	req := mslsad.LsarQueryInformationPolicyReq{PolicyHandle: handle, InformationClass: class}
	in, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal QueryInformationPolicy: %v", err)
	}
	out, err := s.Dispatch(context.Background(), opnum, in)
	if err != nil {
		t.Fatalf("QueryInformationPolicy class %d: %v", class, err)
	}
	return out
}

func TestLSAOpenAndClosePolicy(t *testing.T) {
	s := newTestLSA()
	h1, h2 := openPolicy(t, s), openPolicy(t, s)
	if h1 == ([20]byte{}) || h1 == h2 {
		t.Errorf("handles %x and %x: want nonzero and distinct", h1, h2)
	}
	out, err := s.Dispatch(context.Background(), lsarClose, h1[:])
	if err != nil || !bytes.Equal(out, make([]byte, 24)) {
		t.Errorf("Close = (% x, %v), want a zeroed handle and STATUS_SUCCESS", out, err)
	}
	// LsarOpenPolicy (opnum 6), the older form, answers the same way.
	if out, err := s.Dispatch(context.Background(), lsarOpenPolicy, nil); err != nil || len(out) != 24 {
		t.Errorf("OpenPolicy = (%d bytes, %v), want a 24-byte handle and status", len(out), err)
	}
}

// The primary domain, decoded by go-smb's own client: the workgroup, no SID.
func TestLSAPrimaryDomain(t *testing.T) {
	s := newTestLSA()
	h := openPolicy(t, s)
	for _, opnum := range []uint16{lsarQueryInformationPolicy, lsarQueryInformationPolicy2} {
		var res mslsad.LsarQueryInformationPolicyRes
		if err := res.UnmarshalBinary(queryPolicy(t, s, opnum, h, policyPrimaryDomainInformation)); err != nil {
			t.Fatalf("opnum %d: decode: %v", opnum, err)
		}
		info := res.PolicyInformation
		if res.ReturnCode != ntStatusSuccess || info == nil || info.Tag != policyPrimaryDomainInformation {
			t.Fatalf("opnum %d: status 0x%08x, info %+v", opnum, res.ReturnCode, info)
		}
		if name := info.PolicyPrimaryDomainInfo.Name.Value; name != "WORKGROUP" {
			t.Errorf("opnum %d: primary domain %q, want WORKGROUP", opnum, name)
		}
		if !isNullSID(info.PolicyPrimaryDomainInfo.Sid) {
			t.Errorf("opnum %d: primary domain SID %+v, want none for a workgroup", opnum, info.PolicyPrimaryDomainInfo.Sid)
		}
	}
}

// The exact wire form of the primary-domain reply, which pins what the
// decoder cannot show: the SID pointer is NULL, not an empty SID.
func TestLSAPrimaryDomainWire(t *testing.T) {
	s := newTestLSA()
	got := queryPolicy(t, s, lsarQueryInformationPolicy, openPolicy(t, s), policyPrimaryDomainInformation)
	want := []byte{
		0x00, 0x00, 0x02, 0x00, // PolicyInformation: referent ID
		0x03, 0x00, 0x00, 0x00, // union tag (class 3), padding to the 4-aligned arm
		0x12, 0x00, 0x12, 0x00, // Name.Length, Name.MaximumLength: 18 bytes
		0x04, 0x00, 0x02, 0x00, // Name.Buffer: referent ID
		0x00, 0x00, 0x00, 0x00, // Sid: NULL
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, // Buffer: max 9, offset 0, count 9
		'W', 0, 'O', 0, 'R', 0, 'K', 0, 'G', 0, 'R', 0, 'O', 0, 'U', 0, 'P', 0,
		0x00, 0x00, // padding to 4
		0x00, 0x00, 0x00, 0x00, // STATUS_SUCCESS
	}
	if !bytes.Equal(got, want) {
		t.Errorf("reply:\n got % x\nwant % x", got, want)
	}
}

// Test-only decoding types for the classes go-smb's client does not model,
// declared the way its LSA package declares class 3; decoding with the ndr
// library cross-checks the hand-written encoder.
type testPolicyInfoRes struct {
	Info       *testPolicyInfo `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

type testPolicyInfo struct {
	Tag     uint16             `ndr:"unionTag,encapsulated"`
	Account testAccountDomInfo `ndr:"unionField"`
	DNS     testDNSDomInfo     `ndr:"unionField"`
}

func (u testPolicyInfo) SwitchFunc(tag any) string {
	switch tag.(uint16) {
	case policyAccountDomainInformation:
		return "Account"
	case policyDNSDomainInformation, policyDNSDomainInformationInt:
		return "DNS"
	}
	return ""
}

type testAccountDomInfo struct {
	Name mstypes.RPCUnicodeString
	Sid  *msdtyp.SID `ndr:"pointer"`
}

type testDNSDomInfo struct {
	Name      mstypes.RPCUnicodeString
	DNSDomain mstypes.RPCUnicodeString
	DNSForest mstypes.RPCUnicodeString
	GUID      [16]byte
	Sid       *msdtyp.SID `ndr:"pointer"`
}

// isNullSID reports whether a decoded SID pointer was NULL on the wire. The ndr
// decoder fills a NULL pointer-tagged SID with a zero value rather than nil; a
// real SID never has revision 0.
func isNullSID(s *msdtyp.SID) bool {
	return s == nil || (s.Revision == 0 && s.NumAuth == 0 && len(s.SubAuthorities) == 0)
}

func decodePolicyInfo(t *testing.T, b []byte) testPolicyInfoRes {
	t.Helper()
	var res testPolicyInfoRes
	if err := ndr.NewDecoder(bytes.NewReader(b), false).Decode(&res); err != nil {
		t.Fatalf("decode: %v (% x)", err, b)
	}
	return res
}

// The account domain: the server's own name and its stable machine SID.
func TestLSAAccountDomain(t *testing.T) {
	s := newTestLSA()
	res := decodePolicyInfo(t, queryPolicy(t, s, lsarQueryInformationPolicy, openPolicy(t, s), policyAccountDomainInformation))
	if res.ReturnCode != ntStatusSuccess || res.Info == nil || res.Info.Tag != policyAccountDomainInformation {
		t.Fatalf("status 0x%08x, info %+v", res.ReturnCode, res.Info)
	}
	acct := res.Info.Account
	if acct.Name.Value != "PROXY1" {
		t.Errorf("account domain %q, want PROXY1", acct.Name.Value)
	}
	want := s.machineSID
	if acct.Sid == nil || acct.Sid.Revision != 1 || acct.Sid.Authority != [6]byte{0, 0, 0, 0, 0, 5} ||
		len(acct.Sid.SubAuthorities) != len(want.subAuthorities) {
		t.Fatalf("account domain SID %+v, want S-1-5-21-...", acct.Sid)
	}
	for i, v := range want.subAuthorities {
		if acct.Sid.SubAuthorities[i] != v {
			t.Errorf("SID sub-authority %d = %d, want %d", i, acct.Sid.SubAuthorities[i], v)
		}
	}
}

// DNS domain information for a workgroup member: the workgroup name and
// nothing else.
func TestLSADNSDomain(t *testing.T) {
	s := newTestLSA()
	for _, class := range []uint16{policyDNSDomainInformation, policyDNSDomainInformationInt} {
		res := decodePolicyInfo(t, queryPolicy(t, s, lsarQueryInformationPolicy2, openPolicy(t, s), class))
		if res.ReturnCode != ntStatusSuccess || res.Info == nil || res.Info.Tag != class {
			t.Fatalf("class %d: status 0x%08x, info %+v", class, res.ReturnCode, res.Info)
		}
		dns := res.Info.DNS
		if dns.Name.Value != "WORKGROUP" || dns.DNSDomain.Value != "" || dns.DNSForest.Value != "" ||
			dns.GUID != ([16]byte{}) || !isNullSID(dns.Sid) {
			t.Errorf("class %d: %+v, want WORKGROUP and empty DNS names, GUID and SID", class, dns)
		}
	}
}

func TestLSAUnsupported(t *testing.T) {
	s := newTestLSA()
	// An unanswered class: a NULL pointer and STATUS_INVALID_PARAMETER.
	out := queryPolicy(t, s, lsarQueryInformationPolicy, openPolicy(t, s), 1)
	if want := []byte{0, 0, 0, 0, 0x0d, 0, 0, 0xc0}; !bytes.Equal(out, want) {
		t.Errorf("class 1 -> % x, want % x", out, want)
	}
	// An unanswered opnum faults.
	if _, err := s.Dispatch(context.Background(), 15, nil); err == nil {
		t.Error("opnum 15 (LsarLookupSids) answered, want a fault")
	}
	if _, err := s.Dispatch(context.Background(), lsarQueryInformationPolicy, make([]byte, 10)); err == nil {
		t.Error("short QueryInformationPolicy request accepted, want an error")
	}
}

func TestMachineSID(t *testing.T) {
	a, b := machineSID("PROXY1"), machineSID("PROXY2")
	if a.authority != 5 || len(a.subAuthorities) != 4 || a.subAuthorities[0] != 21 {
		t.Errorf("machine SID %+v, want S-1-5-21-x-y-z", a)
	}
	if again := machineSID("PROXY1"); again.subAuthorities[1] != a.subAuthorities[1] {
		t.Error("machine SID is not stable for one name")
	}
	if a.subAuthorities[1] == b.subAuthorities[1] {
		t.Error("two names share a machine SID")
	}
}
