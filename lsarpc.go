package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/dcerpc/mslsad"
)

// ---------------------------------------------------------------------------
// lsaService — a minimal, read-only LSA policy server (MS-LSAD) on \pipe\lsarpc
//
// Explorer's share Properties > Network tab opens lsarpc after srvsvc's
// NetrServerGetInfo, to learn which workgroup or domain the server belongs to;
// when the pipe cannot be opened, the tab reports that the server does not
// accept remote requests. go-smb has no LSA server, so this answers the policy
// queries a standalone (workgroup) server answers: open and close a policy
// handle, and query its primary, account and DNS domain information. Every
// other opnum faults, which the debug log shows as an unsupported opnum.
// ---------------------------------------------------------------------------

// LSA opnums answered by lsaService (MS-LSAD 3.1.4).
const (
	lsarClose                   = 0
	lsarOpenPolicy              = 6
	lsarQueryInformationPolicy  = 7
	lsarOpenPolicy2             = 44
	lsarQueryInformationPolicy2 = 46
)

// POLICY_INFORMATION_CLASS values answered by lsaService (MS-LSAD 2.2.4.1).
const (
	policyPrimaryDomainInformation = 3
	policyAccountDomainInformation = 5
	policyDNSDomainInformation     = 12
	policyDNSDomainInformationInt  = 13
)

// NTSTATUS codes in LSA responses.
const (
	ntStatusSuccess          = 0x00000000
	ntStatusInvalidParameter = 0xc000000d
)

// lsaService describes the proxy as a standalone server: a member of the
// workgroup netbiosDomain (no domain SID), with its own account domain named
// netbiosName.
type lsaService struct {
	netbiosName   string // the account domain: the server's own name
	netbiosDomain string // the primary domain: the workgroup it belongs to
	machineSID    sid    // the account domain's SID, stable for netbiosName
}

func newLSAService(cfg *config) *lsaService {
	return &lsaService{
		netbiosName:   cfg.netbiosName,
		netbiosDomain: cfg.netbiosDomain,
		machineSID:    machineSID(cfg.netbiosName),
	}
}

func (s *lsaService) InterfaceUUID() string { return mslsad.MSRPCUuidLsaRpc }

func (s *lsaService) InterfaceVersion() (uint16, uint16) {
	return mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion
}

func (s *lsaService) Dispatch(_ context.Context, opnum uint16, in []byte) ([]byte, error) {
	switch opnum {
	case lsarOpenPolicy, lsarOpenPolicy2:
		// The request (system name, object attributes, desired access) needs
		// no inspection: every caller gets a read-only view of the policy.
		return s.openPolicy()
	case lsarClose:
		// [in, out] handle: the closed handle comes back zeroed.
		return make([]byte, 20+4), nil
	case lsarQueryInformationPolicy, lsarQueryInformationPolicy2:
		// [in] handle (20 bytes), [in] POLICY_INFORMATION_CLASS (an NDR
		// 16-bit enum).
		if len(in) < 22 {
			return nil, errors.New("lsarpc: short QueryInformationPolicy request")
		}
		return s.queryInformationPolicy(binary.LittleEndian.Uint16(in[20:22])), nil
	}
	return nil, fmt.Errorf("lsarpc: unsupported opnum %d", opnum)
}

// openPolicy returns a fresh policy handle: a context handle of zero
// attributes and a random UUID. No state stands behind it, as every policy
// query is answered the same way.
func (s *lsaService) openPolicy() ([]byte, error) {
	out := make([]byte, 20+4) // handle, then NTSTATUS success
	if _, err := rand.Read(out[4:20]); err != nil {
		return nil, err
	}
	return out, nil
}

// queryInformationPolicy encodes the response for an information class: a
// unique pointer to the LSAPR_POLICY_INFORMATION union (its 16-bit class,
// then the arm), the arm's deferred strings and SID, and the NTSTATUS. An
// unanswered class gets a NULL pointer and STATUS_INVALID_PARAMETER.
func (s *lsaService) queryInformationPolicy(class uint16) []byte {
	var w ndrWriter
	switch class {
	case policyPrimaryDomainInformation:
		// LSAPR_POLICY_PRIMARY_DOM_INFO: the workgroup, with no domain SID.
		w.pointer(true)
		w.u16(class)
		w.align(4) // the arm, a structure with pointers, is 4-aligned
		name := w.unicodeString(s.netbiosDomain)
		w.pointer(false) // Sid
		name()
	case policyAccountDomainInformation:
		// LSAPR_POLICY_ACCOUNT_DOM_INFO: the server's own account domain.
		w.pointer(true)
		w.u16(class)
		w.align(4) // the arm, a structure with pointers, is 4-aligned
		name := w.unicodeString(s.netbiosName)
		w.pointer(true) // DomainSid
		name()
		w.sid(s.machineSID)
	case policyDNSDomainInformation, policyDNSDomainInformationInt:
		// LSAPR_POLICY_DNS_DOMAIN_INFO for a workgroup member: the workgroup
		// name, no DNS names, a zero GUID and no SID.
		w.pointer(true)
		w.u16(class)
		w.align(4) // the arm, a structure with pointers, is 4-aligned
		name := w.unicodeString(s.netbiosDomain)
		dnsDomain := w.unicodeString("")
		dnsForest := w.unicodeString("")
		w.align(4)
		w.raw(make([]byte, 16)) // DomainGuid
		w.pointer(false)        // Sid
		name()
		dnsDomain()
		dnsForest()
	default:
		w.pointer(false)
		w.u32(ntStatusInvalidParameter)
		return w.b
	}
	w.align(4)
	w.u32(ntStatusSuccess)
	return w.b
}

// ---------------------------------------------------------------------------
// NDR encoding (MS-RPCE NDR 2.0, little-endian), just enough for the LSA
// policy responses above. go-smb's LSA types decode these structures but
// cannot encode them.
// ---------------------------------------------------------------------------

type ndrWriter struct {
	b       []byte
	nextRef uint32 // next referent ID for a non-NULL pointer
}

func (w *ndrWriter) align(n int) {
	for len(w.b)%n != 0 {
		w.b = append(w.b, 0)
	}
}

func (w *ndrWriter) raw(p []byte) { w.b = append(w.b, p...) }

func (w *ndrWriter) u16(v uint16) {
	w.align(2)
	w.b = binary.LittleEndian.AppendUint16(w.b, v)
}

func (w *ndrWriter) u32(v uint32) {
	w.align(4)
	w.b = binary.LittleEndian.AppendUint32(w.b, v)
}

// pointer writes a pointer's referent ID: a fresh nonzero ID for a non-NULL
// pointer (whose pointee the caller writes later, deferred), 0 for NULL.
func (w *ndrWriter) pointer(nonNull bool) {
	if !nonNull {
		w.u32(0)
		return
	}
	if w.nextRef == 0 {
		w.nextRef = 0x00020000
	}
	w.u32(w.nextRef)
	w.nextRef += 4
}

// unicodeString writes the inline part of an RPC_UNICODE_STRING (byte lengths
// and the buffer pointer, NULL for an empty string) and returns the function
// that writes its deferred buffer, a conformant varying array of UTF-16 code
// units without a terminator, for the caller to invoke in NDR's deferred order.
func (w *ndrWriter) unicodeString(s string) (deferred func()) {
	units := utf16.Encode([]rune(s))
	w.u16(uint16(2 * len(units))) // Length
	w.u16(uint16(2 * len(units))) // MaximumLength
	w.pointer(len(units) > 0)
	return func() {
		if len(units) == 0 {
			return
		}
		w.u32(uint32(len(units))) // maximum count
		w.u32(0)                  // offset
		w.u32(uint32(len(units))) // actual count
		for _, u := range units {
			w.b = binary.LittleEndian.AppendUint16(w.b, u)
		}
	}
}

// sid is a security identifier: S-1-<authority>-<subAuthorities...>.
type sid struct {
	authority      uint64 // 48-bit identifier authority
	subAuthorities []uint32
}

// sid writes an RPC_SID pointee: the conformance count, then the structure.
func (w *ndrWriter) sid(s sid) {
	w.u32(uint32(len(s.subAuthorities))) // maximum count of SubAuthority
	w.b = append(w.b, 1, byte(len(s.subAuthorities)))
	var auth [8]byte
	binary.BigEndian.PutUint64(auth[:], s.authority)
	w.raw(auth[2:]) // IdentifierAuthority: 6 bytes, big-endian
	for _, v := range s.subAuthorities {
		w.u32(v)
	}
}

// machineSID derives a machine SID, S-1-5-21-x-y-z, from the server's name, so
// it is stable across restarts as a real machine's is. SHA-256 rather than the
// FNV used for file IDs: FNV barely changes its leading bytes for names that
// differ only at the end (PROXY1, PROXY2), and those bytes would collide.
func machineSID(name string) sid {
	sum := sha256.Sum256([]byte(name))
	return sid{authority: 5, subAuthorities: []uint32{
		21,
		binary.LittleEndian.Uint32(sum[0:4]),
		binary.LittleEndian.Uint32(sum[4:8]),
		binary.LittleEndian.Uint32(sum[8:12]),
	}}
}
