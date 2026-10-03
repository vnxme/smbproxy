package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	"github.com/jfjallid/ndr"
)

// Win32 / NERR codes returned in a srvsvc response's WindowsError.
const (
	errorInvalidLevel     = 124  // ERROR_INVALID_LEVEL
	nerrNetNameNotFound   = 2310 // NERR_NetNameNotFound
	shareMaxUsesUnlimited = 0xffffffff
)

// Values NetrServerGetInfo reports for the proxy (MS-SRVS 2.2.4.40-42).
const (
	platformIDNT        = 500 // PLATFORM_ID_NT
	serverVersionMajor  = 10  // reported as Windows 10 / Server 2016 or later
	serverVersionMinor  = 0
	serverAnnounce      = 240  // seconds between announcements (the Windows default)
	serverAnnounceDelta = 3000 // milliseconds of jitter on them (the Windows default)
	svNoDisconnect      = -1   // SV_NODISC: idle sessions are never disconnected

	// SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_NT | SV_TYPE_SERVER_NT:
	// a Windows NT-family file server that is not a domain controller.
	serverType = 0x00000001 | 0x00000002 | 0x00001000 | 0x00008000
)

// srvsvcService extends go-smb's srvsvc service, which answers only
// NetrShareEnumAll, with the two queries Windows makes about a share and its
// server: NetrShareGetInfo (opnum 16), sent whenever a file on a share is
// handed to an application, and NetrServerGetInfo (opnum 21), sent by
// Explorer's share Properties > Network tab. Without answers each faults, and
// the tab reports that the server does not accept remote requests. All other
// opnums go to the embedded library service.
type srvsvcService struct {
	*srvsvc.Service
	name           string // NetBIOS name, reported by NetrServerGetInfo
	comment        string // server comment, reported by NetrServerGetInfo
	maxUsers       uint32 // concurrent clients allowed; 0xffffffff = no limit
	autodisconnect int32  // idle minutes before a client is disconnected; -1 = never
}

// newSrvsvcService builds the srvsvc service for cfg, listing the shares in
// shares (as go-smb's srvsvc.FromConfig derives them from the server config).
func newSrvsvcService(cfg *config, shares []srvsvc.ShareEntry) *srvsvcService {
	s := &srvsvcService{
		Service:        &srvsvc.Service{Shares: shares},
		name:           cfg.netbiosName,
		comment:        cfg.comment,
		maxUsers:       0xffffffff,
		autodisconnect: svNoDisconnect,
	}
	if cfg.maxConnections > 0 {
		s.maxUsers = uint32(cfg.maxConnections)
	}
	if idle := cfg.clientIdleTimeout; idle > 0 {
		s.autodisconnect = int32(max(1, idle.Minutes()+0.5))
	}
	return s
}

func (s *srvsvcService) Dispatch(ctx context.Context, opnum uint16, in []byte) ([]byte, error) {
	switch opnum {
	case mssrvs.SrvSvcOpNetrShareGetInfo:
		return s.shareGetInfo(in)
	case mssrvs.SrvSvcOpNetServerGetInfo:
		return s.serverGetInfo(in)
	}
	return s.Service.Dispatch(ctx, opnum, in)
}

// shareGetInfo answers NetrShareGetInfo from the configured share list, at the
// info levels Windows clients request. A share's on-disk path is reported as
// a synthetic C:\<share>, since a proxied share has no local path.
func (s *srvsvcService) shareGetInfo(in []byte) ([]byte, error) {
	var req mssrvs.NetShareGetInfoRequest
	if err := req.Unmarshal(in); err != nil {
		return nil, err
	}
	res := mssrvs.NetShareGetInfoResponse{Info: mssrvs.ShareInfoUnion{Level: req.Level}}

	entry, found := s.lookup(req.NetName)
	if !found {
		return getInfoError(req.Level, nerrNetNameNotFound), nil
	}
	switch req.Level {
	case 0:
		res.Info.Level0 = &mssrvs.ShareInfo0{Name: entry.Name}
	case 1:
		res.Info.Level1 = &mssrvs.ShareInfo1{Name: entry.Name, Type: entry.Type, Comment: entry.Comment}
	case 2:
		res.Info.Level2 = &mssrvs.ShareInfo2{
			Name: entry.Name, Type: entry.Type, Comment: entry.Comment,
			MaxUses: shareMaxUsesUnlimited, Path: `C:\` + entry.Name,
		}
	case 501:
		res.Info.Level501 = &mssrvs.ShareInfo501{Name: entry.Name, Type: entry.Type, Comment: entry.Comment}
	case 502:
		res.Info.Level502 = &mssrvs.ShareInfo502{
			Name: entry.Name, Type: entry.Type, Comment: entry.Comment,
			MaxUses: shareMaxUsesUnlimited, Path: `C:\` + entry.Name,
		}
	case 1005:
		// Flags 0: CSC_CACHE_MANUAL_REFERENCE, the default for a new share.
		res.Info.Level1005 = &mssrvs.ShareInfo1005{}
	default:
		return getInfoError(req.Level, errorInvalidLevel), nil
	}
	return res.Marshal()
}

// serverGetInfo answers NetrServerGetInfo at its three levels (100, 101 and
// 102), describing the proxy as a Windows NT-family file server.
func (s *srvsvcService) serverGetInfo(in []byte) ([]byte, error) {
	var req mssrvs.NetServerGetInfoRequest
	if err := req.Unmarshal(in); err != nil {
		return nil, err
	}
	res := serverInfoResponse{Info: serverInfoUnion{Level: req.Level}}
	switch req.Level {
	case 100:
		res.Info.Level100 = &serverInfo100{PlatformID: platformIDNT, Name: s.name}
	case 101:
		res.Info.Level101 = &serverInfo101{
			PlatformID: platformIDNT, Name: s.name,
			VersionMajor: serverVersionMajor, VersionMinor: serverVersionMinor,
			Type: serverType, Comment: s.comment,
		}
	case 102:
		res.Info.Level102 = &serverInfo102{
			PlatformID: platformIDNT, Name: s.name,
			VersionMajor: serverVersionMajor, VersionMinor: serverVersionMinor,
			Type: serverType, Comment: s.comment,
			Users: s.maxUsers, Disc: s.autodisconnect,
			Announce: serverAnnounce, AnnDelta: serverAnnounceDelta,
			UserPath: `C:\`,
		}
	default:
		return getInfoError(req.Level, errorInvalidLevel), nil
	}
	enc := ndr.NewEncoder(&bytes.Buffer{}, false)
	enc.SetEndianness(binary.LittleEndian)
	return enc.Encode(&res)
}

// getInfoError encodes a failed NetrShareGetInfo or NetrServerGetInfo
// response: the union discriminant, a NULL info pointer, then the error.
// go-smb's NDR encoder cannot emit the NULL arm, so it is written by hand.
func getInfoError(level, werr uint32) []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:], level)
	// buf[4:8] stays zero: the NULL referent.
	binary.LittleEndian.PutUint32(buf[8:], werr)
	return buf
}

// lookup finds a configured share by name, case-insensitively as SMB does.
func (s *srvsvcService) lookup(name string) (srvsvc.ShareEntry, bool) {
	for _, e := range s.Shares {
		if strings.EqualFold(e.Name, name) {
			return e, true
		}
	}
	return srvsvc.ShareEntry{}, false
}

// The SERVER_INFO structures (MS-SRVS 2.2.4.40-42) and their response, as in
// go-smb's mssrvs package but with notnullptr on every string: go-smb's own
// types refuse to encode an empty string (such as an unset comment), which
// Windows sends as a non-null pointer to an empty string.
type serverInfoResponse struct {
	Info         serverInfoUnion `ndr:"toplevel"`
	WindowsError uint32
}

type serverInfoUnion struct {
	Level    uint32         `ndr:"unionTag,encapsulated"`
	Level100 *serverInfo100 `ndr:"unionField,pointer"`
	Level101 *serverInfo101 `ndr:"unionField,pointer"`
	Level102 *serverInfo102 `ndr:"unionField,pointer"`
}

func (u serverInfoUnion) SwitchFunc(tag any) string {
	switch tag.(uint32) {
	case 100:
		return "Level100"
	case 101:
		return "Level101"
	case 102:
		return "Level102"
	}
	return ""
}

type serverInfo100 struct {
	PlatformID uint32
	Name       string `ndr:"pointer,conformant,varying,notnullptr"`
}

type serverInfo101 struct {
	PlatformID   uint32
	Name         string `ndr:"pointer,conformant,varying,notnullptr"`
	VersionMajor uint32
	VersionMinor uint32
	Type         uint32
	Comment      string `ndr:"pointer,conformant,varying,notnullptr"`
}

type serverInfo102 struct {
	PlatformID   uint32
	Name         string `ndr:"pointer,conformant,varying,notnullptr"`
	VersionMajor uint32
	VersionMinor uint32
	Type         uint32
	Comment      string `ndr:"pointer,conformant,varying,notnullptr"`
	Users        uint32
	Disc         int32
	Hidden       uint32
	Announce     uint32
	AnnDelta     uint32
	Licenses     uint32
	UserPath     string `ndr:"pointer,conformant,varying,notnullptr"`
}
