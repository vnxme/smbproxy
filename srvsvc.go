package main

import (
	"context"
	"encoding/binary"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
)

// Win32 / NERR codes returned in NetrShareGetInfo's WindowsError.
const (
	errorInvalidLevel     = 124  // ERROR_INVALID_LEVEL
	nerrNetNameNotFound   = 2310 // NERR_NetNameNotFound
	shareMaxUsesUnlimited = 0xffffffff
)

// shareService extends go-smb's srvsvc service, which answers only
// NetrShareEnumAll, with NetrShareGetInfo (opnum 16). Windows asks for a single
// share's details (notably the level-1005 caching flags) whenever a file on the
// share is handed to an application; without an answer every such request
// faults. All other opnums go to the embedded library service.
type shareService struct {
	*srvsvc.Service
}

func (s *shareService) Dispatch(ctx context.Context, opnum uint16, in []byte) ([]byte, error) {
	if opnum == mssrvs.SrvSvcOpNetrShareGetInfo {
		return s.shareGetInfo(in)
	}
	return s.Service.Dispatch(ctx, opnum, in)
}

// shareGetInfo answers NetrShareGetInfo from the configured share list, at the
// info levels Windows clients request. A share's on-disk path is reported as
// a synthetic C:\<share>, since a proxied share has no local path.
func (s *shareService) shareGetInfo(in []byte) ([]byte, error) {
	var req mssrvs.NetShareGetInfoRequest
	if err := req.Unmarshal(in); err != nil {
		return nil, err
	}
	res := mssrvs.NetShareGetInfoResponse{Info: mssrvs.ShareInfoUnion{Level: req.Level}}

	entry, found := s.lookup(req.NetName)
	if !found {
		return shareGetInfoError(req.Level, nerrNetNameNotFound), nil
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
		return shareGetInfoError(req.Level, errorInvalidLevel), nil
	}
	return res.Marshal()
}

// shareGetInfoError encodes a failed NetrShareGetInfo response: the union
// discriminant, a NULL info pointer, then the error. go-smb's NDR encoder
// cannot emit the NULL arm, so it is written by hand.
func shareGetInfoError(level, werr uint32) []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:], level)
	// buf[4:8] stays zero: the NULL referent.
	binary.LittleEndian.PutUint32(buf[8:], werr)
	return buf
}

// lookup finds a configured share by name, case-insensitively as SMB does.
func (s *shareService) lookup(name string) (srvsvc.ShareEntry, bool) {
	for _, e := range s.Shares {
		if strings.EqualFold(e.Name, name) {
			return e, true
		}
	}
	return srvsvc.ShareEntry{}, false
}
