package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
)

func newShareService() *shareService {
	return &shareService{&srvsvc.Service{Shares: []srvsvc.ShareEntry{
		{Name: "IPC$", Type: mssrvs.StypeIPC | mssrvs.StypeSpecial, Comment: "IPC"},
		{Name: "projects", Type: mssrvs.StypeDisktree, Comment: "proxied"},
	}}}
}

// getInfo sends a NetrShareGetInfo request through Dispatch, encoded and
// decoded with the library's client-side structures as a real client would.
func getInfo(t *testing.T, s *shareService, share string, level uint32) mssrvs.NetShareGetInfoResponse {
	t.Helper()
	in, err := mssrvs.NewNetShareGetInfoRequest(`\\proxy`, share, level).Marshal()
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	out, err := s.Dispatch(context.Background(), mssrvs.SrvSvcOpNetrShareGetInfo, in)
	if err != nil {
		t.Fatalf("Dispatch level %d: %v", level, err)
	}
	var res mssrvs.NetShareGetInfoResponse
	if err := res.Unmarshal(out); err != nil {
		t.Fatalf("unmarshal level-%d response: %v", level, err)
	}
	return res
}

func TestShareGetInfoLevels(t *testing.T) {
	s := newShareService()

	// Share names match case-insensitively, as in SMB.
	r1 := getInfo(t, s, "PROJECTS", 1)
	if r1.WindowsError != 0 || r1.Info.Level1 == nil ||
		r1.Info.Level1.Name != "projects" || r1.Info.Level1.Comment != "proxied" || r1.Info.Level1.Type != mssrvs.StypeDisktree {
		t.Errorf("level 1 = %+v (err %d), want projects/proxied/disk", r1.Info.Level1, r1.WindowsError)
	}

	r2 := getInfo(t, s, "projects", 2)
	if r2.WindowsError != 0 || r2.Info.Level2 == nil || r2.Info.Level2.Path != `C:\projects` {
		t.Errorf("level 2 = %+v (err %d), want path C:\\projects", r2.Info.Level2, r2.WindowsError)
	}

	for _, level := range []uint32{0, 501, 502, 1005} {
		if r := getInfo(t, s, "projects", level); r.WindowsError != 0 || r.Info.Level != level {
			t.Errorf("level %d -> WindowsError %d, Level %d; want success", level, r.WindowsError, r.Info.Level)
		}
	}
}

func TestShareGetInfoErrors(t *testing.T) {
	s := newShareService()
	if r := getInfo(t, s, "missing", 1); r.WindowsError != nerrNetNameNotFound {
		t.Errorf("unknown share -> WindowsError %d, want NERR_NetNameNotFound", r.WindowsError)
	}

	// The library cannot decode a union with an unknown level, so check the
	// raw reply: discriminant 7, NULL referent, ERROR_INVALID_LEVEL.
	in, err := mssrvs.NewNetShareGetInfoRequest(`\\proxy`, "projects", 7).Marshal()
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	out, err := s.Dispatch(context.Background(), mssrvs.SrvSvcOpNetrShareGetInfo, in)
	want := []byte{7, 0, 0, 0, 0, 0, 0, 0, errorInvalidLevel, 0, 0, 0}
	if err != nil || !bytes.Equal(out, want) {
		t.Errorf("level 7 -> (% x, %v), want % x", out, err, want)
	}
}

// Other opnums still reach the library service: NetrShareEnumAll lists shares.
func TestShareServiceDelegates(t *testing.T) {
	s := newShareService()
	var resume uint32
	req := mssrvs.NetShareEnumAllRequest{
		ServerName:   new(string),
		InfoStruct:   mssrvs.ShareEnumStruct{Level: 1, Level1: &mssrvs.ShareInfoContainer1{}},
		MaxBuffer:    0xffffffff,
		ResumeHandle: &resume,
	}
	in, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal enum request: %v", err)
	}
	out, err := s.Dispatch(context.Background(), mssrvs.SrvSvcOpNetShareEnumAll, in)
	if err != nil {
		t.Fatalf("Dispatch NetShareEnumAll: %v", err)
	}
	var res mssrvs.NetShareEnumAllResponse
	if err := res.Unmarshal(out); err != nil {
		t.Fatalf("unmarshal enum response: %v", err)
	}
	if res.TotalEntries != 2 {
		t.Errorf("NetShareEnumAll returned %d shares, want 2", res.TotalEntries)
	}
}
