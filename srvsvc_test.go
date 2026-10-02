package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
)

func newShareService() *srvsvcService {
	cfg := &config{netbiosName: "PROXY1", maxConnections: 512, clientIdleTimeout: 5 * time.Minute}
	return newSrvsvcService(cfg, []srvsvc.ShareEntry{
		{Name: "IPC$", Type: mssrvs.StypeIPC | mssrvs.StypeSpecial, Comment: "IPC"},
		{Name: "projects", Type: mssrvs.StypeDisktree, Comment: "proxied"},
	})
}

// serverInfo sends a NetrServerGetInfo request through Dispatch, encoded and
// decoded with the library's client-side structures as a real client would.
func serverInfo(t *testing.T, s *srvsvcService, level uint32) mssrvs.NetServerGetInfoResponse {
	t.Helper()
	in, err := mssrvs.NewNetServerGetInfoRequest(`\\192.0.2.10`, int(level)).Marshal()
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	out, err := s.Dispatch(context.Background(), mssrvs.SrvSvcOpNetServerGetInfo, in)
	if err != nil {
		t.Fatalf("Dispatch level %d: %v", level, err)
	}
	var res mssrvs.NetServerGetInfoResponse
	if err := res.Unmarshal(out); err != nil {
		t.Fatalf("unmarshal level-%d response: %v", level, err)
	}
	return res
}

// Explorer's share Properties > Network tab asks for level 101; without an
// answer it reports that the server does not accept remote requests.
func TestServerGetInfoLevels(t *testing.T) {
	s := newShareService()

	r100 := serverInfo(t, s, 100)
	if r100.WindowsError != 0 || r100.Info.Level100 == nil ||
		r100.Info.Level100.PlatformId != platformIDNT || r100.Info.Level100.Name != "PROXY1" {
		t.Errorf("level 100 = %+v (err %d)", r100.Info.Level100, r100.WindowsError)
	}

	// An unset comment is sent as an empty string, which go-smb's own
	// server-info types cannot encode.
	r101 := serverInfo(t, s, 101)
	i101 := r101.Info.Level101
	if r101.WindowsError != 0 || i101 == nil || i101.Name != "PROXY1" || i101.Comment != "" ||
		i101.PlatformId != platformIDNT || i101.SvType != serverType ||
		i101.VersionMajor != serverVersionMajor || i101.VersionMinor != serverVersionMinor {
		t.Errorf("level 101 = %+v (err %d)", i101, r101.WindowsError)
	}

	s.comment = "Corporate file proxy"
	r102 := serverInfo(t, s, 102)
	i102 := r102.Info.Level102
	if r102.WindowsError != 0 || i102 == nil || i102.Comment != "Corporate file proxy" ||
		i102.Users != 512 || i102.Disc != 5 || i102.Userpath != `C:\` {
		t.Errorf("level 102 = %+v (err %d)", i102, r102.WindowsError)
	}
}

func TestServerGetInfoInvalidLevel(t *testing.T) {
	in, err := mssrvs.NewNetServerGetInfoRequest(`\\proxy`, 100).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	in[len(in)-4] = 103 // the request's trailing Level field: 100 -> 103
	out, err := newShareService().Dispatch(context.Background(), mssrvs.SrvSvcOpNetServerGetInfo, in)
	want := []byte{103, 0, 0, 0, 0, 0, 0, 0, errorInvalidLevel, 0, 0, 0}
	if err != nil || !bytes.Equal(out, want) {
		t.Errorf("level 103 -> (% x, %v), want % x", out, err, want)
	}
}

// The limits reported at level 102 follow the server configuration.
func TestNewSrvsvcServiceLimits(t *testing.T) {
	cases := []struct {
		name  string
		cfg   config
		users uint32
		disc  int32
	}{
		{"limited", config{maxConnections: 100, clientIdleTimeout: 90 * time.Second}, 100, 2},
		{"short idle rounds up to a minute", config{maxConnections: 1, clientIdleTimeout: 10 * time.Second}, 1, 1},
		{"no limits", config{maxConnections: -1}, 0xffffffff, svNoDisconnect},
	}
	for _, c := range cases {
		s := newSrvsvcService(&c.cfg, nil)
		if s.maxUsers != c.users || s.autodisconnect != c.disc {
			t.Errorf("%s: users %d, autodisconnect %d; want %d, %d", c.name, s.maxUsers, s.autodisconnect, c.users, c.disc)
		}
	}
}

// getInfo sends a NetrShareGetInfo request through Dispatch, encoded and
// decoded with the library's client-side structures as a real client would.
func getInfo(t *testing.T, s *srvsvcService, share string, level uint32) mssrvs.NetShareGetInfoResponse {
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
