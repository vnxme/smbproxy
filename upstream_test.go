package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/smb"
)

// connDown is a representative dead-connection error, matching the plain errors
// the library returns when the socket is gone.
var connDown = fmt.Errorf("remote connection has closed")

// A malformed ntHex must fail before any network dial. (parseMapping always
// normalizes ntHex, so this guards direct callers only.) The dial path itself
// needs a live SMB server and is not unit-tested.
func TestOpenUpstreamBadHash(t *testing.T) {
	up, err := openUpstream(mapping{remoteHost: "192.0.2.1", ntHex: "not-hex"})
	if err == nil || up != nil {
		t.Errorf("openUpstream = (%v, %v), want (nil, hex decode error)", up, err)
	}
}

func TestIsTransportErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"status sentinel", smb.StatusMap[smb.StatusAccessDenied], false},
		{"wrapped sentinel", fmt.Errorf("op: %w", smb.StatusMap[smb.StatusObjectNameNotFound]), false},
		{"plain error", errors.New("boom"), true},
		{"dead connection", connDown, true},
		{"eof", io.EOF, true},
	}
	for _, c := range cases {
		if got := isTransportErr(c.err); got != c.want {
			t.Errorf("%s: isTransportErr(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

func TestIsNetworkError(t *testing.T) {
	opErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"dial refused", opErr, true},
		{"wrapped dial error", fmt.Errorf("connect: %w", opErr), true},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "nope"}, true},
		{"status sentinel", smb.StatusMap[smb.StatusAccessDenied], false},
		{"plain error", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := isNetworkError(c.err); got != c.want {
			t.Errorf("%s: isNetworkError(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

func TestConnectFailureHint(t *testing.T) {
	netHint := connectFailureHint(&net.OpError{Op: "dial", Err: errors.New("refused")})
	if !strings.Contains(netHint, "port 445") {
		t.Errorf("network hint missing reachability guidance: %q", netHint)
	}
	if strings.Contains(netHint, "STATUS_LOGON_FAILURE") {
		t.Errorf("network hint should not mention credential causes")
	}

	authHint := connectFailureHint(errors.New("STATUS_ACCESS_DENIED"))
	if !strings.Contains(authHint, "STATUS_LOGON_FAILURE") {
		t.Errorf("auth hint missing credential guidance: %q", authHint)
	}
	if strings.Contains(authHint, "port 445") {
		t.Errorf("auth hint should not mention TCP reachability")
	}
}

func TestUpstreamDoSuccessNoRedial(t *testing.T) {
	u := &upstream{
		conn: &fakeConn{},
		dial: func(mapping) (upstreamConn, error) {
			t.Fatal("dial must not be called on success")
			return nil, nil
		},
	}
	if err := u.do(func(c upstreamConn) error { return c.TreeConnect("x") }); err != nil {
		t.Errorf("do = %v, want nil", err)
	}
}

func TestUpstreamDoNoRedialOnStatusError(t *testing.T) {
	u := &upstream{
		conn: &fakeConn{treeErr: smb.StatusMap[smb.StatusAccessDenied]},
		dial: func(mapping) (upstreamConn, error) {
			t.Fatal("dial must not be called for a protocol NTSTATUS")
			return nil, nil
		},
	}
	err := u.do(func(c upstreamConn) error { return c.TreeConnect("x") })
	if !errors.Is(err, smb.StatusMap[smb.StatusAccessDenied]) {
		t.Errorf("do = %v, want AccessDenied passed through without redial", err)
	}
}

func TestUpstreamDoRedialsAndRetries(t *testing.T) {
	conn1 := &fakeConn{treeErr: connDown} // dead link
	conn2 := &fakeConn{}                  // healthy replacement
	dialed := 0
	u := &upstream{
		m:    mapping{remoteHost: "h"},
		conn: conn1,
		dial: func(mapping) (upstreamConn, error) { dialed++; return conn2, nil },
	}

	if err := u.do(func(c upstreamConn) error { return c.TreeConnect("x") }); err != nil {
		t.Fatalf("do after redial = %v, want nil", err)
	}
	if dialed != 1 {
		t.Errorf("dialed %d times, want exactly 1", dialed)
	}
	if u.conn != upstreamConn(conn2) {
		t.Errorf("connection not swapped to the fresh conn")
	}
	conn1.mu.Lock()
	closed := conn1.closed
	conn1.mu.Unlock()
	if !closed {
		t.Errorf("stale connection not closed on redial")
	}
}

func TestUpstreamDoRedialFailureReturnsOriginalError(t *testing.T) {
	conn1 := &fakeConn{treeErr: connDown}
	u := &upstream{
		conn: conn1,
		dial: func(mapping) (upstreamConn, error) { return nil, errors.New("dial failed") },
	}

	err := u.do(func(c upstreamConn) error { return c.TreeConnect("x") })
	if !errors.Is(err, connDown) {
		t.Errorf("do = %v, want the original transport error when redial fails", err)
	}
	if u.conn != upstreamConn(conn1) {
		t.Errorf("connection was swapped despite a failed redial")
	}
	conn1.mu.Lock()
	closed := conn1.closed
	conn1.mu.Unlock()
	if closed {
		t.Errorf("stale connection closed even though redial failed")
	}
}
