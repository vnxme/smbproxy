package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

// connDown is a representative dead-connection error, matching the plain errors
// the library returns when the socket is gone.
var connDown = fmt.Errorf("remote connection has closed")

// A malformed ntHex must fail in dialConn before any network use. (parseMapping
// always normalizes ntHex, so this guards direct callers only.) The dial itself
// needs a live SMB server and is not unit-tested.
func TestDialConnBadHash(t *testing.T) {
	conn, err := dialConn(mapping{remoteHost: "192.0.2.1", ntHex: "not-hex"}, time.Second)
	if err == nil || conn != nil {
		t.Errorf("dialConn = (%v, %v), want (nil, hex decode error)", conn, err)
	}
}

// newUpstream must not dial until the first operation, and must reuse the
// connection on later operations.
func TestUpstreamLazyConnect(t *testing.T) {
	conn := &fakeConn{}
	dialed := 0
	u := &upstream{m: mapping{remoteHost: "h"}, dial: func(mapping) (upstreamConn, error) {
		dialed++
		return conn, nil
	}}

	if u.conn != nil || dialed != 0 {
		t.Fatalf("dialed before first use (conn=%v, dialed=%d)", u.conn, dialed)
	}
	if err := u.do(func(upstreamConn) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if dialed != 1 || u.conn == nil {
		t.Errorf("after first op: dialed=%d conn=%v, want 1 and connected", dialed, u.conn)
	}
	if err := u.do(func(upstreamConn) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if dialed != 1 {
		t.Errorf("second op redialed (dialed=%d), want the connection reused", dialed)
	}
}

func TestNewUpstreamIsLazy(t *testing.T) {
	u := newUpstream(mapping{remoteHost: "h"}, upstreamTimeouts{idle: 90 * time.Second, io: 30 * time.Second})
	if u.conn != nil {
		t.Errorf("newUpstream dialed eagerly (conn=%v)", u.conn)
	}
	if u.dial == nil || u.idle != 90*time.Second || u.ioTimeout != 30*time.Second {
		t.Errorf("newUpstream fields = (dial set=%v, idle=%v, io=%v), want dial set, idle 90s, io 30s",
			u.dial != nil, u.idle, u.ioTimeout)
	}
}

// connectWithin returns a connection made in time, and otherwise gives up
// with a timeout error that the connect hint treats as a network failure,
// closing the connection the abandoned attempt still produces.
func TestConnectWithin(t *testing.T) {
	quick := &fakeConn{}
	c, err := connectWithin(time.Second, func() (upstreamConn, error) { return quick, nil })
	if err != nil || c != quick {
		t.Fatalf("prompt connect = (%v, %v), want (conn, nil)", c, err)
	}

	late := &fakeConn{}
	release := make(chan struct{})
	finished := make(chan struct{})
	c, err = connectWithin(20*time.Millisecond, func() (upstreamConn, error) {
		defer close(finished)
		<-release
		return late, nil
	})
	if c != nil || !errors.Is(err, os.ErrDeadlineExceeded) || !isNetworkError(err) {
		t.Fatalf("stalled connect = (%v, %v), want (nil, deadline error that isNetworkError)", c, err)
	}
	close(release)
	<-finished
	deadline := time.Now().Add(time.Second)
	for !late.isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("connection established after the timeout was never closed")
		}
		time.Sleep(time.Millisecond)
	}

	// A zero timeout waits for connect, however long it takes.
	if c, err := connectWithin(0, func() (upstreamConn, error) { return quick, nil }); err != nil || c != quick {
		t.Errorf("unbounded connect = (%v, %v), want (conn, nil)", c, err)
	}
}

// ensureConn reports a failed dial as a *connectError, which errToStatus turns
// into a client-facing status that does not blame the client's credentials.
func TestUpstreamConnectErrorStatus(t *testing.T) {
	for _, c := range []struct {
		name    string
		dialErr error
		want    uint32
	}{
		{"unreachable", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}, statusBadNetworkPath},
		{"timed out", fmt.Errorf("no answer: %w", os.ErrDeadlineExceeded), statusBadNetworkPath},
		{"bad credentials", &smb.NTStatusError{Op: "SessionSetup", Status: smb.StatusLogonFailure,
			Err: smb.StatusMap[smb.StatusLogonFailure]}, smb.StatusAccessDenied},
	} {
		u := &upstream{m: mapping{remoteHost: "h"}, dial: func(mapping) (upstreamConn, error) { return nil, c.dialErr }}
		err := u.do(func(upstreamConn) error { return nil })
		if _, ok := errors.AsType[*connectError](err); !ok {
			t.Errorf("%s: do error %v is not a *connectError", c.name, err)
		}
		if got := errToStatus(err); got != c.want {
			t.Errorf("%s: errToStatus = 0x%08x, want 0x%08x", c.name, got, c.want)
		}
	}
}

// When the target reports the proxy's session gone, do reconnects and retries
// instead of passing that status to the client.
func TestUpstreamRedialsOnSessionLost(t *testing.T) {
	expired := &smb.NTStatusError{Op: "Create", Status: statusNetworkSessionExpired} // unmapped in go-smb
	dialed, calls := 0, 0
	u := &upstream{m: mapping{remoteHost: "h"}, dial: func(mapping) (upstreamConn, error) {
		dialed++
		return &fakeConn{}, nil
	}}
	err := u.do(func(upstreamConn) error {
		calls++
		if calls == 1 {
			return expired
		}
		return nil
	})
	if err != nil || dialed != 2 || calls != 2 {
		t.Errorf("do = %v after %d dials and %d calls, want nil after 2 and 2 (redial and retry)", err, dialed, calls)
	}
}

func TestUpstreamClose(t *testing.T) {
	c := &fakeConn{}
	u := &upstream{conn: c}
	u.close()
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if !closed || u.conn != nil {
		t.Errorf("close: connClosed=%v conn=%v, want closed and nil", closed, u.conn)
	}
	u.close() // idempotent / safe when already disconnected
}

func TestUpstreamConnectError(t *testing.T) {
	wantErr := errors.New("nope")
	u := &upstream{m: mapping{remoteHost: "h"}, dial: func(mapping) (upstreamConn, error) {
		return nil, wantErr
	}}

	err := u.do(func(upstreamConn) error {
		t.Fatal("operation ran despite a failed connect")
		return nil
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("do = %v, want the dial error surfaced", err)
	}
	if u.conn != nil {
		t.Errorf("conn set despite a failed dial")
	}
}

func TestReapIfIdle(t *testing.T) {
	now := time.Now()
	newU := func() (*upstream, *fakeConn) {
		c := &fakeConn{}
		return &upstream{
			m:       mapping{remoteHost: "h"},
			conn:    c,
			idle:    time.Minute,
			lastUse: now.Add(-2 * time.Minute), // idle long enough to reap
		}, c
	}

	t.Run("idle and unused is reaped", func(t *testing.T) {
		u, c := newU()
		if !u.reapIfIdle(now) || u.conn != nil {
			t.Fatalf("idle unused upstream not reaped (conn=%v)", u.conn)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.closed {
			t.Errorf("reaped connection was not closed")
		}
	})
	t.Run("recent activity is kept", func(t *testing.T) {
		u, _ := newU()
		u.lastUse = now
		if u.reapIfIdle(now) || u.conn == nil {
			t.Errorf("recently-used upstream was reaped")
		}
	})
	t.Run("open handle is kept", func(t *testing.T) {
		u, _ := newU()
		u.refs = 1
		if u.reapIfIdle(now) || u.conn == nil {
			t.Errorf("upstream with an open handle was reaped")
		}
	})
	t.Run("idle disabled", func(t *testing.T) {
		u, _ := newU()
		u.idle = 0
		if u.reapIfIdle(now) || u.conn == nil {
			t.Errorf("reaped despite idle timeout disabled")
		}
	})
	t.Run("not connected", func(t *testing.T) {
		u, _ := newU()
		u.conn = nil
		if u.reapIfIdle(now) {
			t.Errorf("reapIfIdle reported closing a nil connection")
		}
	})
}

// The full lifecycle: connect on demand, reap when idle, reconnect on next use.
func TestUpstreamReconnectAfterReap(t *testing.T) {
	dialed := 0
	u := &upstream{m: mapping{remoteHost: "h"}, idle: time.Minute, dial: func(mapping) (upstreamConn, error) {
		dialed++
		return &fakeConn{}, nil
	}}

	if err := u.do(func(upstreamConn) error { return nil }); err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	u.lastUse = time.Now().Add(-2 * time.Minute)
	u.mu.Unlock()
	if !u.reapIfIdle(time.Now()) {
		t.Fatal("expected the idle connection to be reaped")
	}
	if err := u.do(func(upstreamConn) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if dialed != 2 {
		t.Errorf("dialed %d times, want 2 (initial + reconnect after reap)", dialed)
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
		{"status error", &smb.NTStatusError{Op: "Read", Status: smb.StatusAccessDenied,
			Err: smb.StatusMap[smb.StatusAccessDenied]}, false},
		{"unmapped status error", &smb.NTStatusError{Op: "Read", Status: 0xc0000123}, false},
		{"session deleted", smb.StatusMap[smb.StatusUserSessionDeleted], true},
		{"session expired (unmapped)", &smb.NTStatusError{Op: "Create", Status: statusNetworkSessionExpired}, true},
		{"tree disconnected", smb.StatusMap[smb.StatusNetworkNameDeleted], true},
		{"plain error", errors.New("boom"), true},
		{"dead connection", connDown, true},
		{"eof", io.EOF, true},
		{"timeout", context.DeadlineExceeded, true},
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
