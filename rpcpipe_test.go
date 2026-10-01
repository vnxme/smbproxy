package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jfjallid/go-smb/smb"
)

// bindAckHex is the exact 116-byte BindAck the library produced for Windows
// Explorer's srvsvc bind (captured). Three srvsvc contexts — NDR, NDR64, BTFN
// — all returned as Acceptance, which Windows rejects as an RPC protocol error.
const bindAckHex = "05000c03100000007400000002000000b810b810010000000d005c504950455c73727673766300000300000000000000045d888aeb1cc9119fe808002b104860020000000000000033057171babe37498319b5dbef9ccc3601000000000000002c1cb76c12984045030000000000000001000000"

func TestFixBindAck(t *testing.T) {
	pdu, err := hex.DecodeString(bindAckHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(pdu) != 116 {
		t.Fatalf("test vector is %d bytes, want 116", len(pdu))
	}
	fixBindAck(pdu)

	// Result list starts at offset 44; entries are 24 bytes each.
	cases := []struct {
		name           string
		off            int
		wantResult     byte
		wantReason     byte
		wantSyntaxZero bool
	}{
		{"ctx0 NDR -> acceptance", 44, 0, 0, false},
		{"ctx1 NDR64 -> provider_rejection", 68, 2, 2, true},
		{"ctx2 BTFN -> negotiate_ack", 92, 3, 0, true},
	}
	for _, c := range cases {
		gotResult := pdu[c.off]
		gotReason := pdu[c.off+2]
		if gotResult != c.wantResult || gotReason != c.wantReason {
			t.Errorf("%s: result=%d reason=%d, want result=%d reason=%d",
				c.name, gotResult, gotReason, c.wantResult, c.wantReason)
		}
		if c.wantSyntaxZero {
			for j := c.off + 4; j < c.off+24; j++ {
				if pdu[j] != 0 {
					t.Errorf("%s: transfer syntax not zeroed at byte %d", c.name, j)
					break
				}
			}
		}
	}
	// NDR context must keep its transfer syntax intact.
	if !equalBytes(pdu[48:64], uuidNDR) {
		t.Errorf("ctx0 NDR transfer syntax was altered")
	}
}

// Malformed or non-BindAck PDUs must pass through unchanged, never panic.
func TestFixBindAckMalformed(t *testing.T) {
	ack, err := hex.DecodeString(bindAckHex)
	if err != nil {
		t.Fatal(err)
	}

	// Result list for the captured vector starts at offset 40 (count) / 44
	// (first entry); see TestFixBindAck.
	tooManyResults := append([]byte(nil), ack[:68]...) // header + 1 full entry
	tooManyResults[40] = 3                             // claims 3 entries

	cases := []struct {
		name string
		pdu  []byte
	}{
		{"empty", []byte{}},
		{"shorter than header", ack[:20]},
		{"request type", makePDU(rpcTypeRequest, 116, 0, 0)},
		{"secondary address overruns", append(append([]byte(nil), ack[:24]...), 0xff, 0x00, 0, 0)},
		{"list count with no room for list", ack[:40]},
	}
	for _, c := range cases {
		in := append([]byte(nil), c.pdu...)
		if got := fixBindAck(in); !bytes.Equal(got, c.pdu) {
			t.Errorf("%s: PDU was modified", c.name)
		}
	}

	// A truncated list: the first entry is complete and gets processed (NDR
	// stays as is), the missing ones are skipped without panicking.
	got := fixBindAck(tooManyResults)
	if len(got) != 68 || !bytes.Equal(got[48:64], uuidNDR) || got[44] != 0 {
		t.Errorf("truncated list: first NDR entry altered or length changed")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// makePDU builds a minimal DCE/RPC PDU of total length n (>= 16) with the
// given packet type; frag_length is set to n. For requests (n >= 24) opnum
// is written at offset 22. Remaining bytes are filled with tag.
func makePDU(ptype byte, n int, opnum int, tag byte) []byte {
	pdu := bytes.Repeat([]byte{tag}, n)
	pdu[0], pdu[1], pdu[2], pdu[3] = 5, 0, ptype, 3
	pdu[8], pdu[9] = byte(n), byte(n>>8)
	pdu[10], pdu[11] = 0, 0
	if ptype == rpcTypeRequest && n >= 24 {
		pdu[22], pdu[23] = byte(opnum), byte(opnum>>8)
	}
	return pdu
}

// fakePipe is an inner PipeBackend that records each Transceive input and
// answers via respond, or echoes the input when respond is nil.
type fakePipe struct {
	got     [][]byte
	respond func(in []byte) ([]byte, uint32, error)
	closed  bool
}

func (f *fakePipe) Transceive(_ context.Context, in []byte) ([]byte, uint32, error) {
	f.got = append(f.got, append([]byte(nil), in...))
	if f.respond != nil {
		return f.respond(in)
	}
	return append([]byte(nil), in...), smb.StatusOk, nil
}

func (f *fakePipe) Write(context.Context, []byte) (int, uint32, error) {
	return 0, smb.StatusNotSupported, nil
}

func (f *fakePipe) Read(context.Context, int) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

func (f *fakePipe) Close(context.Context) error { f.closed = true; return nil }

func TestPduInfo(t *testing.T) {
	withAuth := makePDU(rpcTypeRequest, 64, 7, 0)
	withAuth[10] = 16

	cases := []struct {
		name                       string
		pdu                        []byte
		wantType                   byte
		wantFrag, wantAuth, wantOp int
	}{
		{"request with opnum", makePDU(rpcTypeRequest, 40, 15, 0), rpcTypeRequest, 40, 0, 15},
		{"request opnum high byte", makePDU(rpcTypeRequest, 24, 0x0102, 0), rpcTypeRequest, 24, 0, 0x0102},
		{"auth length", withAuth, rpcTypeRequest, 64, 16, 7},
		{"short request has no opnum", makePDU(rpcTypeRequest, 16, 0, 0), rpcTypeRequest, 16, 0, -1},
		{"bind ack has no opnum", makePDU(rpcTypeBindAck, 300, 0, 0), rpcTypeBindAck, 300, 0, -1},
	}
	for _, c := range cases {
		ptype, frag, auth, op := pduInfo(c.pdu)
		if ptype != c.wantType || frag != c.wantFrag || auth != c.wantAuth || op != c.wantOp {
			t.Errorf("%s: pduInfo = (%d,%d,%d,%d), want (%d,%d,%d,%d)", c.name,
				ptype, frag, auth, op, c.wantType, c.wantFrag, c.wantAuth, c.wantOp)
		}
	}
}

// process (via Transceive) must run the inner handler's BindAck through
// fixBindAck before returning it.
func TestRPCPipeTransceiveFixesBindAck(t *testing.T) {
	ack, err := hex.DecodeString(bindAckHex)
	if err != nil {
		t.Fatal(err)
	}
	want := fixBindAck(append([]byte(nil), ack...))

	inner := &fakePipe{respond: func([]byte) ([]byte, uint32, error) {
		return append([]byte(nil), ack...), smb.StatusOk, nil
	}}
	p := &rpcPipe{inner: inner}
	bind := makePDU(11, 72, 0, 0xAA) // 11 = bind
	out, status, err := p.Transceive(context.Background(), bind)
	if err != nil || status != smb.StatusOk {
		t.Fatalf("Transceive: status=0x%08x err=%v", status, err)
	}
	if !bytes.Equal(out, want) {
		t.Errorf("Transceive did not return the fixed BindAck")
	}
	if len(inner.got) != 1 || !bytes.Equal(inner.got[0], bind) {
		t.Errorf("inner received %d PDUs, want the bind PDU once", len(inner.got))
	}
}

func TestRPCPipeTransceiveNilBecomesEmpty(t *testing.T) {
	wantErr := errors.New("boom")
	inner := &fakePipe{respond: func([]byte) ([]byte, uint32, error) {
		return nil, smb.StatusInvalidParameter, wantErr
	}}
	p := &rpcPipe{inner: inner}
	out, status, err := p.Transceive(context.Background(), makePDU(rpcTypeRequest, 24, 1, 0))
	if out == nil || len(out) != 0 {
		t.Errorf("out = %v, want non-nil empty slice", out)
	}
	if status != smb.StatusInvalidParameter || !errors.Is(err, wantErr) {
		t.Errorf("status=0x%08x err=%v, want inner status and error passed through", status, err)
	}
}

// Write must reassemble PDUs split across and packed within WRITE chunks,
// keep a partial tail buffered, and queue responses for Read.
func TestRPCPipeWriteRead(t *testing.T) {
	a := makePDU(rpcTypeRequest, 32, 1, 0x11)
	b := makePDU(rpcTypeRequest, 40, 2, 0x22)
	c := makePDU(rpcTypeRequest, 24, 3, 0x33)

	inner := &fakePipe{}
	p := &rpcPipe{inner: inner}
	ctx := context.Background()

	// Chunks: [a + first 10 bytes of b] [rest of b + c + first 5 bytes of a]
	var stream []byte
	for _, part := range [][]byte{a, b, c, a[:5]} {
		stream = append(stream, part...)
	}
	split := len(a) + 10
	for _, chunk := range [][]byte{stream[:split], stream[split:]} {
		n, status, err := p.Write(ctx, chunk)
		if n != len(chunk) || status != smb.StatusOk || err != nil {
			t.Fatalf("Write(%d bytes) = (%d, 0x%08x, %v)", len(chunk), n, status, err)
		}
	}

	if len(inner.got) != 3 {
		t.Fatalf("inner got %d PDUs, want 3", len(inner.got))
	}
	for i, want := range [][]byte{a, b, c} {
		if !bytes.Equal(inner.got[i], want) {
			t.Errorf("PDU %d delivered incorrectly", i)
		}
	}
	if !bytes.Equal(p.in, a[:5]) {
		t.Errorf("buffered tail = %x, want %x", p.in, a[:5])
	}

	out, status, err := p.Read(ctx, 4096)
	wantOut := stream[:len(a)+len(b)+len(c)]
	if status != smb.StatusOk || err != nil || !bytes.Equal(out, wantOut) {
		t.Errorf("Read = (%d bytes, 0x%08x, %v), want concatenated echoes", len(out), status, err)
	}
	if out, _, _ := p.Read(ctx, 4096); len(out) != 0 {
		t.Errorf("second Read returned %d bytes, want 0", len(out))
	}
}

func TestRPCPipeWriteMalformedFragLen(t *testing.T) {
	inner := &fakePipe{}
	p := &rpcPipe{inner: inner}
	bad := makePDU(rpcTypeRequest, 20, 0, 0)
	bad[8], bad[9] = 8, 0 // frag_length smaller than the header
	n, status, err := p.Write(context.Background(), bad)
	if n != len(bad) || status != smb.StatusOk || err != nil {
		t.Errorf("Write = (%d, 0x%08x, %v), want accepted and buffered", n, status, err)
	}
	if len(inner.got) != 0 {
		t.Errorf("inner got %d PDUs, want 0 for malformed frag_length", len(inner.got))
	}
}

func TestRPCPipeWriteInnerFailure(t *testing.T) {
	wantErr := errors.New("fault")
	inner := &fakePipe{respond: func([]byte) ([]byte, uint32, error) {
		return nil, smb.StatusAccessDenied, wantErr
	}}
	p := &rpcPipe{inner: inner}
	pdu := makePDU(rpcTypeRequest, 24, 1, 0)
	n, status, err := p.Write(context.Background(), pdu)
	if n != len(pdu) || status != smb.StatusAccessDenied || !errors.Is(err, wantErr) {
		t.Errorf("Write = (%d, 0x%08x, %v), want inner failure surfaced", n, status, err)
	}
	if out, _, _ := p.Read(context.Background(), 4096); len(out) != 0 {
		t.Errorf("Read after failed Write returned %d bytes, want 0", len(out))
	}
}

// Exercises the -debug tracing paths; they must not change behavior.
func TestRPCPipeVerboseLogging(t *testing.T) {
	old := verbose
	verbose = true
	t.Cleanup(func() { verbose = old })

	p := &rpcPipe{inner: &fakePipe{}}
	ctx := context.Background()
	pdu := makePDU(rpcTypeRequest, 24, 1, 0)
	if _, _, err := p.Transceive(ctx, pdu); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Write(ctx, pdu); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := p.Read(ctx, 4096); !bytes.Equal(out, pdu) {
		t.Errorf("Read with verbose on returned %x, want %x", out, pdu)
	}
}

func TestRPCPipeClose(t *testing.T) {
	inner := &fakePipe{}
	p := &rpcPipe{inner: inner}
	if err := p.Close(context.Background()); err != nil || !inner.closed {
		t.Errorf("Close: err=%v closed=%v, want inner closed", err, inner.closed)
	}
}
