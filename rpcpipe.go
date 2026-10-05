package main

import (
	"bytes"
	"context"
	"log"
	"sync"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ---------------------------------------------------------------------------
// rpcPipe — PipeBackend wrapper that makes the library's dcesrv.PipeHandler
// usable by Windows Explorer's srvsvc client. See the rpcPipe type doc below.
// ---------------------------------------------------------------------------

// DCE/RPC common-header packet types (MS-RPCE §2.2.2.4)
const (
	rpcTypeRequest      = 0  // PacketTypeRequest
	rpcTypeBindAck      = 12 // PacketTypeBindAck
	rpcTypeAlterCtxResp = 15 // PacketTypeAlterContextResp
)

// Transfer-syntax UUIDs as they appear on the wire (first three fields
// little-endian), used to classify BindAck result entries. We only speak
// 32-bit NDR; NDR64 and the Bind Time Feature Negotiation pseudo-syntax need
// different result codes than the library emits.
var (
	uuidNDR  = []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	uuidBTFN = []byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// fixBindAck rewrites the result list in a BindAck / AlterContextResp. The
// library's handler accepts every presentation context whose abstract syntax
// matches the interface and echoes its transfer syntax back as Acceptance.
//
// But Windows always offers three srvsvc contexts (32-bit NDR, NDR64, and Bind
// Time Feature Negotiation), and "Acceptance" for the latter two is an RPC
// protocol error that makes the client drop the pipe.
//
// We keep the NDR context as Acceptance, reject NDR64 (we only decode NDR),
// and answer BTFN with negotiate_ack as MS-RPCE requires. Mutates pdu in place
// (the inner handler's freshly marshaled buffer) and returns it.
func fixBindAck(pdu []byte) []byte {
	if len(pdu) < 26 || (pdu[2] != rpcTypeBindAck && pdu[2] != rpcTypeAlterCtxResp) {
		return pdu
	}
	// Header(16) + max_xmit(2) + max_recv(2) + assoc_group(4) = 24, then the
	// variable-length secondary address, then 4-byte padding, then the list.
	secLen := int(pdu[24]) | int(pdu[25])<<8
	off := 26 + secLen
	off = (off + 3) &^ 3 // align to 4 bytes
	if off+4 > len(pdu) {
		return pdu
	}
	n := int(pdu[off])
	base := off + 4
	for i := range n {
		e := base + i*24 // each p_result_t: result(2) reason(2) transfer_syntax(20)
		if e+24 > len(pdu) {
			break
		}
		syn := pdu[e+4 : e+20]
		switch {
		case bytes.Equal(syn, uuidNDR):
			// keep Acceptance (0,0) with the NDR transfer syntax
		case bytes.Equal(syn, uuidBTFN):
			pdu[e], pdu[e+1] = 3, 0 // negotiate_ack
			pdu[e+2], pdu[e+3] = 0, 0
			for j := e + 4; j < e+24; j++ {
				pdu[j] = 0
			}
		default: // NDR64 or any syntax we don't implement
			pdu[e], pdu[e+1] = 2, 0   // provider_rejection
			pdu[e+2], pdu[e+3] = 2, 0 // reason: transfer syntaxes not supported
			for j := e + 4; j < e+24; j++ {
				pdu[j] = 0
			}
		}
	}
	return pdu
}

// rpcPipe wraps dcesrv.PipeHandler and supplies two things it lacks, which
// together let Windows Explorer enumerate shares at \\host.
//
//  1. A WRITE/READ transport. The inner handler only answers
//     FSCTL_PIPE_TRANSCEIVE; its Write/Read return STATUS_NOT_SUPPORTED. The
//     observed client drives srvsvc over separate SMB2 WRITE then READ, so the
//     bind never reached a handler. Write accumulates whole PDUs and runs each
//     through the same path as Transceive; Read returns the queued response.
//
//  2. A corrected BIND result list (see fixBindAck) — the fix the observed
//     client actually needed.
type rpcPipe struct {
	inner server.PipeBackend

	mu  sync.Mutex
	in  []byte // WRITE bytes accumulated until a full PDU is present
	out []byte // response bytes awaiting the client's READ
}

// verbose gates rpcPipe PDU tracing; set from -debug in main.
var verbose bool

// pduInfo decodes the common-header fields used for tracing. opnum is -1 for
// non-request PDUs. Assumes len(pdu) >= 16 (callers check).
func pduInfo(pdu []byte) (ptype byte, fragLen, authLen, opnum int) {
	ptype = pdu[2]
	fragLen = int(pdu[8]) | int(pdu[9])<<8
	authLen = int(pdu[10]) | int(pdu[11])<<8
	opnum = -1
	if ptype == rpcTypeRequest && len(pdu) >= 24 {
		opnum = int(pdu[22]) | int(pdu[23])<<8 // request header: +alloc_hint(4)+ctx_id(2)
	}
	return
}

// process dispatches one complete inbound PDU to the inner handler and
// corrects the BindAck result list on the way out.
func (p *rpcPipe) process(ctx context.Context, pdu []byte) ([]byte, uint32, error) {
	if verbose && len(pdu) >= 16 {
		ptype, fragLen, authLen, opnum := pduInfo(pdu)
		log.Printf("[rpc] in  type=%d frag=%d auth=%d opnum=%d (%d bytes)",
			ptype, fragLen, authLen, opnum, len(pdu))
	}
	out, status, err := p.inner.Transceive(ctx, pdu)
	out = fixBindAck(out) // correct the result list for NDR64 / BTFN contexts
	if verbose {
		rtype := -1
		if len(out) >= 3 {
			rtype = int(out[2])
		}
		log.Printf("[rpc] out type=%d status=0x%08x err=%v (%d bytes)", rtype, status, err, len(out))
	}
	return out, status, err
}

func (p *rpcPipe) Transceive(ctx context.Context, in []byte) ([]byte, uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out, status, err := p.process(ctx, in)
	if out == nil {
		out = []byte{}
	}
	return out, status, err
}

// Write buffers inbound bytes and processes each complete DCE/RPC PDU, whose
// length is frag_length at header bytes 8-9. A short tail is kept until the
// rest of the fragment arrives. Responses queue in p.out for the next READ.
func (p *rpcPipe) Write(_ context.Context, b []byte) (int, uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(b)
	if verbose {
		log.Printf("[rpc] Write %d bytes (buffered total %d)", n, len(p.in)+n)
	}
	p.in = append(p.in, b...)
	for len(p.in) >= 16 {
		fragLen := int(p.in[8]) | int(p.in[9])<<8
		if fragLen < 16 || fragLen > len(p.in) {
			break // incomplete fragment (or malformed) — wait for more
		}
		pdu := p.in[:fragLen]
		p.in = p.in[fragLen:]
		out, status, err := p.process(context.Background(), pdu)
		if err != nil || status != smb.StatusOk {
			return n, status, err // surface the failure on write
		}
		p.out = append(p.out, out...)
	}
	return n, smb.StatusOk, nil
}

// Read drains the queued response in one shot. A response longer than the
// client's READ (a share list of a dozen shares already passes 1 KB) is cut
// by the library, which answers STATUS_BUFFER_OVERFLOW and serves the rest on
// the next READ (see pipeHandle.clip in smb/server/pipe.go).
func (p *rpcPipe) Read(_ context.Context, maxLen int) ([]byte, uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.out
	p.out = nil
	if verbose {
		log.Printf("[rpc] Read max=%d -> %d bytes", maxLen, len(out))
	}
	return out, smb.StatusOk, nil
}

func (p *rpcPipe) Close(ctx context.Context) error { return p.inner.Close(ctx) }
