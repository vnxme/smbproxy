package main

import (
	"encoding/hex"
	"testing"
)

// The hex vector below is the exact 116-byte BindAck the library produced for
// Windows Explorer's srvsvc bind (captured). Three srvsvc contexts — NDR,
// NDR64, BTFN — all returned as Acceptance, which Windows rejects as an RPC
// protocol error.
func TestFixBindAck(t *testing.T) {
	pdu, err := hex.DecodeString("05000c03100000007400000002000000b810b810010000000d005c504950455c73727673766300000300000000000000045d888aeb1cc9119fe808002b104860020000000000000033057171babe37498319b5dbef9ccc3601000000000000002c1cb76c12984045030000000000000001000000")
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
