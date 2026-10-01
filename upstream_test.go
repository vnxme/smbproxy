package main

import "testing"

// A malformed ntHex must fail before any network dial. (parseMapping always
// normalizes ntHex, so this guards direct callers only.) The dial path itself
// needs a live SMB server and is not unit-tested.
func TestOpenUpstreamBadHash(t *testing.T) {
	up, err := openUpstream(mapping{remoteHost: "192.0.2.1", ntHex: "not-hex"})
	if err == nil || up != nil {
		t.Errorf("openUpstream = (%v, %v), want (nil, hex decode error)", up, err)
	}
}
