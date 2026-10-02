package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfjallid/go-smb/ntlmssp"
)

// ntHashOf returns the lowercase hex NT hash of a password, matching what
// parseMapping stores for password credentials.
func ntHashOf(pw string) string {
	return hex.EncodeToString(ntlmssp.Ntowfv1(pw))
}

func TestParseMappingCredential(t *testing.T) {
	const (
		nt  = "8846f7eaee8fb117ad06bdd830b7586c"
		lm  = "aad3b435b51404eeaad3b435b51404ee"
		pre = "share:10.0.0.5:C$:Administrator:CORP:"
	)

	cases := []struct {
		name      string
		cred      string
		wantNTHex string
	}{
		{"bare NT hash", nt, nt},
		{"uppercase NT hash", "8846F7EAEE8FB117AD06BDD830B7586C", nt},
		{"lm:nt pair uses NT half", lm + ":" + nt, nt},
		{"plain password", "S3cretP@ss", ntHashOf("S3cretP@ss")},
		{"password with colons", "a:b:c", ntHashOf("a:b:c")},
		{"explicit pass prefix", "pass:hunter2", ntHashOf("hunter2")},
		{"pass prefix with colons kept", "pass:a:b:c", ntHashOf("a:b:c")},
		// A password that happens to be 32 hex chars: auto-detect reads it as a
		// hash, but the pass: escape forces password mode.
		{"32-hex password forced via pass", "pass:" + nt, ntHashOf(nt)},
		// A 32-char non-hex credential is not a valid hash → treated as password.
		{"32 non-hex chars is a password", "ThisIsExactlyThirtyTwoCharsLong!", ntHashOf("ThisIsExactlyThirtyTwoCharsLong!")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := parseMapping(pre + tc.cred)
			if err != nil {
				t.Fatalf("parseMapping(%q) returned error: %v", tc.cred, err)
			}
			if m.ntHex != tc.wantNTHex {
				t.Errorf("ntHex = %q, want %q", m.ntHex, tc.wantNTHex)
			}
			if len(tc.wantNTHex) != 32 {
				t.Fatalf("test bug: want hash is not 32 chars: %q", tc.wantNTHex)
			}
		})
	}
}

func TestParseMappingSharePath(t *testing.T) {
	cases := []struct {
		name               string
		field              string // the remote-share field
		wantShare, wantSub string
	}{
		{"share root", "C$", "C$", ""},
		{"inner path", "C$\\Users\\Public", "C$", "Users\\Public"},
		{"trailing backslash trimmed", "share\\sub\\", "share", "sub"},
		{"single inner component", "D$\\data", "D$", "data"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := parseMapping("local:10.0.0.5:" + c.field + ":user:CORP:pw")
			if err != nil {
				t.Fatalf("parseMapping: %v", err)
			}
			if m.remoteShare != c.wantShare || m.remoteSub != c.wantSub {
				t.Errorf("remoteShare/remoteSub = %q/%q, want %q/%q",
					m.remoteShare, m.remoteSub, c.wantShare, c.wantSub)
			}
		})
	}
}

func TestParseMappingErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"too few fields", "share:10.0.0.5:C$:Administrator:CORP"},
		{"empty host", "share::C$:Administrator:CORP:8846f7eaee8fb117ad06bdd830b7586c"},
		{"empty credential", "share:10.0.0.5:C$:Administrator:CORP:"},
		{"empty share name before inner path", "share:10.0.0.5:\\Users:Administrator:CORP:pw"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseMapping(tc.raw); err == nil {
				t.Errorf("parseMapping(%q) = nil error, want error", tc.raw)
			}
		})
	}
}

// Fields with identical (host,user,domain) share a connKey only when the
// resolved NT hash matches, whether supplied as a hash or a password.
func TestParseMappingKeyDedup(t *testing.T) {
	const nt = "8846f7eaee8fb117ad06bdd830b7586c"
	pw := "secret"

	byHash, err := parseMapping("a:10.0.0.5:C$:u:CORP:" + ntHashOf(pw))
	if err != nil {
		t.Fatal(err)
	}
	byPass, err := parseMapping("b:10.0.0.5:C$:u:CORP:" + pw)
	if err != nil {
		t.Fatal(err)
	}
	if byHash.key() != byPass.key() {
		t.Errorf("password and its hash produced different conn keys: %+v vs %+v",
			byHash.key(), byPass.key())
	}

	diff, err := parseMapping("c:10.0.0.5:C$:u:CORP:" + nt)
	if err != nil {
		t.Fatal(err)
	}
	if diff.key() == byPass.key() {
		t.Errorf("different credentials unexpectedly shared a conn key: %+v", diff.key())
	}
}

func TestParseMapLines(t *testing.T) {
	// Mixed content: a comment, blanks, CRLF endings, surrounding whitespace,
	// a credential that itself contains '#', and an indented comment.
	content := "# header comment\r\n" +
		"\r\n" +
		"  corp_c:10.0.0.5:C$:Admin:CORP:8846f7eaee8fb117ad06bdd830b7586c  \r\n" +
		"   # indented comment\r\n" +
		"dev:10.0.0.6:Builds:svc:CORP:p@ss#word\n" +
		"\t\n"

	got := parseMapLines(content)
	want := []string{
		"corp_c:10.0.0.5:C$:Admin:CORP:8846f7eaee8fb117ad06bdd830b7586c",
		"dev:10.0.0.6:Builds:svc:CORP:p@ss#word",
	}
	if len(got) != len(want) {
		t.Fatalf("parseMapLines returned %d lines %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}

	if lines := parseMapLines("\n# all comments\n   \n"); lines != nil {
		t.Errorf("comment/blank-only content = %q, want nil", lines)
	}
}

func TestReadMapFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shares.maps")
	content := "# shares\na:h:C$:u:d:p1\n\nb:h:D$:u:d:p2\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	lines, err := readMapFile(path)
	if err != nil {
		t.Fatalf("readMapFile: %v", err)
	}
	if len(lines) != 2 || lines[0] != "a:h:C$:u:d:p1" || lines[1] != "b:h:D$:u:d:p2" {
		t.Errorf("readMapFile = %q, want the two share lines", lines)
	}

	// Each kept line must parse as a valid mapping.
	for _, raw := range lines {
		if _, err := parseMapping(raw); err != nil {
			t.Errorf("parseMapping(%q): %v", raw, err)
		}
	}

	if _, err := readMapFile(filepath.Join(dir, "missing.maps")); err == nil {
		t.Errorf("readMapFile on a missing path = nil error, want an error")
	}
}

func TestMultiFlag(t *testing.T) {
	var f multiFlag
	if got := f.String(); got != "" {
		t.Errorf("empty String() = %q, want \"\"", got)
	}
	for _, s := range []string{"a:1", "b:2"} {
		if err := f.Set(s); err != nil {
			t.Fatalf("Set(%q): %v", s, err)
		}
	}
	if len(f) != 2 || f[0] != "a:1" || f[1] != "b:2" {
		t.Errorf("values = %q, want [a:1 b:2] in order", []string(f))
	}
	if got := f.String(); got != "a:1, b:2" {
		t.Errorf("String() = %q, want \"a:1, b:2\"", got)
	}
}
