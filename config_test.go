package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
)

// minimalConfig is the smallest valid configuration; tests append to it or
// replace parts of it.
const minimalConfig = `
local:
  user: alice
  password: pw
targets:
  t1:
    host: 10.0.0.5
    user: admin
    password: secret
shares:
  - name: data
    target: t1
    path: C$
`

// parse runs parseConfig on yaml with password files resolved against dir.
func parse(t *testing.T, yaml, dir string) (*config, []string, error) {
	t.Helper()
	return parseConfig([]byte(yaml), dir)
}

func mustParse(t *testing.T, yaml string) (*config, []string) {
	t.Helper()
	cfg, warnings, err := parse(t, yaml, t.TempDir())
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	return cfg, warnings
}

// The shipped example must stay valid, and resolve to what it describes.
func TestExampleConfig(t *testing.T) {
	data, err := os.ReadFile("smbproxy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir() // the example's password files, relative to the config
	for name, pass := range map[string]string{"local.pass": "local-pw\n", "corp-admin.pass": "corp-pw\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(pass), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, warnings, err := parseConfig(data, dir)
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("example config warnings: %v", warnings)
	}
	if cfg.localUser != "alice" || string(cfg.localHash) != string(ntlmssp.Ntowfv1("local-pw")) {
		t.Errorf("local login = %q with hash %x, want alice with the hash of local.pass", cfg.localUser, cfg.localHash)
	}
	if cfg.minDialect != smb.DialectSmb_2_1 || cfg.maxDialect != smb.DialectSmb_3_1_1 {
		t.Errorf("dialects = %#x..%#x, want 2.1..3.1.1", cfg.minDialect, cfg.maxDialect)
	}
	want := []struct{ name, target, addr, share, sub string }{
		{"corp_c", "corp-admin", "10.0.0.5:445", "C$", ""},
		{"pub", "corp-admin", "10.0.0.5:445", "C$", `Users\Public`},
		{"builds", "build", "fs01.corp.example:445", "Builds", ""},
		{"lab", "lab", "[fd00::5]:4450", "data", `projects\2024`},
	}
	if len(cfg.shares) != len(want) {
		t.Fatalf("got %d shares, want %d", len(cfg.shares), len(want))
	}
	for i, w := range want {
		s := cfg.shares[i]
		if s.name != w.name || s.target.name != w.target || s.target.addr() != w.addr ||
			s.remoteShare != w.share || s.remoteSub != w.sub {
			t.Errorf("share %d = %s → %s %s %s\\%s, want %s → %s %s %s\\%s", i,
				s.name, s.target.name, s.target.addr(), s.remoteShare, s.remoteSub,
				w.name, w.target, w.addr, w.share, w.sub)
		}
	}
	if cfg.shares[0].target != cfg.shares[1].target {
		t.Error("shares of one target resolved to different targets, so would not share a connection")
	}
	if cfg.shares[0].comment != "Corp server, drive C" {
		t.Errorf("comment = %q", cfg.shares[0].comment)
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg, warnings := mustParse(t, minimalConfig)
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	if cfg.listen != "0.0.0.0:445" || cfg.debug || cfg.allowGuest || cfg.allowAnon || cfg.localDomain != "" {
		t.Errorf("defaults: listen=%q debug=%t guest=%t anon=%t domain=%q",
			cfg.listen, cfg.debug, cfg.allowGuest, cfg.allowAnon, cfg.localDomain)
	}
	if cfg.minDialect != smb.DialectSmb_2_1 || cfg.maxDialect != smb.DialectSmb_3_1_1 {
		t.Errorf("default dialects = %#x..%#x, want 2.1..3.1.1", cfg.minDialect, cfg.maxDialect)
	}
	if want := (upstreamTimeouts{idle: 5 * time.Minute, connect: 15 * time.Second, io: time.Minute}); cfg.timeouts != want {
		t.Errorf("default timeouts = %+v, want %+v", cfg.timeouts, want)
	}
	tg := cfg.shares[0].target
	if tg.port != 445 || tg.domain != "" || string(tg.ntHash) != string(ntlmssp.Ntowfv1("secret")) {
		t.Errorf("target = port %d domain %q hash %x", tg.port, tg.domain, tg.ntHash)
	}
}

// YAML reads an unquoted 3.0 as a number and 5m as a string; both must still
// mean what they look like.
func TestConfigScalars(t *testing.T) {
	cfg, _ := mustParse(t, minimalConfig+`
min_dialect: 3.0
max_dialect: 3.0.2
timeouts:
  idle: 0
  connect: 2m30s
  io: 45s
`)
	if cfg.minDialect != smb.DialectSmb_3_0 || cfg.maxDialect != smb.DialectSmb_3_0_2 {
		t.Errorf("dialects = %#x..%#x, want 3.0..3.0.2", cfg.minDialect, cfg.maxDialect)
	}
	if want := (upstreamTimeouts{idle: 0, connect: 150 * time.Second, io: 45 * time.Second}); cfg.timeouts != want {
		t.Errorf("timeouts = %+v, want %+v", cfg.timeouts, want)
	}
}

func TestConfigCredentials(t *testing.T) {
	const nt = "8846f7eaee8fb117ad06bdd830b7586c"
	ntBytes, _ := hex.DecodeString(nt)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.txt"), []byte("from-file\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, cred string
		want       []byte
	}{
		{"password", "password: pw", ntlmssp.Ntowfv1("pw")},
		{"password that looks like a hash", "password: " + nt, ntlmssp.Ntowfv1(nt)},
		{"relative password_file", "password_file: p.txt", ntlmssp.Ntowfv1("from-file")},
		{"absolute password_file", "password_file: " + filepath.ToSlash(filepath.Join(dir, "p.txt")), ntlmssp.Ntowfv1("from-file")},
		{"hash", "password_hash: " + nt, ntBytes},
		{"upper-case hash", "password_hash: " + strings.ToUpper(nt), ntBytes},
		{"lm:nt pair", "password_hash: aad3b435b51404eeaad3b435b51404ee:" + nt, ntBytes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := strings.Replace(minimalConfig, "password: secret", c.cred, 1)
			cfg, _, err := parse(t, yaml, dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.shares[0].target.ntHash; string(got) != string(c.want) {
				t.Errorf("hash = %x, want %x", got, c.want)
			}
		})
	}
}

func TestConfigLocalLogin(t *testing.T) {
	// Guest- or anonymous-only access needs no user.
	cfg, _ := mustParse(t, strings.Replace(minimalConfig, "  user: alice\n  password: pw\n", "  allow_guest: true\n", 1))
	if cfg.localUser != "" || !cfg.allowGuest {
		t.Errorf("guest-only: user=%q allowGuest=%t", cfg.localUser, cfg.allowGuest)
	}
	cfg, _ = mustParse(t, strings.Replace(minimalConfig, "  user: alice\n", "  user: alice\n  domain: CORP\n", 1))
	if cfg.localDomain != "CORP" {
		t.Errorf("local domain = %q, want CORP", cfg.localDomain)
	}
}

func TestConfigErrors(t *testing.T) {
	without := func(old string) string { return strings.Replace(minimalConfig, old, "", 1) }
	replace := func(old, new string) string { return strings.Replace(minimalConfig, old, new, 1) }
	cases := []struct {
		name, yaml, want string // want: a fragment of the error
	}{
		{"empty file", "", "no way for clients to log in"},
		{"no shares", strings.Split(minimalConfig, "shares:")[0], "shares: none configured"},
		{"unknown key", minimalConfig + "listne: :445\n", "field listne is not a known setting at the top level"},
		{"misspelled nested key", replace("    password: secret", "    pasword: secret"), "field pasword is not a known setting for a target"},
		{"duplicate target", replace("targets:\n", "targets:\n  t1:\n    host: x\n"), "already defined"},
		{"bad dialect", minimalConfig + "max_dialect: 4.0\n", "max_dialect"},
		{"min above max", minimalConfig + "min_dialect: 3.1.1\nmax_dialect: 3.0\n", "above max_dialect"},
		{"negative timeout", minimalConfig + "timeouts:\n  io: -1s\n", "negative"},
		{"timeout without unit", minimalConfig + "timeouts:\n  io: 30\n", "use a unit"},
		{"no local login", without("  user: alice\n  password: pw\n"), "no way for clients to log in"},
		{"local credential without user", without("  user: alice\n"), "no user"},
		{"local user without credential", without("  password: pw\n"), "exactly one of"},
		{"two credentials", replace("    password: secret", "    password: secret\n    password_hash: 8846f7eaee8fb117ad06bdd830b7586c"), "exactly one of"},
		{"bad hash", replace("    password: secret", "    password_hash: xyz"), "32 hex"},
		{"bad lm half", replace("    password: secret", "    password_hash: zz:8846f7eaee8fb117ad06bdd830b7586c"), "LM half"},
		{"missing password_file", replace("    password: secret", "    password_file: nope.txt"), "nope.txt"},
		{"no host", without("    host: 10.0.0.5\n"), "host is required"},
		{"bracketed IPv6", replace("host: 10.0.0.5", `host: "[fd00::5]"`), "without brackets"},
		{"no target user", without("    user: admin\n"), "user is required"},
		{"port out of range", replace("    user: admin", "    port: 70000\n    user: admin"), "between 1 and 65535"},
		{"unknown target", replace("    target: t1", "    target: t2"), `"t2" is not defined`},
		{"no path", without("    path: C$\n"), "path must name"},
		{"read_only false", minimalConfig + "    read_only: false\n", "read_only: false"},
		{"reserved name", replace("name: data", "name: IPC$"), "reserved"},
		{"forbidden character", replace("name: data", "name: da*ta"), "does not allow"},
		{"duplicate share, other case", minimalConfig + "  - name: DATA\n    target: t1\n    path: D$\n", "duplicate name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := parse(t, c.yaml, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one containing %q", err, c.want)
			}
		})
	}
}

// Errors must never echo a credential, even when quoting the offending entry.
func TestConfigErrorsHideCredentials(t *testing.T) {
	yaml := strings.Replace(minimalConfig, "    password: secret", "    password: S3cretP@ss\n    password_hash: zz", 1)
	_, _, err := parse(t, yaml, t.TempDir())
	if err == nil || strings.Contains(err.Error(), "S3cretP@ss") {
		t.Errorf("error = %v, want one not containing the password", err)
	}
}

func TestConfigUnusedTargetWarning(t *testing.T) {
	yaml := strings.Replace(minimalConfig, "targets:\n", "targets:\n  spare:\n    host: 10.0.0.9\n    user: u\n    password: x\n", 1)
	_, warnings := mustParse(t, yaml)
	if len(warnings) != 1 || !strings.Contains(warnings[0], `"spare"`) {
		t.Errorf("warnings = %v, want one about the unused target spare", warnings)
	}
}

func TestTargetAddrAndAccount(t *testing.T) {
	v4 := &target{host: "10.0.0.5", port: 445, user: "admin", domain: "CORP"}
	v6 := &target{host: "fd00::5", port: 4450, user: "alice"}
	if v4.addr() != "10.0.0.5:445" || v6.addr() != "[fd00::5]:4450" {
		t.Errorf("addr = %q, %q", v4.addr(), v6.addr())
	}
	if v4.account() != `CORP\admin` || v6.account() != "alice" {
		t.Errorf("account = %q, %q", v4.account(), v6.account())
	}
}

func TestSplitSharePath(t *testing.T) {
	cases := []struct {
		name, path, wantShare, wantSub string
	}{
		{"share root", "C$", "C$", ""},
		{"inner path", `C$\Users\Public`, "C$", `Users\Public`},
		{"trailing backslash trimmed", `share\sub\`, "share", "sub"},
		{"single inner component", `D$\data`, "D$", "data"},
		{"forward slashes", "data/projects/2024", "data", `projects\2024`},
		{"mixed slashes", `C$/Users\Public`, "C$", `Users\Public`},
		{"trailing forward slash trimmed", "media/clips/", "media", "clips"},
		{"empty share name", `\Users`, "", "Users"},
	}
	for _, c := range cases {
		if share, sub := splitSharePath(c.path); share != c.wantShare || sub != c.wantSub {
			t.Errorf("%s: splitSharePath(%q) = %q/%q, want %q/%q", c.name, c.path, share, sub, c.wantShare, c.wantSub)
		}
	}
}

func TestCheckLocalShareName(t *testing.T) {
	for _, ok := range []string{"corp_c", "Data-2024", "hidden$", "имя", strings.Repeat("s", maxShareNameLen)} {
		if err := checkLocalShareName(ok); err != nil {
			t.Errorf("checkLocalShareName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"IPC$", "ipc$", "my\tshare", "a/b", strings.Repeat("s", maxShareNameLen+1)} {
		if err := checkLocalShareName(bad); err == nil {
			t.Errorf("checkLocalShareName(%q) = nil, want error", bad)
		}
	}
}

func TestReadPassFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Only the line ending is stripped: surrounding spaces belong to the password.
	if got, err := readPassFile(write("crlf", " pa ss \r\nignored\r\n")); err != nil || got != " pa ss " {
		t.Errorf("CRLF file = (%q, %v), want (\" pa ss \", nil)", got, err)
	}
	if got, err := readPassFile(write("bare", "secret")); err != nil || got != "secret" {
		t.Errorf("file without newline = (%q, %v), want (\"secret\", nil)", got, err)
	}
	if _, err := readPassFile(write("empty", "\nsecret\n")); err == nil {
		t.Error("empty first line accepted, want error")
	}
	if _, err := readPassFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted, want error")
	}
}
