package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// minimalConfig is the smallest valid configuration; tests append to it or
// replace parts of it.
const minimalConfig = `
local:
  users:
    alice:
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
	if names := cfg.localUserNames(); strings.Join(names, ",") != "alice,bob,carol" {
		t.Errorf("local users = %v, want alice, bob, carol", names)
	}
	if string(cfg.localUsers["alice"].ntHash) != string(ntlmssp.Ntowfv1("local-pw")) ||
		string(cfg.localUsers["carol"].ntHash) != string(ntlmssp.Ntowfv1("S3cretP@ss")) {
		t.Error("local user hashes do not match local.pass and carol's password")
	}
	// read_access as the example sets it: corp_c alice; pub everyone; builds
	// @builders (carol) and alice; lab @finance (alice, bob).
	wantRead := map[string]string{"corp_c": "alice", "pub": "*", "builds": "alice,carol", "lab": "alice,bob"}
	for _, s := range cfg.shares {
		got := "*"
		if s.readAccess != nil {
			users := make([]string, 0, len(s.readAccess.users))
			for u := range s.readAccess.users {
				users = append(users, u)
			}
			slices.Sort(users)
			got = strings.Join(users, ",")
		}
		if got != wantRead[s.name] {
			t.Errorf("share %s read_access users = %s, want %s", s.name, got, wantRead[s.name])
		}
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
server:
  min_dialect: 3.0
  max_dialect: 3.0.2
target_timeouts:
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

// The defaults reach go-smb's ServerConfig as agreed: encryption supported but
// not required, signing enabled, durable handles off, WORKGROUP identity.
func TestServerConfigDefaults(t *testing.T) {
	cfg, _ := mustParse(t, minimalConfig)
	sc := cfg.serverConfig()
	if sc.NetBIOSName != "SMBPROXY" || sc.NetBIOSDomain != "WORKGROUP" || sc.DnsComputerName != "" || sc.DnsDomainName != "" {
		t.Errorf("identity = %q/%q/%q/%q, want SMBPROXY/WORKGROUP/empty/empty",
			sc.NetBIOSName, sc.NetBIOSDomain, sc.DnsComputerName, sc.DnsDomainName)
	}
	if sc.SigningRequired || !sc.EncryptionSupported || sc.RequireEncryption || sc.Compression {
		t.Errorf("signing required=%t, encryption supported=%t required=%t, compression=%t;"+
			" want false, true, false, false", sc.SigningRequired, sc.EncryptionSupported, sc.RequireEncryption, sc.Compression)
	}
	if sc.DurableHandles || sc.DurableHandleTimeout != time.Minute || sc.MaxDurableHandleTimeout != 10*time.Minute {
		t.Errorf("durable handles = %t %s/%s, want off 1m/10m", sc.DurableHandles, sc.DurableHandleTimeout, sc.MaxDurableHandleTimeout)
	}
	if sc.MaxConnections != 512 || sc.IdleTimeout != 5*time.Minute || sc.WriteTimeout != 30*time.Second {
		t.Errorf("limits = %d conns, idle %s, write %s; want 512, 5m, 30s", sc.MaxConnections, sc.IdleTimeout, sc.WriteTimeout)
	}
	if sc.MinDialect != smb.DialectSmb_2_1 || sc.MaxDialect != smb.DialectSmb_3_1_1 || sc.MaxReadSize != readAheadSize {
		t.Errorf("dialects %#x..%#x, max read %d", sc.MinDialect, sc.MaxDialect, sc.MaxReadSize)
	}
	auth, ok := sc.Authenticator.(*server.MapAuthenticator)
	if !ok || auth.Domain != "" || auth.Accounts["alice"] == nil ||
		string(auth.Accounts["alice"].NTHash) != string(ntlmssp.Ntowfv1("pw")) {
		t.Errorf("authenticator = %+v, want alice with any domain", sc.Authenticator)
	}
	if sc.AllowGuest || sc.AllowAnonymous {
		t.Errorf("guest=%t anonymous=%t, want both off", sc.AllowGuest, sc.AllowAnonymous)
	}
}

func TestServerConfigOverrides(t *testing.T) {
	cfg, _ := mustParse(t, strings.Replace(minimalConfig, "  users:\n    alice:\n", "  domain: CORP\n  users:\n    Alice:\n", 1)+`
server:
  listen: 127.0.0.1:1445
  min_dialect: "3.0"
  netbios_name: PROXY1
  netbios_domain: CORP
  dns_name: proxy1.corp.example
  dns_domain: corp.example
  comment: Corporate file proxy
  signing: required
  encryption: required
  compression: true
  durable_handles:
    enabled: true
    timeout: 2m
    max_timeout: 5m
  max_connections: -1
  timeouts:
    idle: 0
    write: 10s
`)
	sc := cfg.serverConfig()
	if cfg.listen != "127.0.0.1:1445" || sc.MinDialect != smb.DialectSmb_3_0 {
		t.Errorf("listen %q, min dialect %#x", cfg.listen, sc.MinDialect)
	}
	if sc.NetBIOSName != "PROXY1" || sc.NetBIOSDomain != "CORP" ||
		sc.DnsComputerName != "proxy1.corp.example" || sc.DnsDomainName != "corp.example" ||
		cfg.comment != "Corporate file proxy" {
		t.Errorf("identity = %q/%q/%q/%q", sc.NetBIOSName, sc.NetBIOSDomain, sc.DnsComputerName, sc.DnsDomainName)
	}
	if !sc.SigningRequired || !sc.EncryptionSupported || !sc.RequireEncryption || !sc.Compression {
		t.Errorf("signing/encryption/compression = %t/%t/%t/%t, want all on",
			sc.SigningRequired, sc.EncryptionSupported, sc.RequireEncryption, sc.Compression)
	}
	if !sc.DurableHandles || sc.DurableHandleTimeout != 2*time.Minute || sc.MaxDurableHandleTimeout != 5*time.Minute {
		t.Errorf("durable handles = %t %s/%s, want on 2m/5m", sc.DurableHandles, sc.DurableHandleTimeout, sc.MaxDurableHandleTimeout)
	}
	// 0 (no limit) and -1 become go-smb's "no limit", a negative value; 0
	// would select its default instead.
	if sc.MaxConnections != -1 || sc.IdleTimeout >= 0 || sc.WriteTimeout != 10*time.Second {
		t.Errorf("limits = %d conns, idle %s, write %s; want -1, negative, 10s", sc.MaxConnections, sc.IdleTimeout, sc.WriteTimeout)
	}
	// Accounts are keyed by lower-cased user name; the domain is enforced.
	if auth := sc.Authenticator.(*server.MapAuthenticator); auth.Domain != "CORP" || auth.Accounts["alice"] == nil {
		t.Errorf("authenticator = %+v, want alice in domain CORP", auth)
	}

	off, _ := mustParse(t, minimalConfig+"server:\n  encryption: off\n")
	if sc := off.serverConfig(); sc.EncryptionSupported || sc.RequireEncryption {
		t.Errorf("encryption off: supported=%t required=%t, want both false", sc.EncryptionSupported, sc.RequireEncryption)
	}
}

// SMB 2.x clients cannot encrypt, so requiring encryption while still
// admitting them is flagged.
func TestServerEncryptionWarnings(t *testing.T) {
	encryptedShare := minimalConfig + "    encrypt: true\n"
	cases := []struct {
		name, yaml, want string // want "" means no warning
	}{
		{"required with SMB 2.x allowed", minimalConfig + "server:\n  encryption: required\n", "encryption is required"},
		{"encrypted share with SMB 2.x allowed", encryptedShare, "some shares require encryption"},
		{"required with SMB 3.0 minimum", minimalConfig + "server:\n  encryption: required\n  min_dialect: \"3.0\"\n", ""},
		{"encrypted share with SMB 3.0 minimum", encryptedShare + "server:\n  min_dialect: \"3.0\"\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, warnings := mustParse(t, c.yaml)
			if c.want == "" {
				if len(warnings) != 0 {
					t.Errorf("warnings = %v, want none", warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], c.want) {
				t.Errorf("warnings = %v, want one containing %q", warnings, c.want)
			}
		})
	}
	cfg, _ := mustParse(t, encryptedShare)
	if !cfg.shares[0].encrypt {
		t.Error("share encrypt: true did not reach the share")
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
	cfg, _ := mustParse(t, strings.Replace(minimalConfig, "  users:\n    alice:\n      password: pw\n", "  allow_guest: true\n", 1))
	if len(cfg.localUsers) != 0 || !cfg.allowGuest {
		t.Errorf("guest-only: users=%v allowGuest=%t", cfg.localUserNames(), cfg.allowGuest)
	}
	cfg, _ = mustParse(t, strings.Replace(minimalConfig, "  users:\n", "  domain: CORP\n  users:\n", 1))
	if cfg.localDomain != "CORP" {
		t.Errorf("local domain = %q, want CORP", cfg.localDomain)
	}
	// Several users, each with its own credential, all accepted by the
	// authenticator under lower-cased names.
	cfg, _ = mustParse(t, strings.Replace(minimalConfig, "      password: pw\n",
		"      password: pw\n    Bob:\n      password_hash: 8846f7eaee8fb117ad06bdd830b7586c\n", 1))
	auth := cfg.authenticator()
	if len(auth.Accounts) != 2 || auth.Accounts["alice"] == nil || auth.Accounts["bob"] == nil {
		t.Errorf("authenticator accounts = %v, want alice and bob", auth.Accounts)
	}
}

func TestConfigErrors(t *testing.T) {
	without := func(old string) string { return strings.Replace(minimalConfig, old, "", 1) }
	replace := func(old, repl string) string { return strings.Replace(minimalConfig, old, repl, 1) }
	cases := []struct {
		name, yaml, want string // want: a fragment of the error
	}{
		{"empty file", "", "no way for clients to log in"},
		{"no shares", strings.Split(minimalConfig, "shares:")[0], "shares: none configured"},
		{"unknown key", minimalConfig + "listne: :445\n", "field listne is not a known setting at the top level"},
		{"misspelled nested key", replace("    password: secret", "    pasword: secret"), "field pasword is not a known setting for a target"},
		{"duplicate target", replace("targets:\n", "targets:\n  t1:\n    host: x\n"), "already defined"},
		{"old top-level timeouts", minimalConfig + "timeouts:\n  io: 1m\n", "field timeouts is not a known setting at the top level"},
		{"bad dialect", minimalConfig + "server:\n  max_dialect: 4.0\n", "server: max_dialect"},
		{"min above max", minimalConfig + "server:\n  min_dialect: 3.1.1\n  max_dialect: 3.0\n", "above max_dialect"},
		{"negative timeout", minimalConfig + "target_timeouts:\n  io: -1s\n", "negative"},
		{"timeout without unit", minimalConfig + "target_timeouts:\n  io: 30\n", "use a unit"},
		{"unknown server key", minimalConfig + "server:\n  signin: required\n", "field signin is not a known setting under server"},
		{"bad signing", minimalConfig + "server:\n  signing: always\n", "use enabled or required"},
		{"bad encryption", minimalConfig + "server:\n  encryption: true\n", "use off, supported or required"},
		{"empty netbios name", minimalConfig + "server:\n  netbios_name: \"\"\n", "netbios_name is required"},
		{"long netbios name", minimalConfig + "server:\n  netbios_name: ABCDEFGHIJKLMNOP\n", "at most 15"},
		{"bad netbios domain", minimalConfig + "server:\n  netbios_domain: CORP/X\n", "do not allow"},
		{"durable timeout above max", minimalConfig + "server:\n  durable_handles:\n    timeout: 20m\n", "above max_timeout"},
		{"durable timeout zero", minimalConfig + "server:\n  durable_handles:\n    timeout: 0\n", "must be positive"},
		{"zero max_connections", minimalConfig + "server:\n  max_connections: 0\n", "-1 for no limit"},
		{"negative client timeout", minimalConfig + "server:\n  timeouts:\n    write: -1s\n", "server: timeouts"},
		{"required signing with guest", replace("      password: pw\n", "      password: pw\n  allow_guest: true\n") +
			"server:\n  signing: required\n", "cannot provide"},
		{"required encryption with anonymous", replace("      password: pw\n", "      password: pw\n  allow_anonymous: true\n") +
			"server:\n  encryption: required\n", "cannot provide"},
		{"share encrypt without server encryption", minimalConfig + "    encrypt: true\nserver:\n  encryption: off\n", "encrypt needs"},
		{"no local login", without("  users:\n    alice:\n      password: pw\n"), "no way for clients to log in"},
		{
			"old single-user keys", replace("  users:\n    alice:\n      password: pw\n", "  user: alice\n  password: pw\n"),
			"field user is not a known setting under local",
		},
		{
			"domain without users", replace("  users:\n    alice:\n      password: pw\n", "  domain: CORP\n  allow_guest: true\n"),
			"domain is set but no users",
		},
		{"user without credential", without("      password: pw\n"), "alice: set exactly one of"},
		{"misspelled user key", replace("      password: pw\n", "      pasword: pw\n"), "field pasword is not a known setting for a user"},
		{"users differing in case", replace("      password: pw\n", "      password: pw\n    ALICE:\n      password: x\n"), "same user"},
		{"user name starting with @", replace("    alice:\n", "    \"@alice\":\n"), "cannot start with"},
		{"user name with a forbidden character", replace("    alice:\n", "    \"al/ice\":\n"), "does not allow"},
		{"group with unknown member", replace("targets:\n", "  groups:\n    g: [alice, nobody]\ntargets:\n"), `member "nobody" is not defined`},
		{"nested group", replace("targets:\n", "  groups:\n    g: [\"@h\"]\ntargets:\n"), "cannot contain groups"},
		{"reserved group name", replace("targets:\n", "  groups:\n    Guests: [alice]\ntargets:\n"), "reserved"},
		{"group named like a user", replace("targets:\n", "  groups:\n    ALICE: [alice]\ntargets:\n"), "same name as user"},
		{"groups differing in case", replace("targets:\n", "  groups:\n    g: [alice]\n    G: [alice]\ntargets:\n"), "same group"},
		{"group written with @", replace("targets:\n", "  groups:\n    \"@g\": [alice]\ntargets:\n"), "without @"},
		{"read_access unknown user", minimalConfig + "    read_access: [bob]\n", `"bob" is not a user`},
		{"read_access unknown group", minimalConfig + "    read_access: [\"@finance\"]\n", `"@finance" is not a group`},
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
		{"write_access on a read-only share", minimalConfig + "    write_access: [alice]\n", "add read_only: false"},
		{"writer who is not a reader", replace("      password: pw\n", "      password: pw\n    bob:\n      password: b\n") +
			"    read_only: false\n    read_access: [alice]\n    write_access: [bob]\n", "writers must also be readers"},
		{"guest writers who are not readers", minimalConfig +
			"    read_only: false\n    read_access: [alice]\n    write_access: [\"@guests\"]\n", "which read_access does not"},
		{"write_access unknown user", minimalConfig + "    read_only: false\n    write_access: [zed]\n", `write_access: "zed" is not a user`},
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
