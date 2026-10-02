package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"go.yaml.in/yaml/v3"
)

// ---------------------------------------------------------------------------
// Configuration file — the tool's only source of settings
//
// fileConfig and its sections mirror the YAML layout (see
// smbproxy.example.yaml); loadConfig decodes it strictly, applies defaults,
// validates it, and resolves it into a config, whose targets and shares are
// what the rest of the proxy works with.
// ---------------------------------------------------------------------------

// defaultConfigPath is read when -config is not given.
const defaultConfigPath = "smbproxy.yaml"

type fileConfig struct {
	Server         serverSection            `yaml:"server"`
	Debug          bool                     `yaml:"debug"`
	Local          localSection             `yaml:"local"`
	TargetTimeouts targetTimeoutsSection    `yaml:"target_timeouts"`
	Targets        map[string]targetSection `yaml:"targets"`
	Shares         []shareSection           `yaml:"shares"`
}

// serverSection holds how clients see and reach the proxy.
type serverSection struct {
	Listen         string                `yaml:"listen"`
	MinDialect     string                `yaml:"min_dialect"`
	MaxDialect     string                `yaml:"max_dialect"`
	NetBIOSName    string                `yaml:"netbios_name"`
	NetBIOSDomain  string                `yaml:"netbios_domain"`
	DNSName        string                `yaml:"dns_name"`
	DNSDomain      string                `yaml:"dns_domain"`
	Comment        string                `yaml:"comment"`
	Signing        string                `yaml:"signing"`    // enabled | required
	Encryption     string                `yaml:"encryption"` // off | supported | required
	Compression    bool                  `yaml:"compression"`
	DurableHandles durableSection        `yaml:"durable_handles"`
	MaxConnections int                   `yaml:"max_connections"`
	Timeouts       serverTimeoutsSection `yaml:"timeouts"`
}

type durableSection struct {
	Enabled    bool     `yaml:"enabled"`
	Timeout    duration `yaml:"timeout"`
	MaxTimeout duration `yaml:"max_timeout"`
}

// serverTimeoutsSection bounds waits on clients.
type serverTimeoutsSection struct {
	Idle  duration `yaml:"idle"`
	Write duration `yaml:"write"`
}

// Credential is a secret in one of three forms; exactly one must be set.
type Credential struct {
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"password_file"` // first line of the file; relative to the config file
	PasswordHash string `yaml:"password_hash"` // NT hash: 32 hex chars, or an lmhash:nthash pair
}

type localSection struct {
	User           string `yaml:"user"`
	Domain         string `yaml:"domain"`
	Credential     `yaml:",inline"`
	AllowGuest     bool `yaml:"allow_guest"`
	AllowAnonymous bool `yaml:"allow_anonymous"`
}

// targetTimeoutsSection bounds waits on targets.
type targetTimeoutsSection struct {
	Idle    duration `yaml:"idle"`
	Connect duration `yaml:"connect"`
	IO      duration `yaml:"io"`
}

// duration is a time.Duration written as a Go duration string ("90s", "5m").
// Unlike yaml.v3's own decoding it also accepts a bare 0, which is how the
// configuration disables a limit; any other bare number is rejected, as its
// unit would be a guess.
type duration time.Duration

func (d *duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: expected a duration such as 30s or 5m", n.Line)
	}
	if n.Value == "0" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %q is not a duration; use a unit, e.g. 30s or 5m (0 disables)", n.Line, n.Value)
	}
	*d = duration(v)
	return nil
}

type targetSection struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	User       string `yaml:"user"`
	Domain     string `yaml:"domain"`
	Credential `yaml:",inline"`
}

type shareSection struct {
	Name     string `yaml:"name"`
	Target   string `yaml:"target"`
	Path     string `yaml:"path"`
	Comment  string `yaml:"comment"`
	ReadOnly *bool  `yaml:"read_only"`
	Encrypt  bool   `yaml:"encrypt"`
}

// config is a validated configuration, ready to run the proxy from.
type config struct {
	listen                         string
	minDialect, maxDialect         uint16
	minDialectName, maxDialectName string
	debug                          bool

	netbiosName, netbiosDomain string // identity announced during NTLM login
	dnsName, dnsDomain         string
	comment                    string // server description shown by Explorer
	signing                    string // "enabled" | "required"
	encryption                 string // "off" | "supported" | "required"
	compression                bool
	durableHandles             bool
	durableTimeout             time.Duration // default retention of a disconnected handle
	durableMaxTimeout          time.Duration // cap on what a client may request
	maxConnections             int           // -1 = no limit
	clientIdleTimeout          time.Duration // 0 = no limit
	clientWriteTimeout         time.Duration // 0 = no limit

	localUser   string // "" when clients can only connect as guest or anonymous
	localDomain string // "" accepts any domain
	localHash   []byte // the local user's NT hash
	allowGuest  bool
	allowAnon   bool

	timeouts upstreamTimeouts
	shares   []share // in file order, which is the order Explorer lists them in
}

// target is one server the proxy connects to, with the account it uses there.
// Each target gets one upstream connection, shared by all its shares.
type target struct {
	name         string
	host         string
	port         int
	user, domain string
	ntHash       []byte
}

// addr returns the target's host:port, bracketing an IPv6 host.
func (t *target) addr() string { return net.JoinHostPort(t.host, strconv.Itoa(t.port)) }

// account returns the target's login as DOMAIN\user, or user without a domain.
func (t *target) account() string {
	if t.domain == "" {
		return t.user
	}
	return t.domain + `\` + t.user
}

// share is one local share, exposing a folder of a target's share.
type share struct {
	name, comment string
	target        *target
	remoteShare   string // share on the target (e.g. "C$")
	remoteSub     string // inner directory within it (empty = share root)
	encrypt       bool   // require SMB 3.x encryption for this share
}

// yamlSectionNames rewrites the Go type names in yaml.v3's errors ("field x
// not found in type main.localSection") into the sections they stand for.
var yamlSectionNames = strings.NewReplacer(
	"not found in type main.fileConfig", "is not a known setting at the top level",
	"not found in type main.serverSection", "is not a known setting under server",
	"not found in type main.durableSection", "is not a known setting under server.durable_handles",
	"not found in type main.serverTimeoutsSection", "is not a known setting under server.timeouts",
	"not found in type main.localSection", "is not a known setting under local",
	"not found in type main.targetTimeoutsSection", "is not a known setting under target_timeouts",
	"not found in type main.targetSection", "is not a known setting for a target",
	"not found in type main.shareSection", "is not a known setting for a share",
)

// dialectByName maps a dialect name in the configuration to its go-smb constant.
var dialectByName = map[string]uint16{
	"2.0.2": smb.DialectSmb_2_0_2,
	"2.1":   smb.DialectSmb_2_1,
	"3.0":   smb.DialectSmb_3_0,
	"3.0.2": smb.DialectSmb_3_0_2,
	"3.1.1": smb.DialectSmb_3_1_1,
}

// loadConfig reads, validates and resolves the configuration file at path. It
// also returns warnings: settings that are valid but probably not intended.
func loadConfig(path string) (*config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cfg, warnings, err := parseConfig(data, filepath.Dir(path))
	if err != nil {
		return nil, nil, err
	}
	if w := permissionWarning(path, data); w != "" {
		warnings = append(warnings, w)
	}
	return cfg, warnings, nil
}

// parseConfig decodes and resolves configuration data. Relative password_file
// paths are resolved against baseDir, the configuration file's directory.
func parseConfig(data []byte, baseDir string) (*config, []string, error) {
	fc := fileConfig{
		Server: serverSection{
			Listen:        "0.0.0.0:445",
			MinDialect:    "2.1",
			MaxDialect:    "3.1.1",
			NetBIOSName:   "SMBPROXY",
			NetBIOSDomain: "WORKGROUP",
			Signing:       "enabled",
			Encryption:    "supported",
			DurableHandles: durableSection{
				Timeout:    duration(time.Minute),
				MaxTimeout: duration(10 * time.Minute),
			},
			MaxConnections: 512,
			Timeouts: serverTimeoutsSection{
				Idle:  duration(5 * time.Minute),
				Write: duration(30 * time.Second),
			},
		},
		TargetTimeouts: targetTimeoutsSection{
			Idle:    duration(5 * time.Minute),
			Connect: duration(15 * time.Second),
			IO:      duration(time.Minute),
		},
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a misspelled key is an error, not silently ignored
	// An empty file decodes as io.EOF; it then fails below for having no shares.
	if err := dec.Decode(&fc); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, errors.New(yamlSectionNames.Replace(err.Error()))
	}

	cfg := &config{debug: fc.Debug}
	var warnings []string
	if err := resolveServer(cfg, fc.Server); err != nil {
		return nil, nil, fmt.Errorf("server: %w", err)
	}

	// ---- Local login ----
	l := fc.Local
	cfg.allowGuest, cfg.allowAnon = l.AllowGuest, l.AllowAnonymous
	switch {
	case l.User != "":
		hash, err := l.Credential.ntHash(baseDir)
		if err != nil {
			return nil, nil, fmt.Errorf("local: %w", err)
		}
		cfg.localUser, cfg.localDomain, cfg.localHash = l.User, l.Domain, hash
	case l.Domain != "" || l.Credential.count() > 0:
		return nil, nil, errors.New("local: a domain or credential is set but no user")
	case !l.AllowGuest && !l.AllowAnonymous:
		return nil, nil, errors.New("local: no way for clients to log in: set user and a credential," +
			" or allow_guest or allow_anonymous")
	}

	// Guest and anonymous sessions have no session key, so they can neither
	// sign nor encrypt; requiring either would make those logins always fail.
	if (cfg.signing == "required" || cfg.encryption == "required") && (cfg.allowGuest || cfg.allowAnon) {
		return nil, nil, errors.New("server: signing or encryption is required, which guest and anonymous" +
			" sessions cannot provide; disable local.allow_guest and local.allow_anonymous")
	}

	// ---- Target timeouts ----
	t := fc.TargetTimeouts
	if t.Idle < 0 || t.Connect < 0 || t.IO < 0 {
		return nil, nil, errors.New("target_timeouts: must not be negative (0 disables a limit)")
	}
	cfg.timeouts = upstreamTimeouts{idle: time.Duration(t.Idle), connect: time.Duration(t.Connect), io: time.Duration(t.IO)}

	// ---- Targets ----
	// Validated in name order, so the first error reported is deterministic.
	targets := map[string]*target{}
	names := make([]string, 0, len(fc.Targets))
	for name := range fc.Targets {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		tg, err := resolveTarget(name, fc.Targets[name], baseDir)
		if err != nil {
			return nil, nil, fmt.Errorf("targets.%s: %w", name, err)
		}
		targets[name] = tg
	}

	// ---- Shares ----
	if len(fc.Shares) == 0 {
		return nil, nil, errors.New("shares: none configured")
	}
	used := map[string]bool{}
	seen := map[string]string{} // lower-cased name -> name as first given
	for i, s := range fc.Shares {
		sh, err := resolveShare(s, targets)
		if err != nil {
			return nil, nil, fmt.Errorf("shares[%d] (%s): %w", i, s.Name, err)
		}
		// SMB share names are case-insensitive, so "Data" and "data" collide.
		key := strings.ToLower(sh.name)
		if first, dup := seen[key]; dup {
			return nil, nil, fmt.Errorf("shares[%d]: duplicate name %q (share names are case-insensitive; %q is already defined)",
				i, sh.name, first)
		}
		if sh.encrypt && cfg.encryption == "off" {
			return nil, nil, fmt.Errorf("shares[%d] (%s): encrypt needs server.encryption supported or required", i, sh.name)
		}
		seen[key] = sh.name
		used[s.Target] = true
		cfg.shares = append(cfg.shares, sh)
	}
	for _, name := range names {
		if !used[name] {
			warnings = append(warnings, fmt.Sprintf("target %q is not used by any share", name))
		}
	}

	// SMB 2.x has no encryption, so a client that negotiates it cannot reach
	// an encrypted session or share.
	if cfg.minDialect < smb.DialectSmb_3_0 {
		if cfg.encryption == "required" {
			warnings = append(warnings, fmt.Sprintf("server.encryption is required but min_dialect %s lets SMB 2.x"+
				" clients connect, and they cannot encrypt; set min_dialect to 3.0 or above", cfg.minDialectName))
		} else if slices.ContainsFunc(cfg.shares, func(s share) bool { return s.encrypt }) {
			warnings = append(warnings, fmt.Sprintf("some shares require encryption but min_dialect %s lets SMB 2.x"+
				" clients connect, and they cannot open those shares", cfg.minDialectName))
		}
	}
	return cfg, warnings, nil
}

func resolveTarget(name string, s targetSection, baseDir string) (*target, error) {
	switch {
	case s.Host == "":
		return nil, errors.New("host is required")
	case strings.HasPrefix(s.Host, "["):
		return nil, fmt.Errorf("host %q: give an IPv6 address without brackets (the port is a separate field)", s.Host)
	case s.User == "":
		return nil, errors.New("user is required")
	}
	port := s.Port
	if port == 0 {
		port = 445
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d: must be between 1 and 65535", s.Port)
	}
	hash, err := s.Credential.ntHash(baseDir)
	if err != nil {
		return nil, err
	}
	return &target{name: name, host: s.Host, port: port, user: s.User, domain: s.Domain, ntHash: hash}, nil
}

func resolveShare(s shareSection, targets map[string]*target) (share, error) {
	if s.Name == "" {
		return share{}, errors.New("name is required")
	}
	if err := checkLocalShareName(s.Name); err != nil {
		return share{}, err
	}
	if s.Target == "" {
		return share{}, errors.New("target is required")
	}
	tg, ok := targets[s.Target]
	if !ok {
		return share{}, fmt.Errorf("target %q is not defined under targets", s.Target)
	}
	remote, sub := splitSharePath(s.Path)
	if remote == "" {
		return share{}, errors.New("path must name the target's share, optionally followed by an inner folder")
	}
	if s.ReadOnly != nil && !*s.ReadOnly {
		return share{}, errors.New("read_only: false is not supported yet; the proxy is read-only")
	}
	return share{name: s.Name, comment: s.Comment, target: tg, remoteShare: remote, remoteSub: sub, encrypt: s.Encrypt}, nil
}

// resolveServer validates the server section into cfg.
func resolveServer(cfg *config, s serverSection) error {
	cfg.listen = s.Listen
	var ok bool
	if cfg.minDialect, ok = dialectByName[s.MinDialect]; !ok {
		return fmt.Errorf("min_dialect %q: use one of %s", s.MinDialect, dialectNames())
	}
	if cfg.maxDialect, ok = dialectByName[s.MaxDialect]; !ok {
		return fmt.Errorf("max_dialect %q: use one of %s", s.MaxDialect, dialectNames())
	}
	if cfg.minDialect > cfg.maxDialect {
		return fmt.Errorf("min_dialect %s is above max_dialect %s", s.MinDialect, s.MaxDialect)
	}
	cfg.minDialectName, cfg.maxDialectName = s.MinDialect, s.MaxDialect

	if err := checkNetBIOSName("netbios_name", s.NetBIOSName); err != nil {
		return err
	}
	if err := checkNetBIOSName("netbios_domain", s.NetBIOSDomain); err != nil {
		return err
	}
	cfg.netbiosName, cfg.netbiosDomain = s.NetBIOSName, s.NetBIOSDomain
	cfg.dnsName, cfg.dnsDomain, cfg.comment = s.DNSName, s.DNSDomain, s.Comment

	switch s.Signing {
	case "enabled", "required":
		cfg.signing = s.Signing
	default:
		return fmt.Errorf("signing %q: use enabled or required", s.Signing)
	}
	switch s.Encryption {
	case "off", "supported", "required":
		cfg.encryption = s.Encryption
	default:
		return fmt.Errorf("encryption %q: use off, supported or required", s.Encryption)
	}
	cfg.compression = s.Compression

	d := s.DurableHandles
	if d.Timeout <= 0 || d.MaxTimeout <= 0 {
		return errors.New("durable_handles: timeout and max_timeout must be positive")
	}
	if d.Timeout > d.MaxTimeout {
		return fmt.Errorf("durable_handles: timeout %s is above max_timeout %s",
			time.Duration(d.Timeout), time.Duration(d.MaxTimeout))
	}
	cfg.durableHandles = d.Enabled
	cfg.durableTimeout, cfg.durableMaxTimeout = time.Duration(d.Timeout), time.Duration(d.MaxTimeout)

	if s.MaxConnections < 1 && s.MaxConnections != -1 {
		return fmt.Errorf("max_connections %d: use a positive number, or -1 for no limit", s.MaxConnections)
	}
	cfg.maxConnections = s.MaxConnections

	if s.Timeouts.Idle < 0 || s.Timeouts.Write < 0 {
		return errors.New("timeouts: must not be negative (0 disables a limit)")
	}
	cfg.clientIdleTimeout, cfg.clientWriteTimeout = time.Duration(s.Timeouts.Idle), time.Duration(s.Timeouts.Write)
	return nil
}

// netbiosNameInvalidChars are the characters a NetBIOS name may not contain.
const netbiosNameInvalidChars = `\/:*?"<>|`

// checkNetBIOSName rejects a NetBIOS computer or domain name Windows would
// not accept: empty, longer than 15 characters, or with a forbidden character.
func checkNetBIOSName(field, name string) error {
	if name == "" {
		return fmt.Errorf("%s is required", field)
	}
	if n := utf8.RuneCountInString(name); n > 15 {
		return fmt.Errorf("%s %q is %d characters long; NetBIOS names allow at most 15", field, name, n)
	}
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(netbiosNameInvalidChars, r) {
			return fmt.Errorf("%s %q contains %q, which NetBIOS names do not allow", field, name, r)
		}
	}
	return nil
}

// authenticator returns the verifier for client logins: the local user, if
// any, and the required domain ("" accepts any).
func (c *config) authenticator() *server.MapAuthenticator {
	auth := &server.MapAuthenticator{Domain: c.localDomain, Accounts: map[string]*server.Account{}}
	if c.localUser != "" {
		auth.Accounts[strings.ToLower(c.localUser)] = &server.Account{NTHash: c.localHash}
	}
	return auth
}

// serverConfig returns the go-smb server settings the configuration
// describes. Shares and the srvsvc pipe are added by the caller.
func (c *config) serverConfig() *server.ServerConfig {
	return &server.ServerConfig{
		NetBIOSName:             c.netbiosName,
		NetBIOSDomain:           c.netbiosDomain,
		DnsComputerName:         c.dnsName,
		DnsDomainName:           c.dnsDomain,
		MinDialect:              c.minDialect,
		MaxDialect:              c.maxDialect,
		SigningRequired:         c.signing == "required",
		EncryptionSupported:     c.encryption != "off",
		RequireEncryption:       c.encryption == "required",
		Compression:             c.compression,
		DurableHandles:          c.durableHandles,
		DurableHandleTimeout:    c.durableTimeout,
		MaxDurableHandleTimeout: c.durableMaxTimeout,
		// One client READ maps to one upstream read-ahead batch.
		MaxReadSize:    readAheadSize,
		IdleTimeout:    libraryTimeout(c.clientIdleTimeout),
		WriteTimeout:   libraryTimeout(c.clientWriteTimeout),
		MaxConnections: c.maxConnections, // -1 means no limit to go-smb too
		Authenticator:  c.authenticator(),
		AllowAnonymous: c.allowAnon,
		AllowGuest:     c.allowGuest,
	}
}

// libraryTimeout converts a timeout where 0 means no limit, as throughout the
// configuration, into go-smb's convention, where 0 selects its default and a
// negative value means no limit.
func libraryTimeout(d time.Duration) time.Duration {
	if d == 0 {
		return -1
	}
	return d
}

// count returns how many of the credential's forms are set.
func (c Credential) count() int {
	n := 0
	for _, v := range []string{c.Password, c.PasswordFile, c.PasswordHash} {
		if v != "" {
			n++
		}
	}
	return n
}

// ntHash resolves the credential to the NT hash used for NTLM, so every form
// behaves identically from the other side's point of view.
func (c Credential) ntHash(baseDir string) ([]byte, error) {
	if c.count() != 1 {
		return nil, errors.New("set exactly one of password, password_file and password_hash")
	}
	switch {
	case c.Password != "":
		return ntlmssp.Ntowfv1(c.Password), nil
	case c.PasswordFile != "":
		path := c.PasswordFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		pass, err := readPassFile(path)
		if err != nil {
			return nil, fmt.Errorf("password_file %q: %w", c.PasswordFile, err)
		}
		return ntlmssp.Ntowfv1(pass), nil
	default:
		h := c.PasswordHash
		if lm, nt, pair := strings.Cut(h, ":"); pair {
			if !isNTHash(lm) {
				return nil, errors.New("password_hash: the LM half of an lmhash:nthash pair must be 32 hex characters")
			}
			h = nt // only the NT half is used
		}
		if !isNTHash(h) {
			return nil, errors.New("password_hash: must be 32 hex characters, or an lmhash:nthash pair")
		}
		return hex.DecodeString(h)
	}
}

// dialectNames lists the accepted dialect names, lowest first.
func dialectNames() string {
	names := make([]string, 0, len(dialectByName))
	for name := range dialectByName {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int { return int(dialectByName[a]) - int(dialectByName[b]) })
	return strings.Join(names, ", ")
}

// permissionWarning warns when a configuration file holding an inline secret
// (password or password_hash) is readable by users other than its owner.
// Windows file modes do not express this, so it checks only elsewhere.
func permissionWarning(path string, data []byte) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o077 == 0 {
		return ""
	}
	if !bytes.Contains(data, []byte("password:")) && !bytes.Contains(data, []byte("password_hash:")) {
		return ""
	}
	return fmt.Sprintf("%s holds inline secrets but has mode %v; consider chmod 600, or password_file",
		path, fi.Mode().Perm())
}

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

// splitSharePath separates a share's path into the SMB share name and an
// optional inner directory, split on the first path separator. Forward and
// backslashes are both accepted (so slash-style paths work on any platform);
// the returned subpath uses backslashes:
//
//	"C$"               → ("C$", "")
//	"C$\Users\Public"  → ("C$", "Users\Public")
//	"data/projects"    → ("data", "projects")
//
// This lets a local share map to a subfolder of the target share rather than
// its root. Surrounding separators on the subpath are trimmed; SMB share names
// contain no separator, so the first one always begins the subpath.
func splitSharePath(s string) (share, sub string) {
	s = normSlashes(s)
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		return s[:i], strings.Trim(s[i+1:], "\\")
	}
	return s, ""
}

// isNTHash reports whether s is exactly 32 hexadecimal characters — i.e. a
// bare NT hash with no LM-hash prefix.
func isNTHash(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// maxShareNameLen is the longest share name Windows accepts (NNLEN).
const maxShareNameLen = 80

// shareNameInvalidChars are the characters Windows forbids in a share name.
const shareNameInvalidChars = `"/\[]:|<>+=;,*?`

// checkLocalShareName rejects a local share name clients could not connect to:
// one too long, containing a character Windows forbids, or IPC$, which the
// proxy registers itself for its RPC pipes.
func checkLocalShareName(name string) error {
	if strings.EqualFold(name, "IPC$") {
		return fmt.Errorf("share name %q is reserved for the proxy's IPC$ share", name)
	}
	if n := utf8.RuneCountInString(name); n > maxShareNameLen {
		return fmt.Errorf("share name %q is %d characters long; Windows allows at most %d",
			name, n, maxShareNameLen)
	}
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(shareNameInvalidChars, r) {
			return fmt.Errorf("share name %q contains %q, which Windows does not allow (nor any of %s)",
				name, r, shareNameInvalidChars)
		}
	}
	return nil
}

// readPassFile reads a password from the first line of the file at path, so
// it stays out of the configuration file. Only the line ending is stripped,
// since a password may begin or end with spaces.
func readPassFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(data), "\n")
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		return "", errors.New("the first line is empty")
	}
	return line, nil
}
