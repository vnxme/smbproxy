// smbproxy: local SMB server that authenticates upstream using NTLM
// credentials (an NTLM hash or a password), exposing remote Windows shares to
// local SMB clients.
//
// Architecture:
//   Windows Explorer → [local SMB server (this tool)] → [target(s), NTLM auth]
//
// Multiple upstream shares can be proxied simultaneously. Mappings that share
// the same (host, user, domain, credential) tuple reuse a single upstream SMB
// connection; different credentials get separate connections.
//
// Build:
//   go mod tidy && go build -o smbproxy .
//
// Usage (single share):
//   sudo ./smbproxy \
//     -map "share:10.0.0.5:C$:Administrator:CORP:8846f7eaee8fb117ad06bdd830b7586c"
//
// Usage (multiple shares, possibly across multiple hosts):
//   sudo ./smbproxy \
//     -map "corp_c:10.0.0.5:C$:Administrator:CORP:8846...86c" \
//     -map "corp_d:10.0.0.5:D$:Administrator:CORP:8846...86c" \
//     -map "dev:10.0.0.6:Builds:svc_build:CORP:aad3...04ee:dead...beef"
//
// The credential field accepts a 32-char NTLM hash, a "lmhash:nthash" pair
// (only the NT half is used), a plaintext password, or "pass:<password>" to
// force password mode (needed only when the password is itself 32 hex chars).
// A password is converted to its NT hash internally, so it is equivalent to
// passing that hash.
//
// Connect from Explorer:  \\<this-host>\<local-share-name>
// Map a drive:            net use Z: \\<this-host>\corp_c /user:guest guest
//
// The implementation is split across several files in this package:
//   mapping.go   — -map flag parsing, the mapping type, and connKey dedup keys
//   upstream.go  — the shared upstream connection and openUpstream dialing
//   helpers.go   — FILETIME/attr/path conversions shared by the VFS
//   proxyvfs.go  — proxyHandle and proxyVFS (reads, prefetch, dir listing)
//   noopvfs.go   — the no-op VFS registered for IPC$
//   rpcpipe.go   — the srvsvc DCE/RPC pipe wrapper and BindAck fixup
//   main.go      — flag wiring and server startup (this file)

package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcesrv "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/golog"
)

func main() {
	var maps multiFlag
	flag.Var(&maps, "map",
		"share mapping: local_share:host:remote_share:user:domain:credential\n"+
			"\t  credential = 32 hex chars (NTLM hash), lmhash:nthash pair,\n"+
			"\t               a password, or pass:<password> to force password mode\n"+
			"\t               (use pass: for a password that is itself 32 hex chars)\n"+
			"\t  repeat -map for multiple shares / multiple targets\n"+
			"\t  mappings with identical (host,user,domain,credential) share one upstream connection")

	listen := flag.String("l", "0.0.0.0:445", "local listen addr:port (port 445 needs root/CAP_NET_BIND_SERVICE)")
	localUser := flag.String("local-user", "guest", "username clients authenticate with")
	localPass := flag.String("local-pass", "guest", "password clients authenticate with")
	allowGuest := flag.Bool("allow-guest", false, "accept any failed/unknown logon as a guest session (lets Explorer browse \\\\host, which first tries the username \"guest\")")
	maxDialect := flag.String("max-dialect", "3.1.1", "highest SMB dialect to offer clients: 2.1, 3.0, 3.0.2 or 3.1.1 (min stays 2.1; 3.x uses AES-CMAC signing that Windows prefers over 2.1's HMAC-SHA256)")
	debugLog := flag.Bool("debug", false, "enable verbose go-smb debug logging (dialect, signing, session setup, DCE/RPC)")
	flag.Parse()

	maxDialectID, ok := dialectByName[*maxDialect]
	if !ok {
		log.Fatalf("[!] invalid -max-dialect %q: use one of 2.1, 3.0, 3.0.2, 3.1.1", *maxDialect)
	}

	// Verbose go-smb logging. Every go-smb package registers its own named
	// logger at init via golog.Get(...); SetAll raises the level on all of
	// them at once. Lshortfile adds file:line so a failing leg is easy to
	// trace. Without -debug the library stays at its default (Notice).
	if *debugLog {
		golog.SetAll(golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, os.Stdout, os.Stderr)
		verbose = true // enable rpcPipe PDU tracing
	}

	if len(maps) == 0 {
		flag.Usage()
		log.Fatal("\nat least one -map flag is required\n\n" +
			"Example:\n" +
			"  sudo ./smbproxy \\\n" +
			"    -map \"share:10.0.0.5:C$:Administrator:CORP:8846f7eaee8fb117ad06bdd830b7586c\"\n\n" +
			"Multiple shares:\n" +
			"  sudo ./smbproxy \\\n" +
			"    -map \"corp_c:10.0.0.5:C$:Administrator:CORP:8846...86c\" \\\n" +
			"    -map \"corp_d:10.0.0.5:D$:Administrator:CORP:8846...86c\" \\\n" +
			"    -map \"dev:10.0.0.6:Builds:svc_build:CORP:dead...beef\"\n\n" +
			"Password instead of a hash (converted to its NT hash internally):\n" +
			"  sudo ./smbproxy \\\n" +
			"    -map \"share:10.0.0.5:C$:Administrator:CORP:S3cretP@ss\"")
	}

	// ---- Parse and validate all mappings ----
	mappings := make([]mapping, 0, len(maps))
	seen := map[string]bool{}
	for _, raw := range maps {
		m, err := parseMapping(raw)
		if err != nil {
			log.Fatalf("[!] invalid -map %q: %v", raw, err)
		}
		if seen[m.localShare] {
			log.Fatalf("[!] duplicate local share name %q", m.localShare)
		}
		seen[m.localShare] = true
		mappings = append(mappings, m)
	}

	// ---- Open upstream connections (deduplicated by connKey) ----
	upstreams := map[connKey]*upstream{}
	for _, m := range mappings {
		k := m.key()
		if _, ok := upstreams[k]; ok {
			continue // already connected with these credentials
		}
		log.Printf("[*] connecting to \\\\%s\\%s as %s\\%s ...",
			m.remoteHost, m.remoteShare, m.domain, m.user)
		up, err := openUpstream(m)
		if err != nil {
			log.Fatalf("[!] upstream connect \\\\%s as %s\\%s failed: %v\n"+
				"    STATUS_LOGON_FAILURE  → wrong credential\n"+
				"    STATUS_ACCESS_DENIED  → wrong credential or account restrictions\n"+
				"    'signing required'    → target mandates SMB signing; NTLM hash auth not supported",
				m.remoteHost, m.domain, m.user, err)
		}
		upstreams[k] = up
		log.Printf("[+] authenticated as %s\\%s on %s", m.domain, m.user, m.remoteHost)
	}
	defer func() {
		for _, up := range upstreams {
			up.conn.Close()
		}
	}()

	// ---- Build the local server ----
	auth := &server.MapAuthenticator{
		Accounts: map[string]*server.Account{
			strings.ToLower(*localUser): {NTHash: ntlmssp.Ntowfv1(*localPass)},
		},
	}

	cfg := &server.ServerConfig{
		NetBIOSName:    "SMBPROXY",
		MinDialect:     smb.DialectSmb_2_1,
		MaxDialect:     maxDialectID,
		Authenticator:  auth,
		AllowAnonymous: true,
		AllowGuest:     *allowGuest,
		MaxReadSize:    readAheadSize,
	}

	srv := &server.Server{Config: cfg}

	// ---- Register IPC$ with a no-op VFS ----
	// Without this the server auto-provides IPC$ with VFS=nil, which causes
	// a nil dereference panic in queryFileInfo when Explorer sends QUERY_INFO
	// on a pipe handle (e.g. during the initial IPC$ tree setup).
	srv.RegisterShare("IPC$", server.Share{
		Name: "IPC$",
		Type: smb.ShareTypePipe,
		VFS:  &noopVFS{},
	})

	// ---- Register each proxied share ----
	for _, m := range mappings {
		up := upstreams[m.key()]
		vfs := &proxyVFS{up: up, share: m.remoteShare}
		srv.RegisterShare(m.localShare, server.Share{
			Name:          m.localShare,
			Type:          smb.ShareTypeDisk,
			VFS:           vfs,
			MaximalAccess: 0x001f01ff,
		})
		log.Printf("[+] share \\\\<host>\\%s  →  \\\\%s\\%s  (as %s\\%s)",
			m.localShare, m.remoteHost, m.remoteShare, m.domain, m.user)
	}

	// ---- Wire srvsvc so Explorer can enumerate shares at \\host level ----
	// The library's srvsvc.Service answers NetShareEnumAll (opnum 15), which is
	// all Explorer calls to list shares. rpcPipe adds the WRITE/READ transport
	// and the BindAck fixup the Windows client needs (see its doc).
	svc := &srvsvc.Service{Shares: srvsvc.FromConfig(cfg)}
	cfg.PipeOpener = &server.MapPipeOpener{
		Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			"srvsvc": func(_ *server.Session) (server.PipeBackend, error) {
				return &rpcPipe{
					inner: dcesrv.NewPipeHandler("srvsvc", svc),
				}, nil
			},
		},
	}

	log.Printf("[*] listening on %s", *listen)
	log.Printf("[*] local credentials: user=%s  pass=%s", *localUser, *localPass)
	log.Printf("[*] dialect range: 2.1 .. %s  allow-guest=%t", *maxDialect, *allowGuest)
	log.Printf("[*] browse \\\\<this-host>  or connect directly to \\\\<this-host>\\<share>")

	// ---- Graceful shutdown ----
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
		<-quit
		log.Println("[*] shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(*listen); err != nil && !errors.Is(err, server.ErrServerClosed) {
		log.Fatalf("[!] server error: %v", err)
	}
}
