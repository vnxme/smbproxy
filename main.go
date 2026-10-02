// smbproxy: a local SMB server that gathers remote Windows shares — each
// reached with its own upstream credentials — under one host that local
// clients browse with a single local login.
//
// What it is for:
//   - Aggregation: present many shares, possibly spread across several servers
//     and reached under different accounts, behind one \\host that clients see
//     as ordinary shares — a single umbrella over scattered storage.
//   - Indirect access: reach a share when a direct client→server connection is
//     unwanted or not technically possible. The proxy terminates the client
//     connection and makes its own to the target, so routing, firewalling, and
//     dialect/signing differences are handled once, at the proxy.
//   - Credential confinement: avoid handing the upstream server's credentials
//     to every client. Clients authenticate to the proxy with a separate local
//     login; the real upstream credentials stay in the proxy's configuration.
//
// Architecture:
//   SMB client → [local SMB server (this tool), upstream auth] → target(s)
//
// Clients connect using the proxy's own -local-user / -local-pass. Each mapping
// carries the credentials used to reach its own target, so one proxy can front
// shares that require different accounts. Mappings that share the same
// (host, user, domain, credential) tuple reuse a single upstream SMB
// connection; different credentials get separate connections.
//
// Build:
//   go mod tidy && go build -o smbproxy .
//
// Usage (single share):
//   sudo ./smbproxy \
//     -map "share:10.0.0.5:C$:Administrator:CORP:S3cretP@ss"
//
// Usage (several shares behind one umbrella, across hosts and accounts):
//   sudo ./smbproxy \
//     -map "corp_c:10.0.0.5:C$:Administrator:CORP:S3cretP@ss" \
//     -map "corp_d:10.0.0.5:D$:Administrator:CORP:S3cretP@ss" \
//     -map "dev:10.0.0.6:Builds:svc_build:CORP:BuildB0t!"
//
// Usage (mappings from a file, one -map-formatted line per entry; blank lines
// and #-comments are ignored). A file keeps the upstream credentials out of
// the process argument list, and can be combined with -map:
//   sudo ./smbproxy -mapfile /etc/smbproxy.maps
//
// Usage (map a local share to a subfolder of the target share, not its root;
// forward or back slashes both work, which is handy on non-Windows hosts and
// for Samba targets):
//   sudo ./smbproxy \
//     -map "pub:10.0.0.5:C$/Users/Public:Administrator:CORP:S3cretP@ss" \
//     -map "proj:10.0.0.7:data/projects/2024:alice:WORKGROUP:S3cretP@ss"
//
// The credential field is the secret used to reach that target. It accepts a
// plaintext password (the usual case), "pass:<password>" to force password
// mode when the password is itself 32 hex characters, a 32-character NTLM hash,
// or an "lmhash:nthash" pair (only the NT half is used). A password is
// converted to its NT hash internally, so every form behaves identically from
// the target's point of view.
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

// connectFailureHint returns the guidance printed under an upstream connect
// failure, tailored to the kind of error: a TCP-level failure points at
// reachability (SMB off / wrong host or port / firewall), anything else at
// authentication.
func connectFailureHint(err error) string {
	if isNetworkError(err) {
		return "    unreachable at the TCP level (connection refused / timeout / no route / DNS).\n" +
			"    Is SMB running and port 445 open on the target and through any firewall?\n" +
			"    Check the host and port in the mapping."
	}
	return "    STATUS_LOGON_FAILURE  → wrong credential\n" +
		"    STATUS_ACCESS_DENIED  → wrong credential or account restrictions\n" +
		"    'signing required'    → target mandates SMB signing. smbproxy signs with the\n" +
		"                            supplied credential (an NT hash works as well as a\n" +
		"                            password), so this usually means the credential was\n" +
		"                            rejected and the session fell back to guest/anonymous,\n" +
		"                            which cannot sign — re-check user/domain/credential."
}

// reapUpstreams periodically closes upstream connections that have gone idle
// (see upstream.reapIfIdle), until stop is closed. The tick is a fraction of
// the timeout, clamped to a sane range, so a connection is closed within about
// one tick of crossing the threshold.
func reapUpstreams(upstreams map[connKey]*upstream, idle time.Duration, stop <-chan struct{}) {
	interval := idle / 2
	if interval < time.Second {
		interval = time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			for _, up := range upstreams {
				up.reapIfIdle(now)
			}
		}
	}
}

func main() {
	var maps multiFlag
	flag.Var(&maps, "map",
		"share mapping: local_share:host:remote_share:user:domain:credential\n"+
			"\t  remote_share may include an inner path (either slash works), e.g.\n"+
			"\t               C$\\Users\\Public or data/projects, to map the local share\n"+
			"\t               to a subfolder instead of the share root\n"+
			"\t  credential = a password, pass:<password> to force password mode\n"+
			"\t               (use pass: for a password that is itself 32 hex chars),\n"+
			"\t               a 32-hex-char NTLM hash, or an lmhash:nthash pair\n"+
			"\t  repeat -map to place several shares, hosts or accounts behind one host\n"+
			"\t  mappings with identical (host,user,domain,credential) share one upstream connection")

	var mapFiles multiFlag
	flag.Var(&mapFiles, "mapfile",
		"read share mappings from a file, one -map-formatted line per entry:\n"+
			"\t  local_share:host:remote_share:user:domain:credential\n"+
			"\t  blank lines and lines beginning with # are ignored. Keeps\n"+
			"\t  credentials out of the process argument list; repeat for\n"+
			"\t  several files. Combined with any -map flags.")

	listen := flag.String("l", "0.0.0.0:445", "local listen addr:port (port 445 needs root/CAP_NET_BIND_SERVICE)")
	localUser := flag.String("local-user", "guest", "username clients authenticate with")
	localPass := flag.String("local-pass", "guest", "password clients authenticate with")
	allowGuest := flag.Bool("allow-guest", false, "accept any failed/unknown logon as a guest session (lets Explorer browse \\\\host, which first tries the username \"guest\")")
	maxDialect := flag.String("max-dialect", "3.1.1", "highest SMB dialect to offer clients: 2.1, 3.0, 3.0.2 or 3.1.1 (min stays 2.1; 3.x uses AES-CMAC signing that Windows prefers over 2.1's HMAC-SHA256)")
	idleTimeout := flag.Duration("idle-timeout", 5*time.Minute,
		"close an upstream connection after this period with no open handles and no\n"+
			"\tactivity; it is re-established on demand when a client next uses the share.\n"+
			"\t0 keeps each connection (still dialed on demand) until shutdown")
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

	// ---- Gather raw map lines from -map flags and -mapfile files ----
	rawMaps := append([]string(nil), maps...)
	for _, path := range mapFiles {
		lines, err := readMapFile(path)
		if err != nil {
			log.Fatalf("[!] -mapfile %q: %v", path, err)
		}
		rawMaps = append(rawMaps, lines...)
	}

	if len(rawMaps) == 0 {
		flag.Usage()
		log.Fatal("\nat least one -map or -mapfile entry is required\n\n" +
			"Example:\n" +
			"  sudo ./smbproxy \\\n" +
			"    -map \"share:10.0.0.5:C$:Administrator:CORP:8846f7eaee8fb117ad06bdd830b7586c\"\n\n" +
			"Multiple shares:\n" +
			"  sudo ./smbproxy \\\n" +
			"    -map \"corp_c:10.0.0.5:C$:Administrator:CORP:8846...86c\" \\\n" +
			"    -map \"corp_d:10.0.0.5:D$:Administrator:CORP:8846...86c\" \\\n" +
			"    -map \"dev:10.0.0.6:Builds:svc_build:CORP:dead...beef\"\n\n" +
			"From a file (one such line per entry, keeps credentials off the cmdline):\n" +
			"  sudo ./smbproxy -mapfile /etc/smbproxy.maps\n\n" +
			"Password instead of a hash (converted to its NT hash internally):\n" +
			"  sudo ./smbproxy \\\n" +
			"    -map \"share:10.0.0.5:C$:Administrator:CORP:S3cretP@ss\"")
	}

	// ---- Parse and validate all mappings ----
	mappings := make([]mapping, 0, len(rawMaps))
	seen := map[string]bool{}
	for _, raw := range rawMaps {
		m, err := parseMapping(raw)
		if err != nil {
			log.Fatalf("[!] invalid mapping %q: %v", raw, err)
		}
		if seen[m.localShare] {
			log.Fatalf("[!] duplicate local share name %q", m.localShare)
		}
		seen[m.localShare] = true
		mappings = append(mappings, m)
	}

	// ---- Prepare upstreams (deduplicated by connKey; connected on demand) ----
	// No connection is dialed here: each upstream connects when a client first
	// touches one of its shares, and the idle reaper closes it again after
	// -idle-timeout of inactivity. A consequence is that a bad credential or an
	// unreachable target is reported on first use (to the client, and in the
	// log), not at launch.
	upstreams := map[connKey]*upstream{}
	for _, m := range mappings {
		k := m.key()
		if _, ok := upstreams[k]; !ok {
			upstreams[k] = newUpstream(m, *idleTimeout)
		}
	}
	defer func() {
		for _, up := range upstreams {
			up.close()
		}
	}()

	// ---- Reap idle upstream connections ----
	if *idleTimeout > 0 {
		stopReaper := make(chan struct{})
		defer close(stopReaper)
		go reapUpstreams(upstreams, *idleTimeout, stopReaper)
	}

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
		vfs := &proxyVFS{up: up, share: m.remoteShare, base: m.remoteSub}
		srv.RegisterShare(m.localShare, server.Share{
			Name:          m.localShare,
			Type:          smb.ShareTypeDisk,
			VFS:           vfs,
			MaximalAccess: 0x001f01ff,
		})
		sub := ""
		if m.remoteSub != "" {
			sub = "\\" + m.remoteSub
		}
		log.Printf("[+] share \\\\<host>\\%s  →  \\\\%s\\%s%s  (as %s\\%s)",
			m.localShare, m.remoteHost, m.remoteShare, sub, m.domain, m.user)
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
