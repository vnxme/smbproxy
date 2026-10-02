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
// Configuration:
//   Everything is set in one YAML file (see smbproxy.example.yaml), read from
//   ./smbproxy.yaml or the path given with -config:
//     - local: the login clients use to connect to the proxy;
//     - targets: the servers the proxy connects to, each with the account and
//       credential it uses there; each target gets one upstream connection,
//       shared by all its shares;
//     - shares: what clients see under \\<this-host>, each a share (or a
//       folder within one) on a target.
//   A credential is a password, a password_file holding one, or a
//   password_hash (NT hash); a password is converted to its NT hash
//   internally, so every form behaves identically from the other side's
//   point of view.
//
// Build:
//   go mod tidy && go build -o smbproxy .
//
// Run:
//   sudo ./smbproxy -config /etc/smbproxy/smbproxy.yaml
//
// Connect from Explorer:  \\<this-host>\<share-name>
// Map a drive:            net use Z: \\<this-host>\corp_c /user:<local-user> <password>
//
// The implementation is split across several files in this package:
//   config.go    — the configuration file: layout, validation, targets and shares
//   upstream.go  — the shared upstream connection, dialing and timeouts
//   helpers.go   — FILETIME/attr/path conversions and NTSTATUS mapping
//   proxyvfs.go  — proxyHandle and proxyVFS (reads, prefetch, dir listing)
//   noopvfs.go   — the no-op VFS registered for IPC$
//   tracevfs.go  — the debug wrapper logging every VFS call and its result
//   rpcpipe.go   — the srvsvc DCE/RPC pipe wrapper and BindAck fixup
//   srvsvc.go    — the srvsvc service: the library's plus share and server info
//   main.go      — server startup (this file)

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcesrv "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/golog"
)

// readOnlyAccess is the maximal access advertised for proxied shares:
// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE. The proxy refuses every write, so
// advertising full control (the go-smb default) only led Explorer to offer
// edits that then failed.
const readOnlyAccess = 0x001200a9

// connectFailureHint returns the guidance printed under an upstream connect
// failure, tailored to the kind of error: a TCP-level failure points at
// reachability (SMB off / wrong host or port / firewall), anything else at
// authentication.
func connectFailureHint(err error) string {
	if isNetworkError(err) {
		return "    unreachable at the TCP level (connection refused / timeout / no route / DNS).\n" +
			"    Is SMB running on the target, and its port open through any firewall?\n" +
			"    Check the target's host and port in the configuration."
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
func reapUpstreams(upstreams map[*target]*upstream, idle time.Duration, stop <-chan struct{}) {
	interval := idle / 2
	interval = max(interval, time.Second)
	interval = min(interval, time.Minute)
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
	configPath := flag.String("config", defaultConfigPath,
		"configuration file (YAML); see smbproxy.example.yaml for every setting")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"usage: %s [-config file]\n\nAll settings are in the configuration file.\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}

	cfg, warnings, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("[!] configuration %s: %v", *configPath, err)
	}
	for _, w := range warnings {
		log.Printf("[!] configuration: %s", w)
	}

	// Verbose go-smb logging. Every go-smb package registers its own named
	// logger at init via golog.Get(...); SetAll raises the level on all of
	// them at once. Lshortfile adds file:line so a failing leg is easy to
	// trace. Without debug the library stays at its default (Notice).
	if cfg.debug {
		golog.SetAll(golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, os.Stdout, os.Stderr)
		verbose = true // enable rpcPipe PDU tracing
	}

	// ---- Prepare upstreams (one per target in use; connected on demand) ----
	// No connection is dialed here: each upstream connects when a client first
	// touches one of its shares, and the idle reaper closes it again after
	// timeouts.idle of inactivity. A consequence is that a bad credential or an
	// unreachable target is reported on first use (to the client, and in the
	// log), not at launch.
	upstreams := map[*target]*upstream{}
	for _, sh := range cfg.shares {
		if _, ok := upstreams[sh.target]; !ok {
			upstreams[sh.target] = newUpstream(sh.target, cfg.timeouts)
		}
	}
	defer func() {
		for _, up := range upstreams {
			up.close()
		}
	}()

	// ---- Reap idle upstream connections ----
	if cfg.timeouts.idle > 0 {
		stopReaper := make(chan struct{})
		defer close(stopReaper)
		go reapUpstreams(upstreams, cfg.timeouts.idle, stopReaper)
	}

	// ---- Build the local server ----
	srvCfg := cfg.serverConfig()
	srv := &server.Server{Config: srvCfg}

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
	for _, sh := range cfg.shares {
		var vfs server.VFS = &proxyVFS{up: upstreams[sh.target], share: sh.remoteShare, base: sh.remoteSub}
		if cfg.debug {
			vfs = &tracingVFS{share: sh.name, inner: vfs}
		}
		srv.RegisterShare(sh.name, server.Share{
			Name:          sh.name,
			Type:          smb.ShareTypeDisk,
			Remark:        sh.comment,
			EncryptData:   sh.encrypt,
			VFS:           vfs,
			MaximalAccess: readOnlyAccess,
		})
		sub := ""
		if sh.remoteSub != "" {
			sub = "\\" + sh.remoteSub
		}
		log.Printf("[+] share \\\\<host>\\%s  →  %s\\%s%s  (target %s, as %s)",
			sh.name, sh.target.addr(), sh.remoteShare, sub, sh.target.name, sh.target.account())
	}

	// ---- Wire srvsvc so Explorer can enumerate shares at \\host level ----
	// The library's srvsvc.Service answers NetShareEnumAll (opnum 15), which is
	// all Explorer calls to list shares; srvsvcService adds NetrShareGetInfo
	// (opnum 16), queried when a file is opened in an application, and
	// NetrServerGetInfo (opnum 21), queried by a share's Properties > Network
	// tab. rpcPipe adds the WRITE/READ transport and the BindAck fixup the
	// Windows client needs (see its doc).
	svc := newSrvsvcService(cfg, srvsvc.FromConfig(srvCfg))
	srvCfg.PipeOpener = &server.MapPipeOpener{
		Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			"srvsvc": func(_ *server.Session) (server.PipeBackend, error) {
				return &rpcPipe{
					inner: dcesrv.NewPipeHandler("srvsvc", svc),
				}, nil
			},
		},
	}

	log.Printf("[*] listening on %s", cfg.listen)
	switch {
	case cfg.localUser == "":
		log.Printf("[*] local login: none; guest/anonymous access only")
	case cfg.localDomain != "":
		log.Printf("[*] local login: %s\\%s", cfg.localDomain, cfg.localUser)
	default:
		log.Printf("[*] local login: %s (any domain)", cfg.localUser)
	}
	log.Printf("[*] server %s (domain %s)  dialects %s .. %s",
		cfg.netbiosName, cfg.netbiosDomain, cfg.minDialectName, cfg.maxDialectName)
	log.Printf("[*] signing=%s  encryption=%s  compression=%t  durable_handles=%t",
		cfg.signing, cfg.encryption, cfg.compression, cfg.durableHandles)
	log.Printf("[*] allow_guest=%t  allow_anonymous=%t", cfg.allowGuest, cfg.allowAnon)
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

	if err := srv.ListenAndServe(cfg.listen); err != nil && !errors.Is(err, server.ErrServerClosed) {
		log.Fatalf("[!] server error: %v", err)
	}
}
