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
//   rpcpipe.go   — the DCE/RPC pipe wrapper (srvsvc, lsarpc) and BindAck fixup
//   srvsvc.go    — the srvsvc service: the library's plus share and server info
//   lsarpc.go    — a minimal read-only LSA service: domain membership queries
//   proxy.go     — the local server: shares, upstreams and RPC pipes
//   access.go    — share access control (read_access, write_access)
//   main.go      — startup: configuration, logging, shutdown (this file)

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
		_, _ = fmt.Fprintf(flag.CommandLine.Output(),
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

	p := newProxy(cfg)
	defer p.close()

	// ---- Reap idle upstream connections ----
	if cfg.timeouts.idle > 0 {
		stopReaper := make(chan struct{})
		defer close(stopReaper)
		go reapUpstreams(p.upstreams, cfg.timeouts.idle, stopReaper)
	}

	log.Printf("[*] listening on %s", cfg.listen)
	switch names := cfg.localUserNames(); {
	case len(names) == 0:
		log.Printf("[*] local users: none; guest/anonymous access only")
	case cfg.localDomain != "":
		log.Printf("[*] local users (domain %s): %s", cfg.localDomain, strings.Join(names, ", "))
	default:
		log.Printf("[*] local users (any domain): %s", strings.Join(names, ", "))
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
		_ = p.srv.Shutdown(ctx)
	}()

	if err := p.srv.ListenAndServe(cfg.listen); err != nil && !errors.Is(err, server.ErrServerClosed) {
		log.Fatalf("[!] server error: %v", err)
	}
}
