package main

import (
	"log"

	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcesrv "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// proxy is a configuration put together: the local SMB server clients connect
// to, and the upstream connections behind its shares.
type proxy struct {
	srv       *server.Server
	upstreams map[*target]*upstream // one per target in use
}

// newProxy builds the server for cfg, ready to Serve. No upstream connection
// is dialed here: each connects when a client first touches one of its
// shares, and the idle reaper (see reapUpstreams) closes it again after
// target_timeouts.idle of inactivity. A bad credential or an unreachable
// target is therefore reported on first use (to the client, and in the log),
// not at launch.
func newProxy(cfg *config) *proxy {
	p := &proxy{upstreams: map[*target]*upstream{}}
	for _, sh := range cfg.shares {
		if _, ok := p.upstreams[sh.target]; !ok {
			p.upstreams[sh.target] = newUpstream(sh.target, cfg.timeouts)
		}
	}

	srvCfg := cfg.serverConfig()
	p.srv = &server.Server{Config: srvCfg}

	// ---- Register IPC$ with a no-op VFS ----
	// Without this the server auto-provides IPC$ with VFS=nil, which causes
	// a nil dereference panic in queryFileInfo when Explorer sends QUERY_INFO
	// on a pipe handle (e.g. during the initial IPC$ tree setup).
	p.srv.RegisterShare("IPC$", server.Share{
		Name: "IPC$",
		Type: smb.ShareTypePipe,
		VFS:  &noopVFS{},
	})

	// ---- Register each proxied share ----
	for _, sh := range cfg.shares {
		var vfs server.VFS = &proxyVFS{
			up: p.upstreams[sh.target], share: sh.remoteShare, base: sh.remoteSub,
			canWrite: func(s *server.Session) bool { return sh.canWrite(principalOf(s)) },
		}
		if cfg.debug {
			vfs = &tracingVFS{share: sh.name, inner: vfs}
		}
		// go-smb's write gate on CREATE, WRITE and SET_INFO enforces who may
		// change the share; the tree-connect hook reports each client's
		// actual maximal access over this read-only default.
		writers, guestsWrite, anonymousWrite := sh.libraryWriters()
		p.srv.RegisterShare(sh.name, server.Share{
			Name:              sh.name,
			Type:              smb.ShareTypeDisk,
			Remark:            sh.comment,
			EncryptData:       sh.encrypt,
			VFS:               vfs,
			MaximalAccess:     readOnlyAccess,
			WritableUsers:     writers,
			GuestWritable:     guestsWrite,
			AnonymousWritable: anonymousWrite,
		})
		sub := ""
		if sh.remoteSub != "" {
			sub = "\\" + sh.remoteSub
		}
		write := "no one (read-only)"
		if !sh.readOnly {
			write = sh.writeAccess.String()
			if sh.writeAccess == nil {
				write = "every reader"
			}
		}
		log.Printf("[+] share \\\\<host>\\%s  →  %s\\%s%s  (target %s, as %s; read: %s; write: %s)",
			sh.name, sh.target.addr(), sh.remoteShare, sub, sh.target.name, sh.target.account(), sh.readAccess, write)
	}

	// ---- Wire srvsvc so Explorer can enumerate shares at \\host level ----
	// The library's srvsvc.Service answers NetShareEnumAll (opnum 15), which is
	// all Explorer calls to list shares; srvsvcService adds NetrShareGetInfo
	// (opnum 16), queried when a file is opened in an application, and
	// NetrServerGetInfo (opnum 21), queried by a share's Properties > Network
	// tab. rpcPipe adds the WRITE/READ transport and the BindAck fixup the
	// Windows client needs (see its doc).
	allShares := srvsvc.FromConfig(srvCfg)
	lsa := newLSAService(cfg)
	srvCfg.PipeOpener = &server.MapPipeOpener{
		Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			// Built per open, for the session opening it: with
			// hide_inaccessible_shares, each client is listed only the shares
			// its read_access lets it open.
			"srvsvc": func(s *server.Session) (server.PipeBackend, error) {
				shares := allShares
				if cfg.hideInaccessibleShares {
					shares = cfg.visibleShares(allShares, principalOf(s))
				}
				return &rpcPipe{
					inner: dcesrv.NewPipeHandler("srvsvc", newSrvsvcService(cfg, shares)),
				}, nil
			},
			// lsaService answers the domain-membership queries the same tab
			// makes next (see its doc).
			"lsarpc": func(_ *server.Session) (server.PipeBackend, error) {
				return &rpcPipe{
					inner: dcesrv.NewPipeHandler("lsarpc", lsa),
				}, nil
			},
		},
	}
	return p
}

// close tears down every upstream connection.
func (p *proxy) close() {
	for _, up := range p.upstreams {
		up.close()
	}
}
