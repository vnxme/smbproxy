# smbproxy

smbproxy is an SMB server that gathers shares from remote Windows and Samba
servers, each reached with its own account, and serves them under one host to
SMB clients such as Windows Explorer, which log in to the proxy with logins of
its own.

```
SMB clients  ──local logins──▶  smbproxy  ──each target's account──▶  target servers
(Explorer, net use, …)          \\proxy\share                         \\fs01\Projects, \\nas\media, …
```

It is built on [go-smb](https://github.com/jfjallid/go-smb), which provides
both the SMB server clients talk to and the SMB client the proxy uses to reach
the targets.

## What it is for

- **Aggregation.** Present shares spread across several servers, reached
  under different accounts, as ordinary shares of one host.
- **Indirect access.** Reach a share where a direct connection from the
  client is unwanted or impossible: the proxy ends the client's connection
  and makes its own to the target, so routing, firewalling and dialect or
  signing differences are dealt with once, at the proxy.
- **Credential confinement.** Keep the targets' credentials away from the
  clients. Clients log in to the proxy with separate local logins; the
  targets' credentials stay in the proxy's configuration.

## Features

- **Server:** SMB 2.0.2 to 3.1.1, with signing, encryption, compression and
  durable handles, as go-smb provides them.
- **Targets:** any number, with one connection each, shared by all their
  shares. A connection is made on first use, closed when idle and remade
  after a drop. A share maps to a target's share or to a folder inside it,
  which clients cannot leave.
- **Logins and access control:** local users (a password, a password file or
  an NT hash), groups, and optional guest and anonymous access. Each share
  has its own `read_access` and `write_access` lists, and shares a client
  cannot open can be hidden from its share list.
- **Reading:** directory listings, and file reads with read-ahead.
- **Writing,** for shares configured writable: creating, writing,
  overwriting, renaming, deleting and truncating files and folders, and
  setting timestamps and attributes. Share modes are the clients' own, so
  open files are shared between the proxy's clients as Windows shares them
  between programs.
- **Windows Explorer:** browsing `\\proxy`, the share's Network tab, the
  volume's size and free space, and the Security tab with the target's
  permissions. Well-known SIDs are named; the targets' own accounts too, by
  asking the targets, if `resolve_sids` is on.
- **Debugging:** with `debug: true`, every SMB exchange and file system call
  is logged with its result.

## Limitations

- Byte-range locks are not supported. Applications that lock files, such as
  Microsoft Office, may open documents read-only.
- Permissions can be viewed but not changed.
- Clients get no change notifications, so Explorer does not refresh a folder
  by itself when it changes on the target or through another client.
- Opportunistic locks and leases are not passed through, and Previous
  Versions (snapshots) are not available.
- The proxy logs in to targets with NTLM. Everything clients do on a target
  is done as the target's account: the target's permissions apply to that
  account, and the proxy's `read_access` and `write_access` decide which
  clients may use it.
- It runs on Linux, macOS and Windows, on every architecture Go supports for
  them. The BSDs, Solaris, illumos and AIX are not supported, as go-smb does
  not build there.

## Installing

Prebuilt binaries for Linux, macOS and Windows on many architectures are
attached to each [release](https://github.com/vnxme/smbproxy/releases), with a
`SHA256SUMS` file to check them against.

To build it yourself, smbproxy needs Go 1.27 or later.

```sh
go install github.com/vnxme/smbproxy@latest
```

Or build it from a clone:

```sh
git clone https://github.com/vnxme/smbproxy
cd smbproxy
go build
```

On Windows, `build.ps1` builds binaries for several platforms at once; run
`.\build.ps1 -List` for the platforms it knows.

## Running

```sh
smbproxy -config /etc/smbproxy/smbproxy.yaml
```

Without `-config`, smbproxy reads `smbproxy.yaml` in the current directory.
`smbproxy -version` prints the version and the commit it was built from, which
smbproxy also logs at startup.

Clients connect to port 445, which needs root on Linux and macOS. Rather than
running as root, allow the binary to bind it:

```sh
sudo setcap cap_net_bind_service=+ep "$(command -v smbproxy)"
```

On Windows, port 445 is normally taken by Windows' own file sharing (the
Server service), and Windows clients cannot connect to another port, so run
smbproxy on a host whose port 445 is free.

Then, from a client:

```
\\proxy-host\projects
net use P: \\proxy-host\projects /user:alice
```

## Configuration

All settings are in one YAML file. A misspelled setting is an error, so a
mistake stops smbproxy at startup instead of being ignored.
[`smbproxy.example.yaml`](smbproxy.example.yaml) describes every setting and
its default.

A minimal configuration: one local user, one target and one share.

```yaml
local:
  users:
    alice:
      password_file: alice.pass   # first line: alice's password

targets:
  fs:
    host: fs01.corp.example
    user: svc_proxy
    domain: CORP
    password_file: fs.pass

shares:
  - name: projects                # \\proxy-host\projects
    target: fs
    path: Projects/2026           # the target's share, then a folder in it
```

The configuration's top-level settings:

| Setting           | Holds                                                                                  |
|-------------------|----------------------------------------------------------------------------------------|
| `server`          | how clients reach the proxy: address, dialects, identity, signing, encryption, limits |
| `local`           | the logins clients use: users, groups, guest and anonymous access                      |
| `targets`         | the servers the proxy connects to, each with the account it uses                       |
| `target_timeouts` | how long the proxy waits for targets                                                   |
| `shares`          | what clients see, each share a target's share or a folder in it                        |
| `debug`           | log every SMB exchange and file system call                                            |

A credential, for a local user or a target, is exactly one of `password`,
`password_file` (whose first line is the password, relative to the
configuration file) or `password_hash` (the NT hash, 32 hexadecimal
characters).

### Access control

Shares are read-only unless `read_only: false` is set. Who may open a share
and who may change it are lists of users, `@groups`, and the reserved
`@guests` and `@anonymous`:

```yaml
local:
  users:
    alice: {password_file: alice.pass}
    bob:   {password_file: bob.pass}
  groups:
    finance: [alice, bob]

shares:
  - name: reports
    target: fs
    path: Finance/Reports
    read_only: false
    read_access: ["@finance"]     # who may open it; omitted: every login
    write_access: [alice]         # who may change it, among the readers;
                                  # omitted: every reader
```

## Security

- **Protect the configuration file.** It holds the targets' credentials.
  Keep it readable only by the account running smbproxy; on Linux and macOS,
  smbproxy warns at startup about a configuration holding inline secrets that
  others can read. `password_file` keeps secrets out of the file itself.
- **Targets see only the proxy's account.** Every client acts on a target as
  the account configured for it, so give that account only the rights the
  shares need, and use `read_access` and `write_access` to decide which
  clients use it.
- **Guest and anonymous access are off by default.** Turn them on only for
  shares meant to be public.
- **`resolve_sids` is off by default.** Turned on, it lets clients learn the
  names of the targets' accounts, which the targets would otherwise reveal
  only to their own users.
- **Use it only where you are authorized to.** smbproxy needs valid
  credentials for every target; use it only with servers and accounts you
  own or are allowed to use.

## Development

```sh
golangci-lint run   # lint and format checks, configured in .golangci.yml
go test ./...
go test -race ./...
```

golangci-lint must be v2.14 or newer, built with Go 1.27 or newer, as the
official release binaries are; `golangci-lint fmt` applies the formatting.

Besides unit tests, the integration tests run the real proxy in-process
between go-smb's client and a go-smb server standing in for a target, over
loopback.

## License

smbproxy is licensed under the [Apache License 2.0](LICENSE).
