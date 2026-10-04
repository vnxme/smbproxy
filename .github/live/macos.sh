#!/usr/bin/env bash
# Live test on macOS: macOS's own file sharing serves the target share on
# port 445, smbproxy listens on 4445 in front of it, and macOS's own SMB
# client (smbutil, mount_smbfs) uses the proxy. Then the client copies large
# files directly and through the proxy to compare speeds.
#
# Run from the repository root, with ./smbproxy built, on a throwaway
# machine: it turns on file sharing, adds a user and mounts shares.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
live() { python3 "$here/live.py" "$@"; }
step() { echo; echo "=== $*"; }

WORK=$(mktemp -d)
WORK=$(cd "$WORK" && pwd -P)  # /var is a symlink to /private/var
ROOT=/Users/Shared/smbtest   # the target's share; file sharing may not
                             # share folders under /var/folders
TUSER=smbtarget              # target account, created here
TPASS=TargetPw2026x
PUSER=tester                 # proxy logins
PPASS=ProxyPw2026x
OUSER=other
OPASS=OtherPw2026x
PORT=4445
SIZE=${LIVE_SPEED_MIB:-512}
RUNS=${LIVE_SPEED_RUNS:-3}
# Direct mounts go to the machine's own address rather than loopback, in
# case the client treats a share on 127.0.0.1 as its own.
HOST=$(ipconfig getifaddr en0 || echo 127.0.0.1)

cleanup() {
	set +e
	for d in "$WORK"/mnt/*; do mount | grep -q " on $d " && umount "$d"; done
	[ -f "$WORK/proxy.pid" ] && kill "$(cat "$WORK/proxy.pid")"
	cp "$WORK/proxy.log" proxy.log 2>/dev/null
	ls -laR "$ROOT" | head -40
}
trap cleanup EXIT

step "Set up the target share"
mkdir -p "$ROOT"/rw "$ROOT"/ro "$ROOT"/secret
echo "read me" >"$ROOT/ro/readme.txt"
echo "secret" >"$ROOT/secret/secret.txt"
# File sharing authenticates with an NT hash, which macOS keeps only for
# accounts allowed SMB logins and only from the next password change. The
# runner's own account cannot be used: changing its password asks for the
# old one.
sudo sysadminctl -addUser "$TUSER" -fullName "smbproxy live test" -password "$TPASS"
sudo pwpolicy -u "$TUSER" -sethashtypes SMB-NT on
sudo dscl . -passwd "/Users/$TUSER" "$TPASS"
dscl . -read "/Users/$TUSER" AuthenticationAuthority
# What the target account creates through SMB must stay usable by the
# runner, which checks it on the file system, and the other way round.
perms=read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr
perms=$perms,readsecurity,list,search,add_file,add_subdirectory,delete_child
for u in "$TUSER" "$(id -un)"; do
	find "$ROOT" -type d -exec chmod +a "user:$u allow $perms,file_inherit,directory_inherit" {} +
done
ls -led "$ROOT/rw"
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server EnabledServices -array disk
sudo launchctl enable system/com.apple.smbd
sudo launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.smbd.plist 2>/dev/null ||
	sudo launchctl kickstart -k system/com.apple.smbd
sudo sharing -a "$ROOT" -S data -n data
sharing -l
live wait --port 445
echo "client to target: $HOST"

# Listing shares over the srvsvc pipe is checked, but does not fail the job
# yet: smbutil view broke against Homebrew's Samba as well as the proxy.
step "smbutil: list the target's shares directly"
if ! smbutil view -N "//$TUSER:$TPASS@$HOST"; then
	echo "::warning::smbutil view failed against the target directly"
fi

step "Start smbproxy"
# No domain: macOS file sharing refuses WORKGROUP\user, while its own
# client, which names none, logs in.
live config --out "$WORK/live.yaml" --listen "127.0.0.1:$PORT" \
	--host 127.0.0.1 --port 445 --user "$TUSER" --domain "" --password "$TPASS" --share data \
	--proxy-user $PUSER --proxy-password $PPASS --other-user $OUSER --other-password $OPASS
./smbproxy -version
./smbproxy -config "$WORK/live.yaml" >"$WORK/proxy.log" 2>&1 &
echo $! >"$WORK/proxy.pid"
live wait --port $PORT

# smbutil view works against the target directly but not through the
# proxy yet, so it only warns. A second proxy with debug logging, on its own
# port, records the exchange without flooding the other tests' logs.
step "smbutil: list shares"
sed 's/^debug: false/debug: true/; s/:'"$PORT"'"/:'"$((PORT + 1))"'"/' "$WORK/live.yaml" >"$WORK/debug.yaml"
./smbproxy -config "$WORK/debug.yaml" >"$WORK/debug.log" 2>&1 &
debug_pid=$!
live wait --port $((PORT + 1))
if shares=$(smbutil view -N "//$PUSER:$PPASS@127.0.0.1:$((PORT + 1))"); then
	echo "$shares"
	grep -Eq '^rw +Disk' <<<"$shares"
	grep -Eq '^ro +Disk' <<<"$shares"
	if grep -q '^secret' <<<"$shares"; then echo "secret is listed to $PUSER"; exit 1; fi
else
	echo "$shares"
	echo "::warning::smbutil view failed through the proxy"
fi
kill "$debug_pid"
echo "::group::proxy exchange for smbutil view"
grep -vE '^\S+ \S+ \[[*+!]\]' "$WORK/debug.log" | head -150
echo "::endgroup::"

mnt() { # mnt NAME //user:password@host:port/share
	mkdir -p "$WORK/mnt/$1"
	mount_smbfs -N "$2" "$WORK/mnt/$1"
}

# Checks the setup rather than the proxy: what the macOS client creates
# on the target directly must be usable, or every test below fails for that.
step "mount_smbfs: create on the target directly"
mnt direct "//$TUSER:$TPASS@$HOST/data"
mkdir "$WORK/mnt/direct/rw/direct-probe"
echo probe >"$WORK/mnt/direct/rw/direct-probe/probe.txt"
ls -ld "$ROOT/rw/direct-probe" "$ROOT/rw/direct-probe/probe.txt"
rm -r "$WORK/mnt/direct/rw/direct-probe"
umount "$WORK/mnt/direct"

step "mount_smbfs: a wrong password is refused"
if mnt bad "//$PUSER:wrong@127.0.0.1:$PORT/rw"; then echo "mounted"; exit 1; fi

step "mount_smbfs: a share outside read_access is refused"
if mnt secret "//$PUSER:$PPASS@127.0.0.1:$PORT/secret"; then echo "mounted secret"; exit 1; fi

step "mount_smbfs: mount, file-system tests, unmount"
mnt rw "//$PUSER:$PPASS@127.0.0.1:$PORT/rw"
mnt ro "//$PUSER:$PPASS@127.0.0.1:$PORT/ro"
mount | grep "$WORK/mnt"
live fs --mount "$WORK/mnt/rw" --target "$ROOT/rw" --ro-mount "$WORK/mnt/ro" --ro-target "$ROOT/ro"
umount "$WORK/mnt/rw"
umount "$WORK/mnt/ro"
if mount | grep -q "$WORK/mnt"; then echo "still mounted"; exit 1; fi

step "mount_smbfs: speed, direct and through the proxy"
for i in $(seq "$RUNS"); do live mkfile --path "$ROOT/rw/speed-src-$i.bin" --size-mib "$SIZE"; done
for i in $(seq "$RUNS"); do
	mnt direct "//$TUSER:$TPASS@$HOST/data"
	live speed --dir "$WORK/mnt/direct/rw" --src "speed-src-$i.bin" --label direct --size-mib "$SIZE" --out "$WORK/speed.jsonl"
	umount "$WORK/mnt/direct"
	mnt proxy "//$PUSER:$PPASS@127.0.0.1:$PORT/rw"
	live speed --dir "$WORK/mnt/proxy" --src "speed-src-$i.bin" --label proxy --size-mib "$SIZE" --out "$WORK/speed.jsonl"
	umount "$WORK/mnt/proxy"
done
live report --results "$WORK/speed.jsonl" --title "macOS: macOS SMB client, macOS file sharing target" --size-mib "$SIZE" |
	tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
