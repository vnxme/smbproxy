#!/usr/bin/env bash
# Live test on macOS: Samba from Homebrew serves the target share on port
# 1445 (macOS keeps 445 for its own file sharing), smbproxy listens on 4445
# in front of it, and macOS's own SMB client (smbutil, mount_smbfs) uses
# the proxy. Then the client copies large files directly and through the
# proxy to compare speeds.
#
# Run from the repository root, with ./smbproxy built, on a throwaway
# machine: it installs packages, runs smbd as root and mounts shares.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
live() { python3 "$here/live.py" "$@"; }
step() { echo; echo "=== $*"; }

WORK=$(mktemp -d)
WORK=$(cd "$WORK" && pwd -P)  # /var is a symlink to /private/var
ROOT=$WORK/share             # the target's share
TUSER=$(id -un)              # target account: the runner's own user
TPASS=TargetPw2026x
TPORT=1445
PUSER=tester                 # proxy logins
PPASS=ProxyPw2026x
OUSER=other
OPASS=OtherPw2026x
PORT=4445
SIZE=${LIVE_SPEED_MIB:-512}
RUNS=${LIVE_SPEED_RUNS:-3}

cleanup() {
	set +e
	for d in "$WORK"/mnt/*; do mount | grep -q " on $d " && umount "$d"; done
	[ -f "$WORK/proxy.pid" ] && kill "$(cat "$WORK/proxy.pid")"
	[ -f "$WORK/samba/run/smbd.pid" ] && sudo kill "$(cat "$WORK/samba/run/smbd.pid")"
	cp "$WORK/proxy.log" proxy.log 2>/dev/null
	sudo cat "$WORK"/samba/log/* >samba.log 2>/dev/null
}
trap cleanup EXIT

step "Install Samba"
brew install samba
prefix=$(brew --prefix samba)
# Homebrew may rename smbd so it does not shadow the system's.
smbd=$(find "$prefix/" -type f \( -name smbd -o -name samba-dot-org-smbd \) -perm -u+x | head -1)
smbpasswd=$(find "$prefix/" -type f -name smbpasswd -perm -u+x | head -1)
echo "smbd: $smbd"
echo "smbpasswd: $smbpasswd"

step "Set up the target share"
mkdir -p "$ROOT"/rw "$ROOT"/ro "$ROOT"/secret "$WORK"/samba/{private,lock,state,cache,run,log}
echo "read me" >"$ROOT/ro/readme.txt"
echo "secret" >"$ROOT/secret/secret.txt"
conf=$WORK/samba/smb.conf
cat >"$conf" <<EOF
[global]
   server role = standalone server
   workgroup = WORKGROUP
   smb ports = $TPORT
   disable netbios = yes
   server min protocol = SMB2_10
   map to guest = never
   passdb backend = tdbsam:$WORK/samba/private/passdb.tdb
   private dir = $WORK/samba/private
   lock directory = $WORK/samba/lock
   state directory = $WORK/samba/state
   cache directory = $WORK/samba/cache
   pid directory = $WORK/samba/run
   log file = $WORK/samba/log/log.%m
   fruit:aapl = no

[data]
   path = $ROOT
   read only = no
   valid users = $TUSER
EOF
printf '%s\n%s\n' "$TPASS" "$TPASS" | sudo "$smbpasswd" -c "$conf" -a -s "$TUSER"
sudo "$smbd" -D -s "$conf"
live wait --port $TPORT

step "smbutil: list the target's shares directly"
smbutil view -N "//$TUSER:$TPASS@127.0.0.1:$TPORT"

step "Start smbproxy"
live config --out "$WORK/live.yaml" --listen "127.0.0.1:$PORT" \
	--host 127.0.0.1 --port $TPORT --user "$TUSER" --domain WORKGROUP --password "$TPASS" --share data \
	--proxy-user $PUSER --proxy-password $PPASS --other-user $OUSER --other-password $OPASS --debug
./smbproxy -version
./smbproxy -config "$WORK/live.yaml" >"$WORK/proxy.log" 2>&1 &
echo $! >"$WORK/proxy.pid"
live wait --port $PORT

step "smbutil: list shares"
shares=$(smbutil view -N "//$PUSER:$PPASS@127.0.0.1:$PORT")
echo "$shares"
grep -Eq '^rw +Disk' <<<"$shares"
grep -Eq '^ro +Disk' <<<"$shares"
if grep -q '^secret' <<<"$shares"; then echo "secret is listed to $PUSER"; exit 1; fi

mnt() { # mnt NAME //user:password@host:port/share
	mkdir -p "$WORK/mnt/$1"
	mount_smbfs -N "$2" "$WORK/mnt/$1"
}

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
	mnt direct "//$TUSER:$TPASS@127.0.0.1:$TPORT/data"
	live speed --dir "$WORK/mnt/direct/rw" --src "speed-src-$i.bin" --label direct --size-mib "$SIZE" --out "$WORK/speed.jsonl"
	umount "$WORK/mnt/direct"
	mnt proxy "//$PUSER:$PPASS@127.0.0.1:$PORT/rw"
	live speed --dir "$WORK/mnt/proxy" --src "speed-src-$i.bin" --label proxy --size-mib "$SIZE" --out "$WORK/speed.jsonl"
	umount "$WORK/mnt/proxy"
done
live report --results "$WORK/speed.jsonl" --title "macOS: macOS SMB client, Samba target" --size-mib "$SIZE" |
	tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
