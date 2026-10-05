#!/usr/bin/env bash
# Live test on Linux: Samba serves the target share on port 445, smbproxy
# listens on 4445 in front of it, and both smbclient and the kernel's CIFS
# client use the proxy. Then the kernel client copies large files directly
# and through the proxy to compare speeds.
#
# Run from the repository root, with ./smbproxy built, on a throwaway
# machine: it installs packages, adds a Samba user and mounts shares.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
live() { python3 "$here/live.py" "$@"; }
step() { echo; echo "=== $*"; }

ROOT=/srv/smbtest            # the target's share
WORK=$(mktemp -d)
TUSER=$(id -un)              # target account: the runner's own user
TPASS=TargetPw2026x
PUSER=tester                 # proxy logins
PPASS=ProxyPw2026x
OUSER=other
OPASS=OtherPw2026x
PORT=4445
SIZE=${LIVE_SPEED_MIB:-512}
RUNS=${LIVE_SPEED_RUNS:-3}
ids="uid=$(id -u),gid=$(id -g)"

cleanup() {
	set +e
	for d in "$WORK"/mnt/*; do mountpoint -q "$d" && sudo umount "$d"; done
	[ -f "$WORK/proxy.pid" ] && kill "$(cat "$WORK/proxy.pid")"
	cp "$WORK/proxy.log" proxy.log 2>/dev/null
}
trap cleanup EXIT

step "Install Samba and the CIFS client"
sudo apt-get update -q
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q samba smbclient cifs-utils
if ! sudo modprobe cifs; then
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)"
	sudo modprobe cifs
fi

step "Set up the target share"
sudo mkdir -p "$ROOT"/rw "$ROOT"/ro "$ROOT"/secret
echo "read me" | sudo tee "$ROOT/ro/readme.txt" >/dev/null
echo "secret" | sudo tee "$ROOT/secret/secret.txt" >/dev/null
sudo chown -R "$TUSER:" "$ROOT"
sudo tee -a /etc/samba/smb.conf >/dev/null <<EOF

[data]
   path = $ROOT
   read only = no
   valid users = $TUSER
EOF
printf '%s\n%s\n' "$TPASS" "$TPASS" | sudo smbpasswd -a -s "$TUSER"
sudo systemctl restart smbd
live wait --port 445

step "Start smbproxy"
live config --out "$WORK/live.yaml" --listen "127.0.0.1:$PORT" \
	--host 127.0.0.1 --port 445 --user "$TUSER" --domain WORKGROUP --password "$TPASS" --share data \
	--proxy-user $PUSER --proxy-password $PPASS --other-user $OUSER --other-password $OPASS
./smbproxy -version
./smbproxy -config "$WORK/live.yaml" >"$WORK/proxy.log" 2>&1 &
echo $! >"$WORK/proxy.pid"
live wait --port $PORT

proxy=(-p $PORT -U "$PUSER%$PPASS")

step "smbclient: list shares"
shares=$(smbclient -g -L //127.0.0.1 "${proxy[@]}")
echo "$shares"
grep -q '^Disk|rw|' <<<"$shares"
grep -q '^Disk|ro|' <<<"$shares"
if grep -q '|secret|' <<<"$shares"; then echo "secret is listed to $PUSER"; exit 1; fi

step "smbclient: a wrong password is refused"
if smbclient -L //127.0.0.1 -p $PORT -U "$PUSER%wrong" -g; then echo "logged in"; exit 1; fi

step "smbclient: a share outside read_access is refused"
if smbclient //127.0.0.1/secret "${proxy[@]}" -c ls; then echo "opened secret"; exit 1; fi
smbclient //127.0.0.1/secret -p $PORT -U "$OUSER%$OPASS" -c ls

step "smbclient: put, rename, get and delete"
head -c 3000000 /dev/urandom >"$WORK/put.bin"
smbclient //127.0.0.1/rw "${proxy[@]}" -c "mkdir sc; cd sc; put $WORK/put.bin a.bin; rename a.bin b.bin"
cmp "$WORK/put.bin" "$ROOT/rw/sc/b.bin"
smbclient //127.0.0.1/rw "${proxy[@]}" -c "cd sc; get b.bin $WORK/got.bin; del b.bin; cd ..; rmdir sc"
cmp "$WORK/put.bin" "$WORK/got.bin"
test ! -e "$ROOT/rw/sc"

mnt() { # mnt NAME //host/share port user password [options]
	mkdir -p "$WORK/mnt/$1"
	sudo mount -t cifs "$2" "$WORK/mnt/$1" -o "port=$3,username=$4,password=$5,$ids${6:+,$6}"
}

step "Kernel client: a wrong password is refused"
mkdir -p "$WORK/mnt/bad"
if sudo mount -t cifs //127.0.0.1/rw "$WORK/mnt/bad" -o "port=$PORT,username=$PUSER,password=wrong,$ids"; then
	echo "mounted"; exit 1
fi

step "Kernel client: mount, file-system tests, unmount"
mnt rw //127.0.0.1/rw $PORT $PUSER $PPASS
mnt ro //127.0.0.1/ro $PORT $PUSER $PPASS
mount | grep "$WORK/mnt"
live fs --mount "$WORK/mnt/rw" --target "$ROOT/rw" --ro-mount "$WORK/mnt/ro" --ro-target "$ROOT/ro"
sudo umount "$WORK/mnt/rw" "$WORK/mnt/ro"
if mount | grep -q "$WORK/mnt"; then echo "still mounted"; exit 1; fi

step "Kernel client: speed, direct and through the proxy"
for i in $(seq "$RUNS"); do live mkfile --path "$ROOT/rw/speed-src-$i.bin" --size-mib "$SIZE"; done
for i in $(seq "$RUNS"); do
	mnt direct //127.0.0.1/data 445 "$TUSER" "$TPASS"
	live speed --dir "$WORK/mnt/direct/rw" --src "speed-src-$i.bin" --label direct --size-mib "$SIZE" --out "$WORK/speed.jsonl"
	sudo umount "$WORK/mnt/direct"
	mnt proxy //127.0.0.1/rw $PORT $PUSER $PPASS
	live speed --dir "$WORK/mnt/proxy" --src "speed-src-$i.bin" --label proxy --size-mib "$SIZE" --out "$WORK/speed.jsonl"
	sudo umount "$WORK/mnt/proxy"
done

step "Kernel client: small files, direct and through the proxy"
mnt direct //127.0.0.1/data 445 "$TUSER" "$TPASS"
live bench-dir --dir "$WORK/mnt/direct/rw" --label direct --out "$WORK/dir.jsonl"
sudo umount "$WORK/mnt/direct"
mnt proxy //127.0.0.1/rw $PORT $PUSER $PPASS
live bench-dir --dir "$WORK/mnt/proxy" --label proxy --out "$WORK/dir.jsonl"
sudo umount "$WORK/mnt/proxy"

live report --results "$WORK/speed.jsonl" --dir-results "$WORK/dir.jsonl" \
	--title "Linux: kernel CIFS client, Samba target" --size-mib "$SIZE" |
	tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
