#!/usr/bin/env python3
"""Helpers for the live tests (.github/workflows/live.yml).

Each OS script sets up a target share, starts smbproxy in front of it and
mounts the proxy's shares with the OS's own SMB client; this file holds the
parts that are the same everywhere:

  config   write the proxy's configuration
  wait     wait for a TCP port to accept connections
  fs       file-system tests on a mounted share, checked on the target side
  speed    time writing and reading a large file on a mounted share
  report   summarize the speed results as a Markdown table

Python is on every GitHub-hosted runner, and its file API is the same over a
Linux, macOS or Windows mount, so the tests are written once.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import statistics
import sys
import threading
import time

CHUNK = 4 << 20  # 4 MiB


# ---- config ----

def cmd_config(a):
    def q(s):
        return json.dumps(s)  # a JSON string is a valid YAML scalar

    cfg = f"""\
server:
  listen: {q(a.listen)}
  netbios_name: SMBPROXY
  signing: enabled
  encryption: supported
  hide_inaccessible_shares: true
debug: {str(a.debug).lower()}
local:
  users:
    {a.proxy_user}:
      password: {q(a.proxy_password)}
    {a.other_user}:
      password: {q(a.other_password)}
targets:
  live:
    host: {q(a.host)}
    port: {a.port}
    user: {q(a.user)}
    domain: {q(a.domain)}
    password: {q(a.password)}
shares:
  - name: rw
    target: live
    path: {a.share}/rw
    read_only: false
    read_access: [{a.proxy_user}]
    write_access: [{a.proxy_user}]
  - name: ro
    target: live
    path: {a.share}/ro
    read_access: [{a.proxy_user}]
  - name: secret
    target: live
    path: {a.share}/secret
    read_access: [{a.other_user}]
"""
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(cfg)


# ---- wait ----

def cmd_wait(a):
    deadline = time.monotonic() + a.timeout
    while True:
        try:
            with socket.create_connection((a.host, a.port), timeout=1):
                return
        except OSError as e:
            if time.monotonic() > deadline:
                sys.exit(f"{a.host}:{a.port} not accepting connections after {a.timeout}s: {e}")
            time.sleep(0.2)


# ---- fs ----

class Checks:
    def __init__(self):
        self.failed = 0

    def run(self, name, fn):
        start = time.monotonic()
        try:
            fn()
        except Exception as e:  # report every test, then fail at the end
            self.failed += 1
            print(f"FAIL  {name}: {type(e).__name__}: {e}", flush=True)
        else:
            print(f"ok    {name} ({time.monotonic() - start:.2f}s)", flush=True)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(CHUNK):
            h.update(b)
    return h.hexdigest()


def read(path):
    with open(path, "rb") as f:
        return f.read()


def write(path, data, mode="wb"):
    with open(path, mode) as f:
        f.write(data)


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


def expect_raises(exc, fn, what):
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"{what}: no {exc.__name__ if isinstance(exc, type) else exc}")


def cmd_fs(a):
    """Changes made through the mount must show on the target and the other
    way round. a.mount is the proxied share as the client sees it, a.target
    the same folder on the target's own file system."""
    c = Checks()
    work = f"live-{os.getpid()}"
    M = os.path.join(a.mount, work)
    T = os.path.join(a.target, work)
    m = lambda *p: os.path.join(M, *p)  # noqa: E731
    t = lambda *p: os.path.join(T, *p)  # noqa: E731

    def mkdir():
        os.mkdir(M)
        expect(os.path.isdir(T), "folder missing on target")
        os.makedirs(m("a", "b", "c"))
        expect(os.path.isdir(t("a", "b", "c")), "nested folders missing on target")

    c.run("create folders", mkdir)

    def empty():
        os.mkdir(m("empty"))
        expect(os.listdir(m("empty")) == [], f"listing {os.listdir(m('empty'))}")
        os.rmdir(m("empty"))
        expect(not os.path.exists(t("empty")), "folder still on target")

    c.run("list and remove an empty folder", empty)

    def small():
        write(m("hello.txt"), b"hello, proxy\n")
        expect(read(t("hello.txt")) == b"hello, proxy\n", "content differs on target")
        expect(read(m("hello.txt")) == b"hello, proxy\n", "content differs read back")
        expect(os.path.getsize(m("hello.txt")) == 13, "size differs")

    c.run("write and read a small file", small)

    # Sizes around the proxy's 8 MiB read-ahead batch, and an empty file.
    for size in (0, 1, 4095, 65543, (8 << 20) - 1, (8 << 20) + 3, 21 << 20):
        def sized(size=size):
            data = os.urandom(size)
            name = f"size-{size}.bin"
            write(m(name), data)
            expect(os.path.getsize(t(name)) == size, f"target size {os.path.getsize(t(name))}")
            expect(sha(t(name)) == hashlib.sha256(data).hexdigest(), "content differs on target")
            expect(read(m(name)) == data, "content differs read back")

        c.run(f"write and read {size} bytes", sized)

    def from_target():
        data = os.urandom(13 << 20)
        write(t("from-target.bin"), data)
        expect(read(m("from-target.bin")) == data, "content differs")
        expect(sorted(os.listdir(m("a"))) == ["b"], "listing differs")

    c.run("read a file written on the target", from_target)

    def ranged():
        data = bytearray(os.urandom(3 << 20))
        write(m("ranged.bin"), bytes(data))
        with open(m("ranged.bin"), "r+b") as f:
            for off in (0, 4096, 1 << 20, (3 << 20) - 10):
                f.seek(off)
                patch = os.urandom(10)
                f.write(patch)
                data[off:off + 10] = patch
            f.seek(1 << 20)
            expect(f.read(10) == bytes(data[1 << 20:(1 << 20) + 10]), "ranged read differs")
        expect(read(t("ranged.bin")) == bytes(data), "content differs on target")

    c.run("write and read at offsets", ranged)

    def append():
        write(m("log.txt"), b"one\n")
        write(m("log.txt"), b"two\n", "ab")
        expect(read(t("log.txt")) == b"one\ntwo\n", "append differs on target")

    c.run("append", append)

    def overwrite_shorter():
        write(m("over.txt"), b"a long first version\n")
        write(m("over.txt"), b"short\n")
        expect(read(t("over.txt")) == b"short\n", "overwrite left old bytes on target")

    c.run("overwrite with shorter content", overwrite_shorter)

    def truncate():
        write(m("trunc.bin"), b"x" * 1000)
        os.truncate(m("trunc.bin"), 10)
        expect(os.path.getsize(t("trunc.bin")) == 10, "shrink not on target")
        with open(m("trunc.bin"), "r+b") as f:
            f.truncate(5000)
        expect(read(t("trunc.bin")) == b"x" * 10 + b"\0" * 4990, "grow not zero-filled on target")

    c.run("truncate and extend", truncate)

    def rename():
        write(m("old.txt"), b"rename me")
        os.rename(m("old.txt"), m("new.txt"))
        expect(not os.path.exists(t("old.txt")) and read(t("new.txt")) == b"rename me", "rename not on target")
        os.rename(m("new.txt"), m("a", "b", "moved.txt"))
        expect(read(t("a", "b", "moved.txt")) == b"rename me", "move not on target")
        write(m("replacement.txt"), b"replacement")
        os.replace(m("replacement.txt"), m("a", "b", "moved.txt"))
        expect(read(t("a", "b", "moved.txt")) == b"replacement", "replace not on target")
        os.rename(m("a", "b"), m("a", "renamed"))
        expect(os.path.isfile(t("a", "renamed", "moved.txt")), "folder rename not on target")
        expect(sorted(os.listdir(m("a", "renamed"))) == ["c", "moved.txt"], "renamed folder listing")

    c.run("rename and move files and folders", rename)

    def names():
        name = "файл с пробелом ✓ (1).txt"
        write(m(name), b"unicode")
        expect(read(t(name)) == b"unicode", "unicode name not on target")
        expect(name in os.listdir(M), "unicode name not listed")

    c.run("unicode and spaces in names", names)

    def many():
        os.mkdir(m("many"))
        want = {f"f{i:04d}.txt" for i in range(400)}
        for n in want:
            write(m("many", n), n.encode())
        expect(set(os.listdir(m("many"))) == want, "listing through the proxy differs")
        expect(set(os.listdir(t("many"))) == want, "listing on target differs")

    c.run("list a folder of 400 files", many)

    def mtime():
        write(m("dated.txt"), b"dated")
        when = 981173106  # 2001-02-03 04:05:06 UTC
        os.utime(m("dated.txt"), (when, when))
        expect(abs(os.path.getmtime(t("dated.txt")) - when) < 2, "mtime not on target")
        expect(abs(os.path.getmtime(m("dated.txt")) - when) < 2, "mtime differs read back")

    c.run("set modification time", mtime)

    def parallel():
        blobs = {f"par-{i}.bin": os.urandom(5 << 20) for i in range(6)}
        errs = []

        def put(n, d):
            try:
                write(m(n), d)
                expect(read(m(n)) == d, f"{n} differs read back")
            except Exception as e:
                errs.append(f"{n}: {e}")

        ts = [threading.Thread(target=put, args=kv) for kv in blobs.items()]
        for th in ts:
            th.start()
        for th in ts:
            th.join()
        expect(not errs, "; ".join(errs))
        for n, d in blobs.items():
            expect(sha(t(n)) == hashlib.sha256(d).hexdigest(), f"{n} differs on target")

    c.run("parallel writes and reads", parallel)

    def errors():
        expect_raises(FileNotFoundError, lambda: read(m("missing.txt")), "open a missing file")
        expect_raises(FileExistsError, lambda: os.mkdir(m("a")), "create an existing folder")
        expect_raises(OSError, lambda: os.rmdir(m("a")), "remove a non-empty folder")

    c.run("errors for missing and existing paths", errors)

    def delete():
        os.remove(m("hello.txt"))
        expect(not os.path.exists(t("hello.txt")), "file still on target")
        os.rmdir(m("a", "renamed", "c"))
        expect(not os.path.exists(t("a", "renamed", "c")), "folder still on target")
        shutil.rmtree(M)
        expect(not os.path.exists(T), "tree still on target")

    c.run("delete files and folders", delete)

    if a.ro_mount:
        def read_only():
            expect("readme.txt" in os.listdir(a.ro_mount), "readme.txt not listed")
            expect(read(os.path.join(a.ro_mount, "readme.txt")) == read(os.path.join(a.ro_target, "readme.txt")),
                   "content differs")
            expect_raises(OSError, lambda: write(os.path.join(a.ro_mount, "new.txt"), b"x"), "create a file")
            expect_raises(OSError, lambda: os.remove(os.path.join(a.ro_mount, "readme.txt")), "delete a file")
            expect_raises(OSError, lambda: os.mkdir(os.path.join(a.ro_mount, "dir")), "create a folder")
            expect(sorted(os.listdir(a.ro_target)) == ["readme.txt"], "read-only share changed on target")

        c.run("read-only share refuses changes", read_only)

    if c.failed:
        sys.exit(f"{c.failed} file-system test(s) failed")


# ---- speed ----

def cmd_speed(a):
    """Write a new file and read an existing one, appending the timings to
    a.out. A fresh mount for each run keeps the client's cache out of the
    reads; the target's own cache is warm for both paths alike."""
    size = a.size_mib << 20
    buf = os.urandom(CHUNK)  # random, so compression cannot help
    results = []

    path = os.path.join(a.dir, f"speed-write-{os.getpid()}.bin")
    start = time.perf_counter()
    with open(path, "wb", buffering=0) as f:
        for _ in range(size // CHUNK):
            f.write(buf)
        os.fsync(f.fileno())
    results.append(("write", time.perf_counter() - start))
    os.remove(path)

    src = os.path.join(a.dir, a.src)
    n = 0
    start = time.perf_counter()
    with open(src, "rb", buffering=0) as f:
        while chunk := f.read(CHUNK):
            n += len(chunk)
    results.append(("read", time.perf_counter() - start))
    expect(n == size, f"read {n} bytes of {size}")

    with open(a.out, "a", encoding="utf-8") as f:
        for op, secs in results:
            mibs = a.size_mib / secs
            print(f"{a.label:>6} {op:<5} {a.size_mib} MiB in {secs:.2f}s = {mibs:.0f} MiB/s", flush=True)
            f.write(json.dumps({"label": a.label, "op": op, "mib": a.size_mib, "seconds": secs}) + "\n")


def cmd_mkfile(a):
    """A file of random bytes, written on the target for the read runs."""
    with open(a.path, "wb") as f:
        for _ in range(a.size_mib << 20 >> 22):
            f.write(os.urandom(CHUNK))


def cmd_report(a):
    rates = {}
    with open(a.results, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            rates.setdefault((r["op"], r["label"]), []).append(r["mib"] / r["seconds"])
    runs = max(len(v) for v in rates.values())
    print(f"### {a.title}\n")
    print(f"Median of {runs} runs of {a.size_mib} MiB, in MiB/s, over loopback on one runner.\n")
    print("| | direct | through smbproxy | proxy / direct |")
    print("|---|---:|---:|---:|")
    for op in ("write", "read"):
        d = statistics.median(rates.get((op, "direct"), [0]))
        p = statistics.median(rates.get((op, "proxy"), [0]))
        ratio = f"{p / d:.0%}" if d else "–"
        print(f"| {op} | {d:.0f} | {p:.0f} | {ratio} |")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("config")
    p.add_argument("--out", required=True)
    p.add_argument("--listen", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=445)
    p.add_argument("--user", required=True)
    p.add_argument("--domain", default="")
    p.add_argument("--password", required=True)
    p.add_argument("--share", required=True)
    p.add_argument("--proxy-user", required=True)
    p.add_argument("--proxy-password", required=True)
    p.add_argument("--other-user", required=True)
    p.add_argument("--other-password", required=True)
    p.add_argument("--debug", action="store_true")
    p.set_defaults(fn=cmd_config)

    p = sub.add_parser("wait")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--timeout", type=float, default=30)
    p.set_defaults(fn=cmd_wait)

    p = sub.add_parser("fs")
    p.add_argument("--mount", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--ro-mount")
    p.add_argument("--ro-target")
    p.set_defaults(fn=cmd_fs)

    p = sub.add_parser("mkfile")
    p.add_argument("--path", required=True)
    p.add_argument("--size-mib", type=int, required=True)
    p.set_defaults(fn=cmd_mkfile)

    p = sub.add_parser("speed")
    p.add_argument("--dir", required=True)
    p.add_argument("--src", required=True, help="existing file in --dir to read")
    p.add_argument("--label", required=True, choices=["direct", "proxy"])
    p.add_argument("--size-mib", type=int, required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_speed)

    p = sub.add_parser("report")
    p.add_argument("--results", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--size-mib", type=int, required=True)
    p.set_defaults(fn=cmd_report)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
