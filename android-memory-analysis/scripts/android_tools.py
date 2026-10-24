#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
android_tools.py - Android process memory analysis over adb.

Designed for kernel-assisted workflows: works against a rooted device using
/proc/<pid>/mem, and exposes hooks for a custom kernel driver endpoint.

Usage:
  python android_tools.py devices
  python android_tools.py info
  python android_tools.py ps                 [--filter game]
  python android_tools.py maps     --pid 1234 [--filter libgame]
  python android_tools.py read     --pid 1234 --addr libgame.so+0x1A2B3C --type f32
  python android_tools.py write    --pid 1234 --addr 0x7f8a001234 --hex "90 90" [--backup]
  python android_tools.py scan     --pid 1234 --module libgame.so --pattern "48 8B ?? ?? A1"
  python android_tools.py chain    --pid 1234 --base libgame.so+0x1A2B3C --offsets "0x20,0x8,0x14"
  python android_tools.py kallsyms --filter sys_call_table
  python android_tools.py selinux  [--set permissive]
  python android_tools.py module   --list | --load /sdcard/drv.ko | --unload drv
  python android_tools.py dump     --pid 1234 --addr 0x... --size 4096 --out region.bin
"""

import argparse
import base64
import os
import re
import struct
import subprocess
import sys

ADB = "adb"


class ADBError(Exception):
    pass


def adb(args, device=None, timeout=60, raw=False):
    cmd = [ADB]
    if device:
        cmd += ["-s", device]
    cmd += ["shell"] + args
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise ADBError("adb not found on PATH")
    except subprocess.TimeoutExpired:
        raise ADBError("adb command timed out: %s" % " ".join(args))
    if r.returncode != 0 and not raw:
        err = r.stderr.decode("utf-8", "replace").strip()
        if err:
            raise ADBError(err)
    return r.stdout


def adb_text(args, device=None, timeout=60):
    return adb(args, device, timeout).decode("utf-8", "replace")


def require_adb():
    try:
        out = subprocess.run([ADB, "devices"], capture_output=True, timeout=30).stdout.decode()
    except FileNotFoundError:
        print("[!] adb not found on PATH")
        return False
    lines = [l for l in out.splitlines()[1:] if l.strip().endswith("\tdevice")]
    if not lines:
        print("[!] no adb device in state 'device'")
        print("[i] check: adb devices ; adb kill-server && adb start-server")
        return False
    return True


def get_pid(a):
    if a.pid:
        return a.pid
    if not a.proc:
        raise SystemExit("--pid or --proc required")
    out = adb_text(["ps", "-A", "-o", "PID,NAME"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == a.proc:
            return int(parts[0])
        if len(parts) >= 2 and a.proc.lower() in parts[1].lower():
            return int(parts[0])
    raise SystemExit("process not found: %s" % a.proc)


MAP_RE = re.compile(
    r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)\s+([0-9a-fA-F]+)\s+(\S+)\s+(\d+)\s*(.*)$"
)


def read_maps(pid, device=None):
    out = adb_text(["cat", "/proc/%d/maps" % pid])
    regions = []
    for line in out.splitlines():
        m = MAP_RE.match(line.strip())
        if not m:
            continue
        start, end, perms, off, dev, inode, path = m.groups()
        regions.append(
            {
                "start": int(start, 16),
                "end": int(end, 16),
                "perms": perms,
                "offset": int(off, 16),
                "inode": int(inode),
                "path": path.strip(),
            }
        )
    return regions


def resolve_addr(expr, pid, device=None):
    """Accept '0x7f8a001234' or 'libgame.so+0x1A2B3C'."""
    expr = expr.strip()
    if "+" in expr:
        name, _, off_s = expr.partition("+")
        off = int(off_s.strip(), 0)
        for r in read_maps(pid, device):
            if r["path"] and os.path.basename(r["path"]) == name.strip():
                return r["start"] + off
        for r in read_maps(pid, device):
            if r["path"] and name.strip() in r["path"]:
                return r["start"] + off
        raise SystemExit("module not found in maps: %s" % name)
    return int(expr, 0)


def mem_read(pid, addr, size, device=None, chunk=1 << 20):
    """Read process memory via /proc/<pid>/mem. Returns bytes (may be short)."""
    out = b""
    remaining = size
    cur = addr
    while remaining > 0:
        n = min(chunk, remaining)
        b64 = adb(
            [
                "tail",
                "-c",
                "+%d" % (cur + 1),
                "/proc/%d/mem" % pid,
                "2>/dev/null",
                "|",
                "head",
                "-c",
                str(n),
                "|",
                "base64",
            ],
            device,
            raw=True,
        )
        try:
            out += base64.b64decode(b64)
        except Exception:
            break
        got = len(base64.b64decode(b64)) if b64 else 0
        if got == 0:
            break
        cur += n
        remaining -= n
    return out


def mem_write(pid, addr, data, device=None):
    b64 = base64.b64encode(data).decode()
    res = adb_text(
        [
            "echo",
            "'%s'" % b64,
            "|",
            "base64",
            "-d",
            "|",
            "dd",
            "of=/proc/%d/mem" % pid,
            "bs=1",
            "seek=%d" % addr,
            "conv=notrunc",
            "2>&1",
        ],
        device,
    )
    return res.strip()


def ptr_size(pid=None, device=None):
    abi = adb_text(["getprop", "ro.product.cpu.abi"])
    return 8 if "64" in abi else 4


def hexdump(data, base=0):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join("%02X" % b for b in chunk)
        ascii_s = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%016X  %-47s  %s" % (base + i, hexs, ascii_s))
    return "\n".join(lines)


def parse_pattern(pattern):
    tokens = pattern.replace("0x", "").replace(",", " ").split()
    vals, mask = [], []
    for t in tokens:
        t = t.strip()
        if t in ("??", "?", "*"):
            vals.append(0)
            mask.append(False)
        else:
            vals.append(int(t, 16))
            mask.append(True)
    return vals, mask


def scan_bytes(data, pattern, base=0, max_hits=200):
    vals, mask = parse_pattern(pattern)
    plen = len(vals)
    if not plen:
        raise SystemExit("empty pattern")
    hits = []
    first = next((i for i, m in enumerate(mask) if m), 0)
    for i in range(0, len(data) - plen + 1):
        if data[i + first] == vals[first]:
            if all((not mask[j]) or data[i + j] == vals[j] for j in range(plen)):
                hits.append(base + i)
                if len(hits) >= max_hits:
                    break
    return hits


TYPE_FORMATS = {
    "i8": ("<b", 1),
    "u8": ("<B", 1),
    "i16": ("<h", 2),
    "u16": ("<H", 2),
    "i32": ("<i", 4),
    "u32": ("<I", 4),
    "i64": ("<q", 8),
    "u64": ("<Q", 8),
    "ptr": ("<Q", 8),
    "f32": ("<f", 4),
    "f64": ("<d", 8),
}


def cmd_devices(a):
    out = subprocess.run([ADB, "devices", "-l"], capture_output=True).stdout.decode()
    print(out.strip())
    return 0


def cmd_info(a):
    fields = [
        ("ro.product.model", "model"),
        ("ro.product.cpu.abi", "abi"),
        ("ro.build.version.release", "android"),
        ("ro.build.version.sdk", "sdk"),
        ("ro.build.fingerprint", "build"),
        ("ro.build.type", "buildtype"),
        ("ro.debuggable", "debuggable"),
        ("ro.secure", "secure"),
    ]
    for prop, label in fields:
        v = adb_text(["getprop", prop]).strip()
        print("%-12s %s" % (label, v))
    print("%-12s %s" % ("kernel", adb_text(["uname", "-r"]).strip()))
    print("%-12s %s" % ("selinux", adb_text(["getenforce"]).strip()))
    print("%-12s %s" % ("id", adb_text(["id"]).strip()))
    su = adb_text(["which", "su"]).strip()
    print("%-12s %s" % ("su", su if su else "not present"))
    return 0


def cmd_ps(a):
    out = adb_text(["ps", "-A", "-o", "PID,NAME"])
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            rows.append((int(parts[0]), parts[1]))
        except ValueError:
            continue
    if a.filter:
        rows = [r for r in rows if a.filter.lower() in r[1].lower()]
    print("%-8s %s" % ("PID", "NAME"))
    for pid, name in sorted(rows):
        print("%-8d %s" % (pid, name))
    print("total=%d" % len(rows))
    return 0


def cmd_maps(a):
    pid = get_pid(a)
    regions = read_maps(pid, a.device)
    print("%-18s %-18s %-6s %-10s %s" % ("START", "END", "PERMS", "SIZE", "PATH"))
    for r in regions:
        if a.filter and a.filter.lower() not in r["path"].lower():
            continue
        print(
            "0x%016X 0x%016X %-6s 0x%08X  %s"
            % (r["start"], r["end"], r["perms"], r["end"] - r["start"], r["path"])
        )
    print("[*] pid=%d regions=%d" % (pid, len(regions)))
    return 0


def cmd_read(a):
    pid = get_pid(a)
    addr = resolve_addr(a.addr, pid, a.device)
    if a.type == "bytes":
        data = mem_read(pid, addr, a.size or 64, a.device)
        print(hexdump(data, addr) if data else "[!] read returned nothing")
        return 0
    if a.type == "str":
        data = mem_read(pid, addr, a.size or 128, a.device)
        print(data.split(b"\x00", 1)[0].decode("utf-8", "replace") if data else "[!] empty")
        return 0
    if a.type in ("f32x3", "vec3"):
        data = mem_read(pid, addr, 12, a.device)
        if len(data) == 12:
            print("x=%.6f y=%.6f z=%.6f" % struct.unpack("<fff", data))
        return 0
    if a.type == "mat4":
        data = mem_read(pid, addr, 64, a.device)
        if len(data) == 64:
            for r in range(4):
                print(" ".join("%12.6f" % f for f in struct.unpack_from("<ffff", data, r * 16)))
        return 0
    fmt, size = TYPE_FORMATS[a.type]
    data = mem_read(pid, addr, size, a.device)
    if len(data) >= size:
        print(struct.unpack(fmt, data[:size])[0])
    else:
        print("[!] short read: %d/%d bytes" % (len(data), size))
    return 0


def cmd_write(a):
    pid = get_pid(a)
    addr = resolve_addr(a.addr, pid, a.device)
    data = bytes.fromhex(a.hex.replace(" ", "").replace("0x", ""))
    if a.backup:
        old = mem_read(pid, addr, len(data), a.device)
        if old:
            bak = a.out or ("patch_0x%X.bak" % addr)
            with open(bak, "wb") as f:
                f.write(old)
            print("[+] backup %d bytes -> %s" % (len(old), bak))
    print(mem_write(pid, addr, data, a.device))
    return 0


def cmd_scan(a):
    pid = get_pid(a)
    regions = read_maps(pid, a.device)
    targets = []
    for r in regions:
        if not r["perms"].startswith("r"):
            continue
        if a.module:
            if r["path"] and a.module in r["path"]:
                targets.append(r)
        elif r["path"]:
            targets.append(r)
    if not targets:
        print("[!] no readable region matched")
        return 1
    hits = []
    print("[*] scanning %d regions in pid %d" % (len(targets), pid))
    for r in targets:
        size = min(r["end"] - r["start"], a.max_region)
        data = mem_read(pid, r["start"], size, a.device)
        if not data:
            continue
        for h in scan_bytes(data, a.pattern, r["start"], a.max):
            rel = ""
            if r["path"]:
                rel = "  (%s+0x%X)" % (os.path.basename(r["path"]), h - r["start"])
            hits.append((h, rel, r["path"]))
            print("0x%016X%s" % (h, rel))
            if len(hits) >= a.max:
                break
        if len(hits) >= a.max:
            break
    print("[*] hits=%d" % len(hits))
    return 0


def cmd_chain(a):
    pid = get_pid(a)
    addr = resolve_addr(a.base, pid, a.device)
    psz = ptr_size(pid, a.device)
    fmt = "<Q" if psz == 8 else "<I"
    print("[0] 0x%016X" % addr)
    for i, off_s in enumerate(a.offsets.replace(";", ",").split(",")):
        off = int(off_s.strip(), 0)
        data = mem_read(pid, addr, psz, a.device)
        if len(data) < psz:
            print("[!] short read at step %d" % i)
            return 1
        addr = struct.unpack(fmt, data[:psz])[0]
        if addr == 0:
            print("[%d] NULL after +0x%X" % (i + 1, off))
            return 1
        addr += off
        print("[%d] +0x%-8X -> 0x%016X" % (i + 1, off, addr))
    if a.type and a.type != "ptr":
        fmt2, size = TYPE_FORMATS[a.type]
        data = mem_read(pid, addr, size, a.device)
        if len(data) >= size:
            print("value=%s" % struct.unpack(fmt2, data[:size])[0])
    return 0


def cmd_kallsyms(a):
    out = adb_text(["cat", "/proc/kallsyms"])
    n = 0
    for line in out.splitlines():
        if a.filter and a.filter not in line:
            continue
        print(line)
        n += 1
        if n >= a.limit:
            break
    print("[*] lines=%d" % n)
    return 0


def cmd_selinux(a):
    if a.set:
        print(adb_text(["setenforce", a.set]).strip() or "ok (needs root)")
    print("mode=%s" % adb_text(["getenforce"]).strip())
    return 0


def cmd_module(a):
    if a.list:
        print(adb_text(["lsmod"]).strip())
        return 0
    if a.load:
        print(adb_text(["insmod", a.load]).strip() or "loaded (silent)")
        print(adb_text(["lsmod"]).strip())
        return 0
    if a.unload:
        print(adb_text(["rmmod", a.unload]).strip() or "unloaded (silent)")
        return 0
    print("[!] use --list / --load / --unload")
    return 1


def cmd_dump(a):
    pid = get_pid(a)
    addr = resolve_addr(a.addr, pid, a.device)
    data = mem_read(pid, addr, a.size, a.device)
    if not data:
        print("[!] nothing read")
        return 1
    out = a.out or ("dump_0x%X.bin" % addr)
    with open(out, "wb") as f:
        f.write(data)
    print("[+] %d bytes -> %s" % (len(data), out))
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="Android process memory analysis over adb")
    p.add_argument("--device", "-s", help="adb device serial")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("devices")
    s.set_defaults(fn=cmd_devices)

    s = sub.add_parser("info")
    s.set_defaults(fn=cmd_info)

    s = sub.add_parser("ps")
    s.add_argument("--filter", "-f")
    s.set_defaults(fn=cmd_ps)

    s = sub.add_parser("maps")
    s.add_argument("--pid", type=int)
    s.add_argument("--proc")
    s.add_argument("--filter", "-f")
    s.set_defaults(fn=cmd_maps)

    s = sub.add_parser("read")
    s.add_argument("--pid", type=int)
    s.add_argument("--proc")
    s.add_argument("--addr", required=True)
    s.add_argument(
        "--type",
        default="i32",
        choices=sorted(list(TYPE_FORMATS.keys()) + ["bytes", "str", "f32x3", "vec3", "mat4"]),
    )
    s.add_argument("--size", type=int, default=0)
    s.set_defaults(fn=cmd_read)

    s = sub.add_parser("write")
    s.add_argument("--pid", type=int)
    s.add_argument("--proc")
    s.add_argument("--addr", required=True)
    s.add_argument("--hex", required=True)
    s.add_argument("--backup", action="store_true")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_write)

    s = sub.add_parser("scan")
    s.add_argument("--pid", type=int)
    s.add_argument("--proc")
    s.add_argument("--pattern", required=True)
    s.add_argument("--module")
    s.add_argument("--max", type=int, default=200)
    s.add_argument("--max-region", type=int, default=8 << 20)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("chain")
    s.add_argument("--pid", type=int)
    s.add_argument("--proc")
    s.add_argument("--base", required=True)
    s.add_argument("--offsets", required=True)
    s.add_argument("--type", default="ptr")
    s.set_defaults(fn=cmd_chain)

    s = sub.add_parser("kallsyms")
    s.add_argument("--filter")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_kallsyms)

    s = sub.add_parser("selinux")
    s.add_argument("--set", choices=["permissive", "enforcing"])
    s.set_defaults(fn=cmd_selinux)

    s = sub.add_parser("module")
    s.add_argument("--list", action="store_true")
    s.add_argument("--load")
    s.add_argument("--unload")
    s.set_defaults(fn=cmd_module)

    s = sub.add_parser("dump")
    s.add_argument("--pid", type=int)
    s.add_argument("--proc")
    s.add_argument("--addr", required=True)
    s.add_argument("--size", type=int, required=True)
    s.add_argument("--out")
    s.set_defaults(fn=cmd_dump)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd != "devices" and not require_adb():
        return 1
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
