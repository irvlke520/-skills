#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mem_tools.py - Windows process memory inspection toolkit.

Zero third-party dependencies (ctypes + stdlib only).
Every mutating operation writes a backup before touching the target.

Usage:
  python mem_tools.py ps
  python mem_tools.py modules --pid 1234 [--filter game]
  python mem_tools.py read   --pid 1234 --addr 0x7FF6A1B2C3D4 --type i32
  python mem_tools.py read   --pid 1234 --addr 0x... --type f32x3
  python mem_tools.py write  --pid 1234 --addr 0x... --hex "90 90" [--backup]
  python mem_tools.py scan   --pid 1234 --module game.exe --pattern "48 8B ?? ?? A1"
  python mem_tools.py chain  --pid 1234 --base 0x7FF6A1B20000+0x1A2B3C --offsets "0x20,0x8,0x14"
  python mem_tools.py dump   --pid 1234 --addr 0x... --size 4096 --out region.bin
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_ALL = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

MAX_PATH = 260


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * MAX_PATH),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def _err(msg):
    print("[!] %s (GetLastError=%d)" % (msg, ctypes.get_last_error()))
    return None


def enable_debug_privilege():
    """Best-effort SeDebugPrivilege escalation. Returns True on success."""

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD), ("Luid", LUID), ("Attributes", wt.DWORD)]

    hproc = kernel32.GetCurrentProcess()
    token = wt.HANDLE()
    if not advapi32.OpenProcessToken(hproc, 0x0020 | 0x0008, ctypes.byref(token)):
        return False
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        kernel32.CloseHandle(token)
        return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Luid = luid
    tp.Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
    ok = advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
    kernel32.CloseHandle(token)
    return bool(ok)


def open_process(pid, write=False):
    access = PROCESS_ALL if write else (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION)
    h = kernel32.OpenProcess(access, False, pid)
    if not h:
        return _err("OpenProcess failed for pid %d" % pid)
    return h


def list_processes():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return _err("CreateToolhelp32Snapshot failed") or []
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    out = []
    ok = kernel32.Process32First(snap, ctypes.byref(entry))
    while ok:
        out.append((entry.th32ProcessID, entry.szExeFile.decode("utf-8", "replace")))
        ok = kernel32.Process32Next(snap, ctypes.byref(entry))
    kernel32.CloseHandle(snap)
    return out


def list_modules(pid):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE:
        return _err("CreateToolhelp32Snapshot(modules) failed for pid %d" % pid) or []
    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    out = []
    ok = kernel32.Module32First(snap, ctypes.byref(entry))
    while ok:
        base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
        out.append((entry.szModule.decode("utf-8", "replace"), base, entry.modBaseSize))
        ok = kernel32.Module32Next(snap, ctypes.byref(entry))
    kernel32.CloseHandle(snap)
    return out


def read_memory(hproc, addr, size):
    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
    if not ok:
        return _err("ReadProcessMemory failed at 0x%X" % addr)
    return bytes(bytearray(buf)[: read.value])


def write_memory(hproc, addr, data):
    size = len(data)
    buf = (ctypes.c_ubyte * size).from_buffer_copy(data)
    written = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(written))
    if not ok:
        return _err("WriteProcessMemory failed at 0x%X" % addr)
    return written.value


def query_region(hproc, addr):
    mbi = MEMORY_BASIC_INFORMATION()
    n = kernel32.VirtualQueryEx(hproc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not n:
        return None
    return mbi


def iter_committed_regions(hproc, module_base=None, module_size=None):
    addr = module_base if module_base else 0
    limit = (module_base + module_size) if module_base else 0x7FFFFFFFFFFF
    seen = 0
    while addr < limit:
        mbi = query_region(hproc, addr)
        if not mbi or not mbi.BaseAddress:
            break
        base = mbi.BaseAddress
        size = mbi.RegionSize
        committed = mbi.State == 0x1000  # MEM_COMMIT
        readable = mbi.Protect in (0x02, 0x04, 0x20, 0x40, 0x08, 0x10, 0x80)
        if committed and readable:
            yield base, size
        addr = base + size
        seen += 1
        if seen > 200000:
            break


def parse_pattern(pattern):
    """'48 8B ?? A1' -> (bytes_mask list, mask list). '??' is a wildcard."""
    tokens = pattern.replace("0x", "").replace(",", " ").split()
    vals, mask = [], []
    for t in tokens:
        t = t.strip()
        if t in ("??", "?", "*"):
            vals.append(0)
            mask.append(False)
        else:
            try:
                vals.append(int(t, 16))
                mask.append(True)
            except ValueError:
                raise SystemExit("bad pattern token: %r" % t)
    return vals, mask


def aob_scan(hproc, pattern, module_base=None, module_size=None, max_hits=200):
    vals, mask = parse_pattern(pattern)
    plen = len(vals)
    if plen == 0:
        raise SystemExit("empty pattern")
    hits = []
    first_idx = next((i for i, m in enumerate(mask) if m), 0)
    for base, size in iter_committed_regions(hproc, module_base, module_size):
        try:
            data = read_memory(hproc, base, size)
        except Exception:
            continue
        if not data:
            continue
        i = 0
        n = len(data)
        while i <= n - plen:
            if data[i + first_idx] == vals[first_idx]:
                matched = True
                for j in range(plen):
                    if mask[j] and data[i + j] != vals[j]:
                        matched = False
                        break
                if matched:
                    hits.append(base + i)
                    if len(hits) >= max_hits:
                        return hits
                    i += 1
                    continue
            i += 1
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


def resolve_addr(expr, modules=None):
    """Accept '0x1234', 'game.exe+0x1A2B3C', 'module+0x10'."""
    expr = expr.strip()
    if "+" in expr:
        name, _, off = expr.partition("+")
        off = int(off.strip(), 0)
        if modules is None:
            raise SystemExit("module expression requires module table")
        for mname, base, _sz in modules:
            if mname.lower() == name.strip().lower():
                return base + off
        raise SystemExit("module not found: %s" % name)
    return int(expr, 0)


def cmd_ps(a):
    rows = list_processes()
    if a.filter:
        rows = [r for r in rows if a.filter.lower() in r[1].lower()]
    print("%-8s %s" % ("PID", "NAME"))
    for pid, name in sorted(rows, key=lambda r: r[0]):
        print("%-8d %s" % (pid, name))
    print("total=%d" % len(rows))
    return 0


def cmd_modules(a):
    rows = list_modules(a.pid)
    if a.filter:
        rows = [r for r in rows if a.filter.lower() in r[0].lower()]
    print("%-32s %-18s %s" % ("MODULE", "BASE", "SIZE"))
    for name, base, size in rows:
        print("%-32s 0x%016X 0x%X" % (name, base, size))
    print("total=%d" % len(rows))
    return 0


def cmd_read(a):
    h = open_process(a.pid)
    if not h:
        return 1
    try:
        mods = list_modules(a.pid)
        addr = resolve_addr(a.addr, mods)
        if a.type == "bytes":
            size = a.size or 64
            data = read_memory(h, addr, size)
            if data:
                print(hexdump(data, addr))
            return 0
        if a.type == "str":
            size = a.size or 128
            data = read_memory(h, addr, size)
            if data:
                txt = data.split(b"\x00", 1)[0]
                print(txt.decode(a.encoding, "replace"))
            return 0
        if a.type in ("f32x3", "vec3"):
            data = read_memory(h, addr, 12)
            if data:
                x, y, z = struct.unpack("<fff", data)
                print("x=%.6f y=%.6f z=%.6f" % (x, y, z))
            return 0
        if a.type in ("f32x4", "vec4"):
            data = read_memory(h, addr, 16)
            if data:
                v = struct.unpack("<ffff", data)
                print(" ".join("%.6f" % f for f in v))
            return 0
        if a.type == "mat4":
            data = read_memory(h, addr, 64)
            if data:
                for r in range(4):
                    print(" ".join("%12.6f" % f for f in struct.unpack_from("<ffff", data, r * 16)))
            return 0
        fmt, size = TYPE_FORMATS[a.type]
        data = read_memory(h, addr, size)
        if data:
            print(struct.unpack(fmt, data)[0])
        return 0
    finally:
        kernel32.CloseHandle(h)


def cmd_write(a):
    h = open_process(a.pid, write=True)
    if not h:
        return 1
    try:
        mods = list_modules(a.pid)
        addr = resolve_addr(a.addr, mods)
        data = bytes.fromhex(a.hex.replace(" ", "").replace("0x", ""))
        if a.backup:
            old = read_memory(h, addr, len(data))
            if old:
                bak = "%s.addr_%X.bak" % (a.out or "patch", addr)
                with open(bak, "wb") as f:
                    f.write(old)
                print("[+] backup of %d bytes -> %s" % (len(old), bak))
        n = write_memory(h, addr, data)
        if n is None:
            return 1
        print("[+] wrote %d bytes at 0x%X" % (n, addr))
        return 0
    finally:
        kernel32.CloseHandle(h)


def cmd_scan(a):
    h = open_process(a.pid)
    if not h:
        return 1
    try:
        base = size = None
        if a.module:
            for name, b, s in list_modules(a.pid):
                if name.lower() == a.module.lower():
                    base, size = b, s
                    break
            if base is None:
                print("[!] module not found: %s" % a.module)
                return 1
            print("[*] scanning %s [0x%X, +0x%X]" % (a.module, base, size))
        hits = aob_scan(h, a.pattern, base, size, a.max)
        print("[*] pattern=%s hits=%d" % (a.pattern, len(hits)))
        mods = list_modules(a.pid)
        for hit in hits:
            rel = ""
            if base:
                rel = "  (%s+0x%X)" % (a.module, hit - base)
            else:
                for name, b, s in mods:
                    if b and b <= hit < b + s:
                        rel = "  (%s+0x%X)" % (name, hit - b)
                        break
            print("0x%016X%s" % (hit, rel))
        return 0
    finally:
        kernel32.CloseHandle(h)


def cmd_chain(a):
    h = open_process(a.pid)
    if not h:
        return 1
    try:
        mods = list_modules(a.pid)
        addr = resolve_addr(a.base, mods)
        print("[0] 0x%016X" % addr)
        offsets = [int(o, 0) for o in a.offsets.replace(";", ",").split(",") if o.strip()]
        for i, off in enumerate(offsets):
            data = read_memory(h, addr, 8)
            if not data:
                return 1
            addr = struct.unpack("<Q", data)[0]
            if addr == 0:
                print("[%d] NULL after +0x%X" % (i + 1, off))
                return 1
            addr += off
            print("[%d] +0x%-8X -> 0x%016X" % (i + 1, off, addr))
        if a.type and a.type != "ptr":
            fmt, size = TYPE_FORMATS[a.type]
            data = read_memory(h, addr, size)
            if data:
                print("value=%s" % struct.unpack(fmt, data)[0])
        return 0
    finally:
        kernel32.CloseHandle(h)


def cmd_dump(a):
    h = open_process(a.pid)
    if not h:
        return 1
    try:
        mods = list_modules(a.pid)
        addr = resolve_addr(a.addr, mods)
        data = read_memory(h, addr, a.size)
        if not data:
            return 1
        out = a.out or ("dump_0x%X.bin" % addr)
        with open(out, "wb") as f:
            f.write(data)
        print("[+] %d bytes -> %s" % (len(data), out))
        return 0
    finally:
        kernel32.CloseHandle(h)


def hexdump(data, base=0):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join("%02X" % b for b in chunk)
        ascii_s = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%016X  %-47s  %s" % (base + i, hexs, ascii_s))
    return "\n".join(lines)


def build_parser():
    p = argparse.ArgumentParser(description="Windows process memory inspection toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("ps", help="list processes")
    s.add_argument("--filter", "-f")
    s.set_defaults(fn=cmd_ps)

    s = sub.add_parser("modules", help="list modules of a process")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--filter", "-f")
    s.set_defaults(fn=cmd_modules)

    s = sub.add_parser("read", help="read memory")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--addr", required=True, help="0x... or module.exe+0x...")
    s.add_argument(
        "--type",
        default="i32",
        choices=sorted(list(TYPE_FORMATS.keys()) + ["bytes", "str", "f32x3", "vec3", "f32x4", "vec4", "mat4"]),
    )
    s.add_argument("--size", type=int, default=0)
    s.add_argument("--encoding", default="utf-8")
    s.set_defaults(fn=cmd_read)

    s = sub.add_parser("write", help="write memory")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--addr", required=True)
    s.add_argument("--hex", required=True, help='bytes as hex, e.g. "90 90"')
    s.add_argument("--backup", action="store_true")
    s.add_argument("--out", help="backup filename prefix")
    s.set_defaults(fn=cmd_write)

    s = sub.add_parser("scan", help="array-of-bytes scan")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--pattern", required=True, help='e.g. "48 8B ?? ?? A1"')
    s.add_argument("--module", help="restrict to module name, e.g. game.exe")
    s.add_argument("--max", type=int, default=200)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("chain", help="resolve multi-level pointer chain")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--base", required=True, help="0x... or module.exe+0x...")
    s.add_argument("--offsets", required=True, help='e.g. "0x20,0x8,0x14"')
    s.add_argument("--type", default="ptr")
    s.set_defaults(fn=cmd_chain)

    s = sub.add_parser("dump", help="dump a region to file")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--addr", required=True)
    s.add_argument("--size", type=int, required=True)
    s.add_argument("--out")
    s.set_defaults(fn=cmd_dump)
    return p


def main(argv=None):
    if os.name != "nt":
        print("[!] mem_tools requires Windows")
        return 1
    enable_debug_privilege()
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
