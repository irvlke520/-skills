#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re_tools.py - offline binary structure analysis. PE/ELF parsing, strings, entropy, AOB scan, patching.

Zero third-party dependencies. Every write operation produces a backup first.

Usage:
  python re_tools.py identify  <file>
  python re_tools.py sections  <file>
  python re_tools.py imports   <file> [--filter ws2]
  python re_tools.py exports   <file>
  python re_tools.py strings   <file> [--min 6] [--utf16]
  python re_tools.py entropy   <file> [--block 4096]
  python re_tools.py scan      <file> --pattern "48 8B ?? ?? A1"
  python re_tools.py disasm    <file> --addr 0x140001000 --len 64 [--tool r2]
  python re_tools.py patch     <file> --offset 0x1234 --hex "90 90" [--out out.bin]
  python re_tools.py hash      <file>
"""

import argparse
import hashlib
import math
import os
import shutil
import struct
import subprocess
import sys

MACHINE = {
    0x014C: "x86 (i386)",
    0x8664: "x86-64 (AMD64)",
    0x01C0: "ARM",
    0x01C4: "ARMNT (Thumb-2)",
    0xAA64: "ARM64",
    0x0200: "IA64",
    0x0EBC: "EFI bytecode",
}

SUBSYSTEM = {
    0: "unknown",
    1: "native",
    2: "GUI",
    3: "CUI (console)",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "WinCE GUI",
    10: "EFI application",
    14: "XBOX",
    16: "boot service driver",
}

MAGIC = [
    (b"MZ", "PE/DOS executable"),
    (b"\x7fELF", "ELF"),
    (b"\xfe\xed\xfa\xce", "Mach-O (32-bit BE)"),
    (b"\xce\xfa\xed\xfe", "Mach-O (32-bit LE)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (64-bit BE)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O (64-bit LE)"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
    (b"PK\x03\x04", "ZIP / JAR / APK / DOCX"),
    (b"dex\n035\x00", "Dalvik DEX"),
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
]


class PE:
    """Minimal PE32 / PE32+ reader."""

    def __init__(self, data):
        self.data = data
        self.is_pe = False
        self.is64 = False
        self.sections = []
        self.entry = 0
        self.image_base = 0
        self.machine = 0
        self.subsystem = 0
        self.data_dirs = []
        self._parse()

    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _u64(self, off):
        return struct.unpack_from("<Q", self.data, off)[0]

    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            return
        e_lfanew = self._u32(0x3C)
        if e_lfanew + 24 > len(d) or d[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return
        self.is_pe = True
        coff = e_lfanew + 4
        self.machine = self._u16(coff)
        nsections = self._u16(coff + 2)
        size_opt = self._u16(coff + 16)
        opt = coff + 20
        magic = self._u16(opt)
        self.is64 = magic == 0x20B
        dd_off = 112 if self.is64 else 96
        nrva_off = 108 if self.is64 else 92
        self.entry = self._u32(opt + 16)
        self.image_base = self._u64(opt + 24) if self.is64 else self._u32(opt + 28)
        self.subsystem = self._u16(opt + 68)
        n_dirs = self._u32(opt + nrva_off)
        base_dd = opt + dd_off
        for i in range(min(n_dirs, 16)):
            rva = self._u32(base_dd + i * 8)
            size = self._u32(base_dd + i * 8 + 4)
            self.data_dirs.append((rva, size))
        sec_off = opt + size_opt
        for i in range(nsections):
            s = sec_off + i * 40
            if s + 40 > len(d):
                break
            name = d[s : s + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize = self._u32(s + 8)
            vaddr = self._u32(s + 12)
            rawsize = self._u32(s + 16)
            rawptr = self._u32(s + 20)
            chars = self._u32(s + 36)
            self.sections.append(
                {
                    "name": name,
                    "vaddr": vaddr,
                    "vsize": vsize,
                    "rawptr": rawptr,
                    "rawsize": rawsize,
                    "chars": chars,
                }
            )

    def rva_to_off(self, rva):
        for s in self.sections:
            span = max(s["vsize"], s["rawsize"])
            if s["vaddr"] <= rva < s["vaddr"] + span:
                off = s["rawptr"] + (rva - s["vaddr"])
                if off < len(self.data):
                    return off
                return None
        if rva < self.sections[0]["rawsize"] if self.sections else False:
            return rva
        return None

    def cstring(self, off, limit=256):
        end = self.data.find(b"\x00", off, min(off + limit, len(self.data)))
        if end < 0:
            end = min(off + limit, len(self.data))
        return self.data[off:end].decode("ascii", "replace")

    def imports(self):
        if len(self.data_dirs) < 2:
            return []
        rva, size = self.data_dirs[1]
        if not rva:
            return []
        off = self.rva_to_off(rva)
        if off is None:
            return []
        out = []
        tsz = 8 if self.is64 else 4
        for i in range(512):
            desc = off + i * 20
            if desc + 20 > len(self.data):
                break
            oft = self._u32(desc)
            name_rva = self._u32(desc + 12)
            ft = self._u32(desc + 16)
            if not name_rva and not oft and not ft:
                break
            noff = self.rva_to_off(name_rva)
            if noff is None:
                continue
            dll = self.cstring(noff)
            thunk_rva = oft or ft
            toff = self.rva_to_off(thunk_rva)
            funcs = []
            if toff is not None:
                for j in range(4096):
                    t = toff + j * tsz
                    if t + tsz > len(self.data):
                        break
                    val = self._u64(t) if self.is64 else self._u32(t)
                    if not val:
                        break
                    if self.is64 and (val >> 63):
                        funcs.append(("ordinal", val & 0xFFFF))
                        continue
                    if not self.is64 and (val & 0x80000000):
                        funcs.append(("ordinal", val & 0xFFFF))
                        continue
                    hnoff = self.rva_to_off(val)
                    if hnoff is None:
                        continue
                    funcs.append(("name", self.cstring(hnoff + 2)))
            out.append((dll, funcs))
        return out

    def exports(self):
        if not self.data_dirs:
            return []
        rva, size = self.data_dirs[0]
        if not rva:
            return []
        off = self.rva_to_off(rva)
        if off is None:
            return []
        n_funcs = self._u32(off + 20)
        n_names = self._u32(off + 24)
        addr_funcs = self._u32(off + 28)
        addr_names = self._u32(off + 32)
        addr_ords = self._u32(off + 36)
        base = self._u32(off + 16)
        afo = self.rva_to_off(addr_funcs)
        ano = self.rva_to_off(addr_names)
        aoo = self.rva_to_off(addr_ords)
        if afo is None or ano is None:
            return []
        out = []
        for i in range(min(n_names, 4096)):
            nrva = self._u32(ano + i * 4)
            noff = self.rva_to_off(nrva)
            ord_idx = self._u16(aoo + i * 2) if aoo is not None else i
            frva = self._u32(afo + ord_idx * 4)
            name = self.cstring(noff) if noff is not None else "?"
            out.append((name, base + ord_idx, self.image_base + frva))
        return out


def shannon(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


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


def scan_bytes(data, pattern, max_hits=200):
    vals, mask = parse_pattern(pattern)
    plen = len(vals)
    if not plen:
        raise SystemExit("empty pattern")
    hits = []
    first = next((i for i, m in enumerate(mask) if m), 0)
    n = len(data)
    for i in range(0, n - plen + 1):
        if data[i + first] == vals[first]:
            if all((not mask[j]) or data[i + j] == vals[j] for j in range(plen)):
                hits.append(i)
                if len(hits) >= max_hits:
                    break
    return hits


def find_external(tool):
    return shutil.which(tool)


def cmd_identify(a):
    p = a.file
    data = open(p, "rb").read()
    kind = "unknown"
    for magic, name in MAGIC:
        if data.startswith(magic):
            kind = name
            break
    print("file     : %s" % p)
    print("size     : %d bytes" % len(data))
    print("type     : %s" % kind)
    print("md5      : %s" % hashlib.md5(data).hexdigest())
    print("sha256   : %s" % hashlib.sha256(data).hexdigest())
    pe = PE(data)
    if pe.is_pe:
        print("format   : PE%s" % ("32+" if pe.is64 else "32"))
        print("machine  : %s (0x%X)" % (MACHINE.get(pe.machine, "?"), pe.machine))
        print("subsystem: %s" % SUBSYSTEM.get(pe.subsystem, "?"))
        print("imagebase: 0x%X" % pe.image_base)
        print("entry    : 0x%X (RVA)" % pe.entry)
        print("sections : %d" % len(pe.sections))
    return 0


def cmd_sections(a):
    data = open(a.file, "rb").read()
    pe = PE(data)
    if not pe.is_pe:
        print("[!] not a PE image")
        return 1
    print("%-10s %-10s %-10s %-10s %-10s %s" % ("NAME", "VADDR", "VSIZE", "RAWPTR", "RAWSIZE", "CHARS"))
    for s in pe.sections:
        print(
            "%-10s 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X"
            % (s["name"], s["vaddr"], s["vsize"], s["rawptr"], s["rawsize"], s["chars"])
        )
    print("[*] entropy per section:")
    for s in pe.sections:
        chunk = data[s["rawptr"] : s["rawptr"] + s["rawsize"]]
        print("    %-10s %.3f" % (s["name"], shannon(chunk)))
    return 0


def cmd_imports(a):
    data = open(a.file, "rb").read()
    pe = PE(data)
    if not pe.is_pe:
        print("[!] not a PE image")
        return 1
    total = 0
    for dll, funcs in pe.imports():
        if a.filter and a.filter.lower() not in dll.lower():
            funcs_f = [f for f in funcs if a.filter.lower() in str(f[1]).lower()]
            if not funcs_f:
                continue
            funcs = funcs_f
        print("%s" % dll)
        for kind, name in funcs:
            print("    %-8s %s" % (kind, name))
            total += 1
    print("[*] total symbols=%d" % total)
    return 0


def cmd_exports(a):
    data = open(a.file, "rb").read()
    pe = PE(data)
    if not pe.is_pe:
        print("[!] not a PE image")
        return 1
    print("%-10s %-40s %s" % ("ORDINAL", "NAME", "RVA/VA"))
    for name, ordinal, va in pe.exports():
        print("%-10d %-40s 0x%X" % (ordinal, name, va))
    print("[*] total=%d" % len(pe.exports()))
    return 0


def cmd_strings(a):
    data = open(a.file, "rb").read()
    out = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= a.min:
                out.append((start, cur.decode("ascii", "replace")))
            cur = bytearray()
    if len(cur) >= a.min:
        out.append((start, cur.decode("ascii", "replace")))
    if a.utf16:
        cur = bytearray()
        start = 0
        i = 0
        while i + 1 < len(data):
            b0, b1 = data[i], data[i + 1]
            if 32 <= b0 < 127 and b1 == 0:
                if not cur:
                    start = i
                cur.append(b0)
                i += 2
                continue
            if len(cur) >= a.min:
                out.append((start, cur.decode("ascii", "replace")))
            cur = bytearray()
            i += 1
    out.sort(key=lambda t: t[0])
    for off, s in out:
        if a.filter and a.filter.lower() not in s.lower():
            continue
        print("%08X  %s" % (off, s))
    print("[*] total=%d" % len(out))
    return 0


def cmd_entropy(a):
    data = open(a.file, "rb").read()
    print("overall  : %.4f" % shannon(data))
    print("%-12s %-12s %s" % ("OFFSET", "ENTROPY", "BAR"))
    for off in range(0, len(data), a.block):
        chunk = data[off : off + a.block]
        e = shannon(chunk)
        bar = "#" * int(e * 5)
        print("0x%08X    %.4f       %s" % (off, e, bar))
    return 0


def cmd_scan(a):
    data = open(a.file, "rb").read()
    hits = scan_bytes(data, a.pattern, a.max)
    print("[*] pattern=%s hits=%d" % (a.pattern, len(hits)))
    pe = PE(data)
    for h in hits:
        extra = ""
        if pe.is_pe:
            for s in pe.sections:
                if s["rawptr"] <= h < s["rawptr"] + s["rawsize"]:
                    extra = "  %s+0x%X (RVA 0x%X)" % (s["name"], h - s["rawptr"], s["vaddr"] + (h - s["rawptr"]))
                    break
        print("0x%08X%s" % (h, extra))
    return 0


def cmd_disasm(a):
    if not a.tool or a.tool == "auto":
        for t in ("r2", "radare2", "objdump", "dumpbin", "ndisasm"):
            if find_external(t):
                a.tool = t
                break
    exe = find_external(a.tool) if a.tool != "auto" else None
    if a.tool == "r2" or a.tool == "radare2":
        if not exe:
            print("[!] radare2 not found on PATH")
            return 1
        cmd = [exe, "-q", "-c", "pd %d @ 0x%X" % (a.len, a.addr), "-N", a.file]
    elif a.tool == "objdump":
        if not exe:
            print("[!] objdump not found on PATH")
            return 1
        cmd = [exe, "-d", "--start-address=0x%X" % a.addr, "--stop-address=0x%X" % (a.addr + a.len), a.file]
    elif a.tool == "ndisasm":
        if not exe:
            print("[!] ndisasm not found on PATH")
            return 1
        cmd = [exe, "-o", "0x%X" % a.addr, a.file]
    else:
        print("[!] unsupported disassembler: %s" % a.tool)
        print("[i] install one of: radare2 (r2), binutils (objdump), nasm (ndisasm)")
        return 1
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout[-20000:] if len(r.stdout) > 20000 else r.stdout)
    if r.stderr:
        print(r.stderr[-4000:], file=sys.stderr)
    return 0


def cmd_patch(a):
    p = a.file
    data = bytearray(open(p, "rb").read())
    raw = bytes.fromhex(a.hex.replace(" ", "").replace("0x", ""))
    off = int(a.offset, 0)
    if off + len(raw) > len(data):
        print("[!] patch exceeds file size")
        return 1
    old = bytes(data[off : off + len(raw)])
    print("[*] offset 0x%X  old=%s  new=%s" % (off, old.hex(" ").upper(), raw.hex(" ").upper()))
    if a.dry:
        print("[*] dry-run, nothing written")
        return 0
    bak = a.out or (p + ".bak")
    if os.path.abspath(bak) == os.path.abspath(p):
        bak = p + ".bak"
    shutil.copy2(p, bak)
    print("[+] backup -> %s" % bak)
    data[off : off + len(raw)] = raw
    with open(p, "wb") as f:
        f.write(data)
    print("[+] patched %d bytes at 0x%X" % (len(raw), off))
    return 0


def cmd_hash(a):
    data = open(a.file, "rb").read()
    for algo in ("md5", "sha1", "sha256"):
        h = hashlib.new(algo)
        h.update(data)
        print("%-8s %s" % (algo, h.hexdigest()))
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="offline binary structure analysis")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("identify")
    s.add_argument("file")
    s.set_defaults(fn=cmd_identify)

    s = sub.add_parser("sections")
    s.add_argument("file")
    s.set_defaults(fn=cmd_sections)

    s = sub.add_parser("imports")
    s.add_argument("file")
    s.add_argument("--filter")
    s.set_defaults(fn=cmd_imports)

    s = sub.add_parser("exports")
    s.add_argument("file")
    s.set_defaults(fn=cmd_exports)

    s = sub.add_parser("strings")
    s.add_argument("file")
    s.add_argument("--min", type=int, default=6)
    s.add_argument("--utf16", action="store_true")
    s.add_argument("--filter")
    s.set_defaults(fn=cmd_strings)

    s = sub.add_parser("entropy")
    s.add_argument("file")
    s.add_argument("--block", type=int, default=4096)
    s.set_defaults(fn=cmd_entropy)

    s = sub.add_parser("scan")
    s.add_argument("file")
    s.add_argument("--pattern", required=True)
    s.add_argument("--max", type=int, default=200)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("disasm")
    s.add_argument("file")
    s.add_argument("--addr", default="0x0")
    s.add_argument("--len", type=int, default=64)
    s.add_argument("--tool", default="auto")
    s.set_defaults(fn=cmd_disasm)

    s = sub.add_parser("patch")
    s.add_argument("file")
    s.add_argument("--offset", required=True)
    s.add_argument("--hex", required=True)
    s.add_argument("--out", help="backup path (default: <file>.bak)")
    s.add_argument("--dry", action="store_true")
    s.set_defaults(fn=cmd_patch)

    s = sub.add_parser("hash")
    s.add_argument("file")
    s.set_defaults(fn=cmd_hash)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
