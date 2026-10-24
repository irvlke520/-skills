#!/usr/bin/env python3
"""AOB（字节特征码）扫描器。

两种模式：
  1. 扫文件：  python aob_scan.py --file game.exe "48 8B 05 ?? ?? ?? ?? 48 85 C0"
  2. 扫进程：  python aob_scan.py --pid 1234 --module game.exe "48 8B 05 ?? ?? ?? ??"
                （Windows，走 ReadProcessMemory；模块基址自动解析）

通配符用 ? 或 ?? 表示"该字节会变"（地址、立即数、跳转偏移）。

用法补充：
  --all        列出全部命中而不是只列第一个
  --base 0x...  手动指定扫描起始地址（进程模式）
  --size N      手动指定扫描长度（进程模式，默认扫整个模块）
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import sys


def parse_pattern(pattern: str):
    """把 '48 8B 05 ?? ?? ?? ?? 48' 解析成 (pat_bytes, mask_bytes)。

    mask 中 0xFF 表示必须匹配，0x00 表示忽略（通配符）。
    """
    toks = pattern.replace("0x", "").split()
    pat, mask = bytearray(), bytearray()
    for t in toks:
        if t in ("?", "??", "*", "**"):
            pat.append(0x00)
            mask.append(0x00)
        else:
            try:
                pat.append(int(t, 16))
            except ValueError:
                sys.exit("无法解析的字节: %r" % t)
            mask.append(0xFF)
    if not pat:
        sys.exit("空特征码")
    return bytes(pat), bytes(mask)


def scan(data: bytes, pat: bytes, mask: bytes, find_all: bool = False):
    """在 data 里找特征码，返回命中的偏移列表。"""
    n = len(pat)
    hits = []
    # 先把必须匹配的第一个字节拿出来做快速跳过
    first_idx = next((i for i, m in enumerate(mask) if m), 0)
    fb = pat[first_idx]
    i = 0
    end = len(data) - n
    while i <= end:
        if data[i + first_idx] != fb:
            i += 1
            continue
        ok = True
        for j in range(n):
            if mask[j] and data[i + j] != pat[j]:
                ok = False
                break
        if ok:
            hits.append(i)
            if not find_all:
                return hits
            i += 1
        else:
            i += 1
    return hits


class MODULEINFO(ctypes.Structure):
    """ctypes.wintypes 里没有这个，必须自己定义（注意 64 位下指针 8 字节对齐）。"""
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", ctypes.c_uint32),
                ("EntryPoint", ctypes.c_void_p)]


def read_process_module(pid: int, module: str = None, base: int = 0, size: int = 0):
    """读目标进程的某个模块映像（Windows）。返回 (base, data)。"""
    k = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    h = k.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        sys.exit("OpenProcess 失败 (pid=%d)，权限不足或进程不存在" % pid)

    # 枚举模块找基址与大小
    if module and not base:
        mods = (ctypes.c_void_p * 1024)()
        needed = ctypes.c_ulong()
        if not psapi.EnumProcessModulesEx(h, ctypes.byref(mods), ctypes.sizeof(mods),
                                          ctypes.byref(needed), 0x03):
            sys.exit("EnumProcessModules 失败")
        cnt = needed.value // ctypes.sizeof(ctypes.c_void_p)
        name_buf = ctypes.create_unicode_buffer(260)
        for i in range(cnt):
            psapi.GetModuleBaseNameW(h, ctypes.c_void_p(mods[i]), name_buf, 260)
            if name_buf.value.lower() == module.lower():
                info = MODULEINFO()
                psapi.GetModuleInformation(h, ctypes.c_void_p(mods[i]),
                                           ctypes.byref(info), ctypes.sizeof(info))
                base = info.lpBaseOfDll
                size = info.SizeOfImage
                break
        if not base:
            sys.exit("进程里找不到模块: %s" % module)

    if not size:
        sys.exit("需要 --size 或 --module 来确定扫描长度")

    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(read))
    k.CloseHandle(h)
    if not ok:
        sys.exit("ReadProcessMemory 失败 (已读 %d 字节)" % read.value)
    return base, buf.raw[: read.value]


def main():
    ap = argparse.ArgumentParser(description="AOB 字节特征码扫描器")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", help="扫描本地文件")
    g.add_argument("--pid", type=int, help="扫描进程（配合 --module 或 --base/--size）")
    ap.add_argument("--module", help="进程模式：模块名，如 game.exe")
    ap.add_argument("--base", help="进程模式：起始地址（十六进制）")
    ap.add_argument("--size", type=int, help="进程模式：扫描长度")
    ap.add_argument("--all", action="store_true", help="列出全部命中")
    ap.add_argument("pattern", help='特征码，如 "48 8B 05 ?? ?? ?? ?? 48 85 C0"')
    args = ap.parse_args()

    pat, mask = parse_pattern(args.pattern)
    print("特征码: %d 字节, 通配符 %d 个" % (len(pat), mask.count(0)))

    if args.file:
        if not os.path.exists(args.file):
            sys.exit("文件不存在: %s" % args.file)
        with open(args.file, "rb") as f:
            data = f.read()
        base = 0
        print("文件: %s (%d 字节)" % (args.file, len(data)))
    else:
        base = int(args.base, 16) if args.base else 0
        base, data = read_process_module(args.pid, args.module, base, args.size or 0)
        print("进程: pid=%d  基址=0x%X  长度=%d" % (args.pid, base, len(data)))

    hits = scan(data, pat, mask, args.all)
    if not hits:
        print("未命中")
        return 1

    print("命中 %d 处:" % len(hits))
    for off in hits[:50]:
        ctx = data[off: off + min(len(pat) + 8, 24)]
        print("  偏移 0x%X  绝对地址 0x%X  字节: %s"
              % (off, base + off, " ".join("%02X" % b for b in ctx)))
    if len(hits) > 50:
        print("  ...还有 %d 处未列出" % (len(hits) - 50))
    return 0


if __name__ == "__main__":
    sys.exit(main())
