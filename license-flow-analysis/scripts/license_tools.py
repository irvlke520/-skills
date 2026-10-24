#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
license_tools.py - authorization/activation verification flow analysis.

Locates activation-related code paths in a binary, profiles key formats,
tests candidate checksum schemes, generates candidates for a local verifier,
and diffs two builds to narrow down comparison sites.

Zero third-party dependencies.

Usage:
  python license_tools.py scan     <file> [--min 5]
  python license_tools.py probe    <code>
  python license_tools.py checksum <code>
  python license_tools.py generate --template "XXXXX-XXXXX-XXXXX" --charset base32 --count 10
  python license_tools.py verify   --verifier verifier.py --codes codes.txt
  python license_tools.py bdiff    <fileA> <fileB> [--tolerance 16]
"""

import argparse
import importlib.util
import os
import random
import re
import sys
import zlib

KEYWORD_GROUPS = {
    "activation": [
        r"activat", r"register", r"registr", r"licen[cs]e", r"\bkey\b",
        r"serial", r"product\s*id", r"unlock", r"unlocked", r"activate",
    ],
    "trial": [
        r"trial", r"evaluation", r"demo", r"expire", r"expiry", r"expiration",
        r"days\s*left", r"remaining", r"time\s*left",
    ],
    "verdict": [
        r"invalid", r"valid", r"success", r"failed", r"wrong", r"error",
        r"thank you", r"congrat", r"accepted", r"rejected",
    ],
    "crypto": [
        r"md5", r"sha1", r"sha256", r"sha512", r"rsa", r"aes", r"des",
        r"base64", r"crc32", r"hmac", r"\bhash\b", r"checksum",
    ],
    "binding": [
        r"machine\s*id", r"hardware\s*id", r"hwid", r"mac\s*addr", r"volume",
        r"cpu\s*id", r"bios", r"motherboard", r"fingerprint",
    ],
    "network": [
        r"https?://", r"\bapi\b", r"server", r"online", r"offline",
        r"validate", r"verify", r"auth",
    ],
}

CHARSETS = {
    "base32": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    "crockford": "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
    "hex": "0123456789ABCDEF",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "alnum": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "base64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
}


def extract_strings(data, min_len=5, utf16=True):
    out = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append((start, cur.decode("ascii", "replace")))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append((start, cur.decode("ascii", "replace")))
    if utf16:
        cur = bytearray()
        start = 0
        i = 0
        n = len(data)
        while i + 1 < n:
            b0, b1 = data[i], data[i + 1]
            if 32 <= b0 < 127 and b1 == 0:
                if not cur:
                    start = i
                cur.append(b0)
                i += 2
                continue
            if len(cur) >= min_len:
                out.append((start, cur.decode("ascii", "replace")))
            cur = bytearray()
            i += 1
        if len(cur) >= min_len:
            out.append((start, cur.decode("ascii", "replace")))
    out.sort(key=lambda t: t[0])
    return out


def cmd_scan(a):
    data = open(a.file, "rb").read()
    strs = extract_strings(data, a.min, True)
    compiled = {g: [re.compile(p, re.I) for p in pats] for g, pats in KEYWORD_GROUPS.items()}
    total = 0
    for group in KEYWORD_GROUPS:
        hits = []
        for off, s in strs:
            for rx in compiled[group]:
                if rx.search(s):
                    hits.append((off, s))
                    break
        if not hits:
            continue
        print("== %s (%d) ==" % (group, len(hits)))
        for off, s in hits[: a.limit]:
            print("  0x%08X  %s" % (off, s[:120]))
        if len(hits) > a.limit:
            print("  ... %d more" % (len(hits) - a.limit))
        total += len(hits)
    print("[*] total candidates=%d" % total)
    return 0


def cmd_probe(a):
    code = a.code.strip()
    print("input        : %s" % code)
    print("length       : %d" % len(code))
    groups = re.split(r"[-_ ]+", code)
    print("groups       : %s" % " / ".join(str(len(g)) for g in groups))
    print("group sizes  : %s" % [len(g) for g in groups])
    alpha = sorted(set(c for c in code if c.isalnum()))
    print("alphabet     : %s" % "".join(alpha))
    print("case         : %s" % ("upper" if code.upper() == code and any(c.isalpha() for c in code) else "mixed/lower"))
    matches = []
    for name, cs in CHARSETS.items():
        pool = set(cs)
        if all(c.isalnum() and c.upper() in pool for c in code):
            matches.append(name)
    print("charset match: %s" % (", ".join(matches) if matches else "none"))
    for name in ("base32", "hex", "base64"):
        cs = CHARSETS[name]
        compact = code.replace("-", "").replace(" ", "")
        ok = all(c in cs for c in compact)
        if ok and len(compact) % (8 if name == "base32" else 2) == 0:
            print("decodable as : %s (length %d)" % (name, len(compact)))
    return 0


def luhn_ok(digits):
    ds = [int(c) for c in digits if c.isdigit()]
    if not ds:
        return False
    total = 0
    parity = len(ds) % 2
    for i, d in enumerate(ds):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def cmd_checksum(a):
    code = a.code.strip().upper().replace("-", "").replace(" ", "")
    print("normalized : %s (len %d)" % (code, len(code)))
    result = []
    result.append(("luhn", luhn_ok(code)))
    for n in (7, 10, 11, 16, 26, 32, 36, 62):
        s = sum(ord(c) for c in code) % n
        result.append(("sum(ord) mod %d == 0" % n, s == 0))
    crc = zlib.crc32(code.encode()) & 0xFFFFFFFF
    result.append(("crc32 %% 256 == 0 (crc=0x%08X)" % crc, crc % 256 == 0))
    alpha = CHARSETS["base32"]
    if all(c in alpha for c in code):
        idx_sum = sum(alpha.index(c) for c in code)
        result.append(("base32 index sum mod 32 == 0 (%d)" % idx_sum, idx_sum % 32 == 0))
    for name, ok in result:
        print("  %-34s %s" % (name, "HIT" if ok else "-"))
    hits = [n for n, ok in result if ok]
    print("[*] hits=%d %s" % (len(hits), hits if hits else ""))
    return 0


def cmd_generate(a):
    cs = CHARSETS[a.charset]
    rng = random.Random(a.seed) if a.seed is not None else random.Random()
    seen = set()
    out = []
    for _ in range(a.count):
        for _try in range(100):
            s = "".join(rng.choice(cs) if ch == "X" else ch for ch in a.template)
            if s not in seen:
                seen.add(s)
                out.append(s)
                break
    for s in out:
        print(s)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print("[+] wrote %d -> %s" % (len(out), a.out))
    return 0


def cmd_verify(a):
    path = os.path.abspath(a.verifier)
    spec = importlib.util.spec_from_file_location("local_verifier", path)
    if spec is None or spec.loader is None:
        print("[!] cannot load verifier: %s" % path)
        return 1
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "verify"):
        print("[!] verifier must expose verify(code) -> bool")
        return 1
    if a.codes_file:
        codes = [l.strip() for l in open(a.codes_file, encoding="utf-8") if l.strip()]
    else:
        codes = [c.strip() for c in a.codes.split(",") if c.strip()]
    passed = []
    for c in codes:
        try:
            ok = bool(mod.verify(c))
        except Exception as e:
            print("[!] %s raised %s" % (c, e))
            continue
        print("%-40s %s" % (c, "PASS" if ok else "fail"))
        if ok:
            passed.append(c)
    print("[*] passed=%d/%d" % (len(passed), len(codes)))
    if a.out and passed:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("\n".join(passed) + "\n")
    return 0


def cmd_bdiff(a):
    da = open(a.fileA, "rb").read()
    db = open(a.fileB, "rb").read()
    print("A: %s (%d bytes)" % (a.fileA, len(da)))
    print("B: %s (%d bytes)" % (a.fileB, len(db)))
    n = min(len(da), len(db))
    ranges = []
    i = 0
    while i < n:
        if da[i] != db[i]:
            start = i
            last = i
            j = i
            while j < n:
                if da[j] != db[j]:
                    last = j
                    j += 1
                    if j - last > a.tolerance:
                        # long identical stretch closes the range
                        break
                else:
                    j += 1
                    if j - last > a.tolerance:
                        break
            ranges.append((start, last + 1))
            i = last + 1
        else:
            i += 1
    print("[*] differing ranges=%d" % len(ranges))
    for start, end in ranges[: a.limit]:
        print("  0x%08X - 0x%08X  (%d bytes)" % (start, end, end - start))
        print("    A: %s" % da[start : min(end, start + 16)].hex(" ").upper())
        print("    B: %s" % db[start : min(end, start + 16)].hex(" ").upper())
    if len(ranges) > a.limit:
        print("  ... %d more" % (len(ranges) - a.limit))
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="authorization verification flow analysis")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan")
    s.add_argument("file")
    s.add_argument("--min", type=int, default=5)
    s.add_argument("--limit", type=int, default=40)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("probe")
    s.add_argument("code")
    s.set_defaults(fn=cmd_probe)

    s = sub.add_parser("checksum")
    s.add_argument("code")
    s.set_defaults(fn=cmd_checksum)

    s = sub.add_parser("generate")
    s.add_argument("--template", default="XXXXX-XXXXX-XXXXX")
    s.add_argument("--charset", default="base32", choices=sorted(CHARSETS.keys()))
    s.add_argument("--count", type=int, default=10)
    s.add_argument("--seed", type=int)
    s.add_argument("--out")
    s.set_defaults(fn=cmd_generate)

    s = sub.add_parser("verify")
    s.add_argument("--verifier", required=True)
    s.add_argument("--codes")
    s.add_argument("--codes-file")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("bdiff")
    s.add_argument("fileA")
    s.add_argument("fileB")
    s.add_argument("--tolerance", type=int, default=16)
    s.add_argument("--limit", type=int, default=40)
    s.set_defaults(fn=cmd_bdiff)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
