#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 t3_sessions/ 里录制的响应预处理成"可直接发送的 HTTP 报文"，
输出 responses.h 供 t3local.c 内嵌（设备端本地重放，不依赖 PC / T3 服务器）。

处理规则与 t3_mitm.py 的 build() 一致：
  去掉 transfer-encoding/connection/date/content-length/server/expires/
  cache-control/vary，改成 Content-Length + Connection: close。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SESS = os.path.join(os.path.dirname(HERE), 't3_sessions')

DROP = {b'transfer-encoding', b'connection', b'date', b'content-length',
        b'server', b'expires', b'cache-control', b'vary'}

# kind -> 录制文件编号
FILE_IDX = {'rules': '01', 'crc': '03', 'beat': '05',
            'notice': '07', 'login': '09', 'heart': '11'}


def build(name):
    raw = open(os.path.join(SESS, name), 'rb').read()
    i = raw.find(b'\r\n\r\n')
    if i < 0:
        return None
    head, body = raw[:i + 4], raw[i + 4:]
    lines = head.split(b'\r\n')
    status = lines[0]
    keep = []
    for l in lines[1:]:
        if not l:
            continue
        k = l.split(b':')[0].strip().lower()
        if k in DROP:
            continue
        keep.append(l)
    out = status + b'\r\n' + b'\r\n'.join(keep)
    out += b'\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body)
    return out + body


def carray(name, data):
    lines = ['static const unsigned char %s[] = {' % name]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        lines.append('    ' + ','.join('0x%02x' % b for b in chunk) + ',')
    lines.append('};')
    lines.append('static const int %s_len = %d;' % (name, len(data)))
    return '\n'.join(lines)


def main():
    out = ['/* 自动生成，勿手改：来源 t3_sessions/ */',
           '#ifndef RESPONSES_H', '#define RESPONSES_H', '']
    ok = []
    for kind in ('rules', 'crc', 'beat', 'notice', 'login', 'heart'):
        n = FILE_IDX[kind]
        p = os.path.join(SESS, '%s_resp.txt' % n)
        if not os.path.exists(p):
            print('[!] 缺少 %s -> %s 无响应，用空占位' % (kind, p))
            out.append('static const unsigned char resp_%s[] = { 0 };' % kind)
            out.append('static const int resp_%s_len = 0;' % kind)
            out.append('')
            continue
        data = build('%s_resp.txt' % n)
        out.append(carray('resp_%s' % kind, data))
        out.append('')
        ok.append((kind, len(data)))
        print('[+] %-7s %s_resp.txt -> %d bytes' % (kind, n, len(data)))
    out.append('#endif')
    dst = os.path.join(HERE, 'responses.h')
    open(dst, 'w', encoding='utf-8').write('\n'.join(out))
    print('[+] 写出 %s' % dst)
    if not ok:
        sys.exit(2)


if __name__ == '__main__':
    main()
