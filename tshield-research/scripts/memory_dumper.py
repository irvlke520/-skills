#!/usr/bin/env python3
"""
T盾 运行时内存 Dump 工具
生成 gdb 脚本和 Frida 脚本，用于 dump 解密后的代码段

用法：
    python3 memory_dumper.py --elf <elf_file> --gdb-script dump.gdb
    python3 memory_dumper.py --elf <elf_file> --frida-script dump.js
    python3 memory_dumper.py --pid <pid> --adb
    python3 memory_dumper.py --maps maps.txt --output-dir ./dump/
"""

import sys
import os
import struct
import argparse
import re

sys.path.insert(0, '/home/user/Doubao/chats/38419632913971970/tshield-research/scripts')
from tshield_analyzer import ELFParser, PT_LOAD, format_flags


def find_decrypted_segments(elf):
    """从 ELF 中找到解密后代码段（filesz=0, memsz>0, 可执行）"""
    segments = []
    for ph in elf.phdrs:
        if (ph['p_type'] == PT_LOAD and
            ph['p_filesz'] == 0 and
            ph['p_memsz'] > 0x1000 and
            (ph['p_flags'] & 1)):  # 可执行
            segments.append({
                'vaddr': ph['p_vaddr'],
                'memsz': ph['p_memsz'],
                'end': ph['p_vaddr'] + ph['p_memsz'],
                'flags': ph['p_flags'],
            })
    return segments


def find_payload_segments(elf):
    """找到加密 payload 段（高熵、可执行、filesz>0）"""
    segments = []
    for ph in elf.phdrs:
        if (ph['p_type'] == PT_LOAD and
            ph['p_filesz'] > 0x10000 and
            (ph['p_flags'] & 1)):  # 可执行
            segments.append({
                'vaddr': ph['p_vaddr'],
                'filesz': ph['p_filesz'],
                'end': ph['p_vaddr'] + ph['p_filesz'],
                'flags': ph['p_flags'],
            })
    return segments


def generate_gdb_script(elf, output_file, base_addr=0):
    """生成 gdb dump 脚本"""
    decrypted = find_decrypted_segments(elf)
    payload = find_payload_segments(elf)

    lines = []
    lines.append('# T盾 内存 Dump gdb 脚本')
    lines.append('# 自动生成')
    lines.append('')
    lines.append('set pagination off')
    lines.append('set logging on')
    lines.append('')
    lines.append('# 确认进程已附加')
    lines.append('# target remote :1234')
    lines.append('')

    # dump 解密后代码段
    lines.append('# ============================================')
    lines.append('# Dump 解密后代码段（最重要）')
    lines.append('# ============================================')
    for i, seg in enumerate(decrypted):
        start = seg['vaddr'] + base_addr
        end = seg['end'] + base_addr
        filename = f'decrypted_code_{i}.bin'
        lines.append(f'')
        lines.append(f'# 段{i}: 0x{start:x} - 0x{end:x} ({seg["memsz"]:,} 字节)')
        lines.append(f'printf "Dumping decrypted code segment {i}...\\n"')
        lines.append(f'dump memory {filename} 0x{start:x} 0x{end:x}')
        lines.append(f'printf "Done: {filename}\\n"')

    # dump payload 段
    lines.append('')
    lines.append('# ============================================')
    lines.append('# Dump 加密 payload 段（包含Stub和解密器）')
    lines.append('# ============================================')
    for i, seg in enumerate(payload):
        start = seg['vaddr'] + base_addr
        end = seg['end'] + base_addr
        filename = f'payload_{i}.bin'
        lines.append(f'')
        lines.append(f'# 段{i}: 0x{start:x} - 0x{end:x} ({seg["filesz"]:,} 字节)')
        lines.append(f'printf "Dumping payload segment {i}...\\n"')
        lines.append(f'dump memory {filename} 0x{start:x} 0x{end:x}')
        lines.append(f'printf "Done: {filename}\\n"')

    # dump 所有可执行段
    lines.append('')
    lines.append('# ============================================')
    lines.append('# Dump 所有可执行段（完整）')
    lines.append('# ============================================')
    lines.append('')
    lines.append('# 手动执行以下命令获取所有可执行段:')
    lines.append('# info proc mappings')
    lines.append('# 然后对每个 r-xp 段执行 dump memory')

    lines.append('')
    lines.append('printf "All dumps completed.\\n"')
    lines.append('quit')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f'gdb 脚本已生成: {output_file}')
    print(f'  解密后代码段: {len(decrypted)} 个')
    print(f'  payload 段: {len(payload)} 个')


def generate_frida_script(elf, output_file):
    """生成 Frida dump 脚本（需授权注入）"""
    decrypted = find_decrypted_segments(elf)
    payload = find_payload_segments(elf)

    lines = []
    lines.append('// T盾 内存 Dump Frida 脚本')
    lines.append('// 需授权注入到目标进程')
    lines.append('// 用法: frida -U -f <package> -l dump.js')
    lines.append('')
    lines.append('function dumpMemory(start, end, filename) {')
    lines.append('    const size = end - start;')
    lines.append('    try {')
    lines.append('        const data = ptr(start).readByteArray(size);')
    lines.append('        const file = new File(filename, "wb");')
    lines.append('        file.write(data);')
    lines.append('        file.flush();')
    lines.append('        file.close();')
    lines.append('        console.log("[+] Dumped 0x" + start.toString(16) + "-0x" + end.toString(16) + " (" + size + " bytes) -> " + filename);')
    lines.append('    } catch(e) {')
    lines.append('        console.log("[-] Failed to dump 0x" + start.toString(16) + ": " + e);')
    lines.append('    }')
    lines.append('}')
    lines.append('')
    lines.append('function findModuleBase(name) {')
    lines.append('    const modules = Process.enumerateModules();')
    lines.append('    for (const m of modules) {')
    lines.append('        if (m.name.includes(name) || m.path.includes(name)) {')
    lines.append('            return m.base;')
    lines.append('        }')
    lines.append('    }')
    lines.append('    return null;')
    lines.append('}')
    lines.append('')
    lines.append('// 等待程序加载完成')
    lines.append('setTimeout(function() {')
    lines.append('    console.log("[*] Starting memory dump...");')
    lines.append('')

    # dump 解密后代码段
    lines.append('    // ============================================')
    lines.append('    // Dump 解密后代码段（最重要）')
    lines.append('    // ============================================')
    for i, seg in enumerate(decrypted):
        lines.append(f'    // 段{i}: 0x{seg["vaddr"]:x} - 0x{seg["end"]:x}')
        lines.append(f'    dumpMemory(ptr("0x{seg["vaddr"]:x}"), ptr("0x{seg["end"]:x}"), "/data/local/tmp/decrypted_code_{i}.bin");')

    # dump payload 段
    lines.append('')
    lines.append('    // ============================================')
    lines.append('    // Dump 加密 payload 段')
    lines.append('    // ============================================')
    for i, seg in enumerate(payload):
        lines.append(f'    // 段{i}: 0x{seg["vaddr"]:x} - 0x{seg["end"]:x}')
        lines.append(f'    dumpMemory(ptr("0x{seg["vaddr"]:x}"), ptr("0x{seg["end"]:x}"), "/data/local/tmp/payload_{i}.bin");')

    # dump 所有可执行段
    lines.append('')
    lines.append('    // ============================================')
    lines.append('    // Dump 所有可执行段（完整）')
    lines.append('    // ============================================')
    lines.append('    const ranges = Process.enumerateRanges("r-x");')
    lines.append('    console.log("[*] Found " + ranges.length + " executable ranges");')
    lines.append('    ranges.forEach(function(range, idx) {')
    lines.append('        const filename = "/data/local/tmp/code_" + idx + "_" + range.base.toString(16) + ".bin";')
    lines.append('        dumpMemory(range.base, range.base.add(range.size), filename);')
    lines.append('    });')

    lines.append('')
    lines.append('    console.log("[+] All dumps completed!");')
    lines.append('}, 5000);  // 5秒后开始dump（等待程序加载完成）')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f'Frida 脚本已生成: {output_file}')
    print(f'  解密后代码段: {len(decrypted)} 个')
    print(f'  payload 段: {len(payload)} 个')


def parse_maps(maps_file):
    """解析 /proc/pid/maps 文件"""
    segments = []
    with open(maps_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = re.match(
                r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s*(.*)',
                line
            )
            if match:
                start = int(match.group(1), 16)
                end = int(match.group(2), 16)
                perms = match.group(3)
                offset = int(match.group(4), 16)
                path = match.group(5).strip()
                segments.append({
                    'start': start, 'end': end,
                    'perms': perms, 'offset': offset,
                    'path': path, 'size': end - start,
                })
    return segments


def generate_dump_from_maps(maps_file, output_dir):
    """从 maps 文件生成 dump 命令"""
    segments = parse_maps(maps_file)

    os.makedirs(output_dir, exist_ok=True)

    # 分类
    anon_exec = [s for s in segments if 'x' in s['perms'] and not s['path']]
    file_exec = [s for s in segments if 'x' in s['perms'] and s['path']]
    rw_data = [s for s in segments if 'r' in s['perms'] and 'w' in s['perms']]

    print(f'解析到 {len(segments)} 个内存段')
    print(f'  匿名可执行段（解密后代码）: {len(anon_exec)} 个')
    print(f'  文件映射可执行段: {len(file_exec)} 个')
    print(f'  读写数据段: {len(rw_data)} 个')

    # 生成 gdb 脚本
    gdb_script = os.path.join(output_dir, 'dump_all.gdb')
    lines = []
    lines.append('# 从 /proc/pid/maps 生成的 dump 脚本')
    lines.append('set pagination off')
    lines.append('')

    idx = 0
    for seg in anon_exec:
        filename = f'anon_exec_{idx}.bin'
        lines.append(f'dump memory {filename} 0x{seg["start"]:x} 0x{seg["end"]:x}')
        lines.append(f'printf "Dumped: {filename} (0x{seg["start"]:x}-0x{seg["end"]:x})\\n"')
        idx += 1

    idx = 0
    for seg in file_exec:
        safe_name = seg['path'].replace('/', '_').replace(' ', '_')[:50]
        filename = f'file_exec_{idx}_{safe_name}.bin'
        lines.append(f'dump memory {filename} 0x{seg["start"]:x} 0x{seg["end"]:x}')
        idx += 1

    with open(gdb_script, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f'\ngdb 脚本已生成: {gdb_script}')

    # 生成报告
    report = os.path.join(output_dir, 'dump_report.txt')
    with open(report, 'w', encoding='utf-8') as f:
        f.write('内存 Dump 报告\n')
        f.write('=' * 60 + '\n\n')
        f.write(f'总段数: {len(segments)}\n')
        f.write(f'匿名可执行段（解密后代码）: {len(anon_exec)}\n')
        f.write(f'文件映射可执行段: {len(file_exec)}\n')
        f.write(f'读写数据段: {len(rw_data)}\n\n')

        f.write('匿名可执行段（解密后代码，最重要）:\n')
        f.write('-' * 60 + '\n')
        for i, seg in enumerate(anon_exec):
            f.write(f'  [{i}] 0x{seg["start"]:012x}-0x{seg["end"]:012x} '
                    f'({seg["size"]:,} 字节, {seg["size"]/1024/1024:.2f} MB) {seg["perms"]}\n')

        f.write('\n文件映射可执行段:\n')
        f.write('-' * 60 + '\n')
        for i, seg in enumerate(file_exec):
            f.write(f'  [{i}] 0x{seg["start"]:012x}-0x{seg["end"]:012x} '
                    f'({seg["size"]:,} 字节) {seg["perms"]} {seg["path"]}\n')

    print(f'报告已生成: {report}')


def main():
    parser = argparse.ArgumentParser(description='T盾 运行时内存 Dump 工具')
    parser.add_argument('--elf', help='ELF 文件路径（用于分析段结构）')
    parser.add_argument('--gdb-script', help='生成 gdb dump 脚本')
    parser.add_argument('--frida-script', help='生成 Frida dump 脚本')
    parser.add_argument('--maps', help='/proc/pid/maps 文件路径')
    parser.add_argument('--output-dir', default='./dump_output', help='输出目录')
    parser.add_argument('--base', default='0', help='基址（用于PIE，默认0）')
    args = parser.parse_args()

    if args.elf:
        try:
            elf = ELFParser(args.elf)
        except Exception as e:
            print(f'错误: {e}')
            sys.exit(1)

        # 显示段信息
        decrypted = find_decrypted_segments(elf)
        payload = find_payload_segments(elf)

        print('=' * 60)
        print('内存段分析')
        print('=' * 60)

        if decrypted:
            print(f'\n解密后代码段（运行时填充，filesz=0）:')
            for i, seg in enumerate(decrypted):
                print(f'  [{i}] 0x{seg["vaddr"]:012x}-0x{seg["end"]:012x} '
                      f'({seg["memsz"]:,} 字节, {seg["memsz"]/1024/1024:.2f} MB) '
                      f'{format_flags(seg["flags"])}')

        if payload:
            print(f'\n加密 payload 段:')
            for i, seg in enumerate(payload):
                print(f'  [{i}] 0x{seg["vaddr"]:012x}-0x{seg["end"]:012x} '
                      f'({seg["filesz"]:,} 字节, {seg["filesz"]/1024/1024:.2f} MB) '
                      f'{format_flags(seg["flags"])}')

        base_addr = int(args.base, 16) if args.base.startswith('0x') else int(args.base)

        if args.gdb_script:
            generate_gdb_script(elf, args.gdb_script, base_addr)

        if args.frida_script:
            generate_frida_script(elf, args.frida_script)

    if args.maps:
        generate_dump_from_maps(args.maps, args.output_dir)

    if not args.elf and not args.maps:
        parser.print_help()


if __name__ == '__main__':
    main()
