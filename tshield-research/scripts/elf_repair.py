#!/usr/bin/env python3
"""
T盾 脱壳后 ELF 结构修复工具
修复动态 dump 后的 ELF 文件，使其可以被 IDA/Ghidra 正常加载

用法：
    python3 elf_repair.py --input dump.bin --output repaired.elf --base 0x0
    python3 elf_repair.py --input dump.bin --output repaired.elf --maps maps.txt
    python3 elf_repair.py --verify repaired.elf
"""

import sys
import os
import struct
import argparse
import math

# ELF 常量
ELF_MAGIC = b'\x7fELF'
ET_DYN = 3
EM_AARCH64 = 183
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_PHDR = 6
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK = 0x6474e551
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_DYNAMIC = 6
SHF_ALLOC = 2
SHF_EXECINSTR = 4
SHF_WRITE = 1


class ELFRepairer:
    def __init__(self, input_file, output_file, base_addr=0):
        self.input_file = input_file
        self.output_file = output_file
        self.base_addr = base_addr

        with open(input_file, 'rb') as f:
            self.data = bytearray(f.read())

        self.size = len(self.data)

    def repair_elf_header(self, entry_point=None, machine=EM_AARCH64):
        """修复 ELF 头"""
        d = self.data

        # 魔数
        d[0:4] = ELF_MAGIC
        d[4] = 2  # 64位
        d[5] = 1  # 小端
        d[6] = 1  # 版本
        d[7] = 0  # OS/ABI

        # e_type
        struct.pack_into('<H', d, 0x10, ET_DYN)
        # e_machine
        struct.pack_into('<H', d, 0x12, machine)
        # e_version
        struct.pack_into('<I', d, 0x14, 1)

        # e_entry
        if entry_point is not None:
            struct.pack_into('<Q', d, 0x18, entry_point)

        # e_phoff (Program Header 紧跟 ELF 头)
        struct.pack_into('<Q', d, 0x20, 64)

        # e_ehsize
        struct.pack_into('<H', d, 0x34, 64)
        # e_phentsize
        struct.pack_into('<H', d, 0x36, 56)

        print('[+] ELF 头已修复')

    def build_program_headers(self, segments):
        """构建 Program Headers

        segments: list of dict {vaddr, size, flags, file_offset, is_bss}
        """
        d = self.data
        phoff = 64
        phentsize = 56
        phnum = len(segments) + 1  # +1 for PHDR

        # 确保有足够空间
        needed = phoff + phnum * phentsize
        if len(d) < needed:
            d.extend(b'\x00' * (needed - len(d)))

        # PHDR
        struct.pack_into('<I', d, phoff, PT_PHDR)
        struct.pack_into('<I', d, phoff + 4, 4)  # R
        struct.pack_into('<Q', d, phoff + 8, phoff)
        struct.pack_into('<Q', d, phoff + 16, phoff)
        struct.pack_into('<Q', d, phoff + 24, phoff)
        struct.pack_into('<Q', d, phoff + 32, phnum * phentsize)
        struct.pack_into('<Q', d, phoff + 40, phnum * phentsize)
        struct.pack_into('<Q', d, phoff + 48, 8)

        # LOAD 段
        for i, seg in enumerate(segments):
            offset = phoff + (i + 1) * phentsize

            struct.pack_into('<I', d, offset, PT_LOAD)
            struct.pack_into('<I', d, offset + 4, seg['flags'])
            struct.pack_into('<Q', d, offset + 8, seg.get('file_offset', 0))
            struct.pack_into('<Q', d, offset + 16, seg['vaddr'])
            struct.pack_into('<Q', d, offset + 24, seg['vaddr'])
            struct.pack_into('<Q', d, offset + 32, 0 if seg.get('is_bss') else seg['size'])
            struct.pack_into('<Q', d, offset + 40, seg['size'])
            struct.pack_into('<Q', d, offset + 48, 0x1000)

        # 更新 e_phnum
        struct.pack_into('<H', d, 0x38, phnum)

        print(f'[+] Program Headers 已构建 ({phnum} 个)')

    def build_section_headers(self, sections):
        """构建 Section Headers

        sections: list of dict {name, type, flags, addr, offset, size, is_bss}
        """
        d = self.data

        # 构建 .shstrtab
        shstrtab = b'\x00'
        name_offsets = {}
        for sec in sections:
            name = sec['name'].encode('utf-8') + b'\x00'
            name_offsets[sec['name']] = len(shstrtab)
            shstrtab += name

        # .shstrtab 本身
        shstrtab_name_offset = len(shstrtab)
        shstrtab += b'.shstrtab\x00'

        # Section Header 放在文件末尾
        shoff = len(d)
        shentsize = 64
        shnum = len(sections) + 2  # NULL + sections + .shstrtab

        # 确保有足够空间
        d.extend(b'\x00' * (shnum * shentsize))

        # NULL section (index 0)
        # 全零即可

        # 各 section
        for i, sec in enumerate(sections):
            offset = shoff + (i + 1) * shentsize

            struct.pack_into('<I', d, offset, name_offsets[sec['name']])
            struct.pack_into('<I', d, offset + 4, sec['type'])
            struct.pack_into('<Q', d, offset + 8, sec['flags'])
            struct.pack_into('<Q', d, offset + 16, sec['addr'])
            struct.pack_into('<Q', d, offset + 24, sec.get('offset', 0))
            struct.pack_into('<Q', d, offset + 32, 0 if sec.get('is_bss') else sec['size'])
            struct.pack_into('<I', d, offset + 40, 0)  # sh_link
            struct.pack_into('<I', d, offset + 44, 0)  # sh_info
            struct.pack_into('<Q', d, offset + 48, sec.get('addralign', 16))
            struct.pack_into('<Q', d, offset + 56, 0)  # sh_entsize

        # .shstrtab section (最后一个)
        shstrtab_offset = shoff + (shnum - 1) * shentsize
        struct.pack_into('<I', d, shstrtab_offset, shstrtab_name_offset)
        struct.pack_into('<I', d, shstrtab_offset + 4, SHT_STRTAB)
        struct.pack_into('<Q', d, shstrtab_offset + 8, 0)
        struct.pack_into('<Q', d, shstrtab_offset + 16, 0)
        struct.pack_into('<Q', d, shstrtab_offset + 24, len(d) - shnum * shentsize)
        struct.pack_into('<Q', d, shstrtab_offset + 32, len(shstrtab))
        struct.pack_into('<I', d, shstrtab_offset + 40, 0)
        struct.pack_into('<I', d, shstrtab_offset + 44, 0)
        struct.pack_into('<Q', d, shstrtab_offset + 48, 1)
        struct.pack_into('<Q', d, shstrtab_offset + 56, 0)

        # 写入 .shstrtab 数据
        d.extend(shstrtab)

        # 更新 ELF 头
        struct.pack_into('<Q', d, 0x28, shoff)  # e_shoff
        struct.pack_into('<H', d, 0x3a, shentsize)  # e_shentsize
        struct.pack_into('<H', d, 0x3c, shnum)  # e_shnum
        struct.pack_into('<H', d, 0x3e, shnum - 1)  # e_shstrndx

        print(f'[+] Section Headers 已构建 ({shnum} 个)')

    def save(self):
        """保存修复后的文件"""
        with open(self.output_file, 'wb') as f:
            f.write(self.data)
        print(f'[+] 已保存到: {self.output_file}')
        print(f'    文件大小: {len(self.data):,} 字节 ({len(self.data)/1024/1024:.2f} MB)')


def verify_elf(filepath):
    """验证 ELF 文件"""
    print(f'验证: {filepath}')
    print('=' * 60)

    with open(filepath, 'rb') as f:
        data = f.read()

    # 检查魔数
    if data[:4] != ELF_MAGIC:
        print('[-] 不是有效的 ELF 文件（魔数错误）')
        return False
    print('[+] ELF 魔数正确')

    # 检查架构
    ei_class = data[4]
    ei_data = data[5]
    e_machine = struct.unpack_from('<H', data, 0x12)[0]
    e_type = struct.unpack_from('<H', data, 0x10)[0]
    e_entry = struct.unpack_from('<Q', data, 0x18)[0]
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]

    print(f'[+] 位数: {"64位" if ei_class == 2 else "32位"}')
    print(f'[+] 字节序: {"小端" if ei_data == 1 else "大端"}')
    print(f'[+] 类型: {e_type}')
    print(f'[+] 架构: {e_machine} ({"ARM64" if e_machine == EM_AARCH64 else "未知"})')
    print(f'[+] 入口点: 0x{e_entry:x}')
    print(f'[+] Program Headers: {e_phnum} 个 (偏移 0x{e_phoff:x})')
    print(f'[+] Section Headers: {e_shnum} 个 (偏移 0x{e_shoff:x})')

    # 验证 Program Headers
    print()
    print('Program Headers:')
    print(f'{"#":>3} {"类型":<10} {"权限":<6} {"文件偏移":>12} {"虚拟地址":>12} {"文件大小":>12} {"内存大小":>12}')
    print('-' * 80)
    for i in range(e_phnum):
        offset = e_phoff + i * 56
        p_type = struct.unpack_from('<I', data, offset)[0]
        p_flags = struct.unpack_from('<I', data, offset + 4)[0]
        p_offset = struct.unpack_from('<Q', data, offset + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, offset + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, offset + 32)[0]
        p_memsz = struct.unpack_from('<Q', data, offset + 40)[0]

        type_names = {0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 6: 'PHDR'}
        type_name = type_names.get(p_type, f'0x{p_type:x}')
        r = 'R' if p_flags & 4 else '-'
        w = 'W' if p_flags & 2 else '-'
        x = 'X' if p_flags & 1 else '-'

        print(f'{i:>3} {type_name:<10} {r}{w}{x:<3} '
              f'0x{p_offset:010x} 0x{p_vaddr:010x} '
              f'0x{p_filesz:010x} 0x{p_memsz:010x}')

    # 验证 Section Headers
    if e_shnum > 0 and e_shoff > 0:
        print()
        print('Section Headers:')
        print(f'{"#":>3} {"名称":<16} {"类型":<10} {"地址":>12} {"偏移":>12} {"大小":>12}')
        print('-' * 70)

        # 读取 .shstrtab
        shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
        shstrtab_offset = struct.unpack_from('<Q', data, e_shoff + shstrndx * 64 + 24)[0]
        shstrtab_size = struct.unpack_from('<Q', data, e_shoff + shstrndx * 64 + 32)[0]
        shstrtab = data[shstrtab_offset:shstrtab_offset + shstrtab_size]

        type_names = {0: 'NULL', 1: 'PROGBITS', 3: 'STRTAB', 6: 'DYNAMIC', 8: 'NOBITS'}

        for i in range(e_shnum):
            offset = e_shoff + i * 64
            sh_name = struct.unpack_from('<I', data, offset)[0]
            sh_type = struct.unpack_from('<I', data, offset + 4)[0]
            sh_addr = struct.unpack_from('<Q', data, offset + 16)[0]
            sh_offset = struct.unpack_from('<Q', data, offset + 24)[0]
            sh_size = struct.unpack_from('<Q', data, offset + 32)[0]

            name_end = shstrtab.find(b'\x00', sh_name)
            if name_end == -1:
                name_end = len(shstrtab)
            name = shstrtab[sh_name:name_end].decode('utf-8', errors='replace')

            type_name = type_names.get(sh_type, f'0x{sh_type:x}')

            print(f'{i:>3} {name:<16} {type_name:<10} '
                  f'0x{sh_addr:010x} 0x{sh_offset:010x} 0x{sh_size:010x}')

    print()
    print('[+] 验证完成')
    return True


def main():
    parser = argparse.ArgumentParser(description='T盾 脱壳后 ELF 结构修复工具')
    parser.add_argument('--input', help='输入的 dump 文件')
    parser.add_argument('--output', help='输出的修复后 ELF 文件')
    parser.add_argument('--base', default='0x0', help='基址（十六进制）')
    parser.add_argument('--entry', help='入口点（十六进制，默认从文件中读取）')
    parser.add_argument('--verify', help='验证指定的 ELF 文件')
    parser.add_argument('--simple', action='store_true', help='简单修复模式（仅修复ELF头和PHDR）')
    args = parser.parse_args()

    if args.verify:
        verify_elf(args.verify)
        return

    if not args.input or not args.output:
        parser.print_help()
        return

    base_addr = int(args.base, 16) if args.base.startswith('0x') else int(args.base)
    entry_point = int(args.entry, 16) if args.entry else None

    print(f'输入: {args.input}')
    print(f'输出: {args.output}')
    print(f'基址: 0x{base_addr:x}')
    print()

    repairer = ELFRepairer(args.input, args.output, base_addr)

    # 修复 ELF 头
    repairer.repair_elf_header(entry_point=entry_point)

    if args.simple:
        # 简单模式：只修复 ELF 头，保留原始 Program Headers
        # 假设输入已经是有效的内存 dump
        print('[+] 简单修复模式：保留原始 Program Headers')
    else:
        # 完整模式：重建 Program Headers 和 Section Headers
        # 这里假设输入是单个连续的内存 dump
        # 需要用户提供段信息，或者自动检测

        # 简单的自动检测：把整个文件作为一个 LOAD 段
        segments = [{
            'vaddr': base_addr,
            'size': repairer.size,
            'flags': 5,  # R-X
            'file_offset': 0,
            'is_bss': False,
        }]
        repairer.build_program_headers(segments)

        # 构建基本的 Section Headers
        sections = [{
            'name': '.text',
            'type': SHT_PROGBITS,
            'flags': SHF_ALLOC | SHF_EXECINSTR,
            'addr': base_addr,
            'offset': 0,
            'size': repairer.size,
            'is_bss': False,
        }]
        repairer.build_section_headers(sections)

    repairer.save()

    # 验证
    print()
    verify_elf(args.output)


if __name__ == '__main__':
    main()
