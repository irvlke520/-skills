#!/usr/bin/env python3
"""
T盾 Stub 批量提取器
提取所有函数 Stub、函数ID，建立函数ID映射表

用法：
    python3 stub_extractor.py <elf_file>
    python3 stub_extractor.py <elf_file> --output stubs.json
    python3 stub_extractor.py <elf_file> --decryptor 0x4b7e3c8
    python3 stub_extractor.py <elf_file> --mapping
"""

import sys
import struct
import json
import argparse

# 复用 tshield_analyzer 中的 ELFParser
sys.path.insert(0, '/home/user/Doubao/chats/38419632913971970/tshield-research/scripts')
from tshield_analyzer import ELFParser, PT_LOAD, calculate_entropy


def extract_stubs(elf, decryptor_addr=None):
    """提取所有 Stub"""
    stubs = []
    e = elf.endian

    for ph in elf.phdrs:
        if ph['p_type'] != PT_LOAD:
            continue
        if not (ph['p_flags'] & 1):  # 不可执行
            continue
        if ph['p_filesz'] == 0:
            continue

        data = elf.read_vaddr(ph['p_vaddr'], ph['p_filesz'])
        if data is None:
            continue

        count = len(data) // 4
        i = 0
        while i < count - 4:
            insns = [struct.unpack_from(e + 'I', data, (i + j) * 4)[0] for j in range(5)]

            # Stub 模式检测
            if (insns[0] == 0xf81f0fed and
                (insns[1] & 0xff80001f) == 0x5280000d and
                (insns[2] & 0xffe0001f) == 0x72a0000d and
                insns[3] == 0xf90007ed and
                (insns[4] & 0xfc000000) == 0x14000000):

                stub_vaddr = ph['p_vaddr'] + i * 4
                imm16_lo = (insns[1] >> 5) & 0xffff
                imm16_hi = (insns[2] >> 5) & 0xffff
                func_id = (imm16_hi << 16) | imm16_lo

                # b 指令目标
                b_offset = insns[4] & 0x03ffffff
                if b_offset & 0x02000000:
                    b_offset -= 0x04000000
                b_offset *= 4
                target = stub_vaddr + 16 + b_offset

                if decryptor_addr is None or target == decryptor_addr:
                    stubs.append({
                        'vaddr': stub_vaddr,
                        'func_id': func_id,
                        'target': target,
                        'segment': ph['index'],
                    })

                i += 5
            else:
                i += 1

    return stubs


def build_mapping_table(stubs):
    """建立函数ID映射表"""
    mapping = {}
    for stub in stubs:
        func_id = stub['func_id']
        if func_id not in mapping:
            mapping[func_id] = []
        mapping[func_id].append(stub['vaddr'])
    return mapping


def find_decryptor(stubs):
    """从 Stub 中推断统一解密器地址"""
    targets = {}
    for stub in stubs:
        target = stub['target']
        targets[target] = targets.get(target, 0) + 1

    if not targets:
        return None

    # 出现次数最多的目标就是统一解密器
    decryptor = max(targets, key=targets.get)
    return decryptor, targets[decryptor]


def main():
    parser = argparse.ArgumentParser(description='T盾 Stub 批量提取器')
    parser.add_argument('elf_file', help='ELF 文件路径')
    parser.add_argument('--output', help='输出 JSON 文件')
    parser.add_argument('--decryptor', help='统一解密器地址（十六进制，如 0x4b7e3c8）')
    parser.add_argument('--mapping', action='store_true', help='输出函数ID映射表')
    parser.add_argument('--limit', type=int, default=20, help='打印前 N 个 Stub（默认20）')
    args = parser.parse_args()

    try:
        elf = ELFParser(args.elf_file)
    except Exception as e:
        print(f'错误: {e}')
        sys.exit(1)

    decryptor_addr = None
    if args.decryptor:
        decryptor_addr = int(args.decryptor, 16)

    print(f'正在扫描 Stub...')
    stubs = extract_stubs(elf, decryptor_addr)

    if not stubs:
        print('未找到任何 Stub')
        sys.exit(1)

    # 统计
    func_ids = set(s['func_id'] for s in stubs)
    print(f'\n找到 {len(stubs)} 个 Stub')
    print(f'唯一函数ID: {len(func_ids)} 个')

    # 推断统一解密器
    if decryptor_addr is None:
        result = find_decryptor(stubs)
        if result:
            decryptor, count = result
            print(f'推断统一解密器: 0x{decryptor:x} (被 {count} 个 Stub 引用)')

    # 打印前 N 个
    print(f'\n前 {min(args.limit, len(stubs))} 个 Stub:')
    print(f'{"#":>4} {"虚拟地址":>12} {"函数ID":>10} {"跳转目标":>12} {"段":>4}')
    print('-' * 60)
    for i, stub in enumerate(stubs[:args.limit]):
        print(f'{i:>4} 0x{stub["vaddr"]:010x} 0x{stub["func_id"]:08x} '
              f'0x{stub["target"]:010x} {stub["segment"]:>4}')

    if len(stubs) > args.limit:
        print(f'... 还有 {len(stubs) - args.limit} 个')

    # 函数ID映射表
    if args.mapping:
        mapping = build_mapping_table(stubs)
        print(f'\n函数ID映射表（前 {min(args.limit, len(mapping))} 个）:')
        print(f'{"函数ID":>10} {"Stub数量":>8} {"第一个Stub地址":>14}')
        print('-' * 50)
        for i, (func_id, addrs) in enumerate(sorted(mapping.items())):
            if i >= args.limit:
                break
            print(f'0x{func_id:08x} {len(addrs):>8} 0x{addrs[0]:010x}')

    # 输出 JSON
    if args.output:
        output_data = {
            'file': args.elf_file,
            'total_stubs': len(stubs),
            'unique_func_ids': len(func_ids),
            'decryptor_addr': decryptor_addr,
            'stubs': stubs,
        }
        if args.mapping:
            output_data['mapping'] = {str(k): v for k, v in build_mapping_table(stubs).items()}

        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f'\n已保存到: {args.output}')


if __name__ == '__main__':
    main()
