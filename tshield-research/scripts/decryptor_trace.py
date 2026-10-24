#!/usr/bin/env python3
"""
T盾 统一解密器动态跟踪辅助工具
生成 gdb 脚本和 Frida 脚本，用于跟踪统一解密器

用法：
    python3 decryptor_trace.py --elf <elf_file> --gdb-script trace.gdb
    python3 decryptor_trace.py --elf <elf_file> --frida-script trace.js
    python3 decryptor_trace.py --decryptor 0x4b7e3c8 --gdb-script trace.gdb
    python3 decryptor_trace.py --parse-log trace.log --output mapping.json
"""

import sys
import os
import re
import json
import struct
import argparse

sys.path.insert(0, '/home/user/Doubao/chats/38419632913971970/tshield-research/scripts')
from tshield_analyzer import ELFParser, TShieldDetector


def find_decryptor(elf):
    """从 ELF 中找到统一解密器地址"""
    detector = TShieldDetector(elf)
    if hasattr(detector, 'decryptor_addr') and detector.decryptor_addr:
        return detector.decryptor_addr
    return None


def generate_gdb_script(decryptor_addr, output_file, max_calls=1000):
    """生成 gdb 跟踪脚本"""
    lines = []
    lines.append('# T盾 统一解密器跟踪 gdb 脚本')
    lines.append('# 自动生成')
    lines.append('')
    lines.append('set pagination off')
    lines.append('set logging on')
    lines.append('')
    lines.append('# 初始化计数器')
    lines.append('set $call_count = 0')
    lines.append('')
    lines.append(f'# 在统一解密器入口下断点')
    lines.append(f'break *0x{decryptor_addr:x}')
    lines.append('commands')
    lines.append('    silent')
    lines.append('    set $call_count = $call_count + 1')
    lines.append('    printf "=== Decryptor Call #%d ===\\n", $call_count')
    lines.append('    printf "SP = 0x%lx\\n", $sp')
    lines.append('    # 查看栈内容（寻找函数ID）')
    lines.append('    x/16gx $sp')
    lines.append('    # 查看寄存器')
    lines.append('    printf "x0=0x%lx x1=0x%lx x2=0x%lx x3=0x%lx\\n", $x0, $x1, $x2, $x3')
    lines.append('    printf "x7=0x%lx x11=0x%lx x13=0x%lx\\n", $x7, $x11, $x13')
    lines.append(f'    if $call_count >= {max_calls}')
    lines.append('        printf "Max calls reached, stopping\\n"')
    lines.append('        quit')
    lines.append('    end')
    lines.append('    continue')
    lines.append('end')
    lines.append('')
    lines.append('# 在解密函数调用处下断点（如果已知地址）')
    lines.append('# break *0x5a90278')
    lines.append('# commands')
    lines.append('#     silent')
    lines.append('#     printf "bl decrypt_func: x0=0x%lx x1=0x%lx x2=0x%lx\\n", $x0, $x1, $x2')
    lines.append('#     continue')
    lines.append('# end')
    lines.append('')
    lines.append('printf "T盾 解密器跟踪已启动，解密器地址: 0x%x\\n"', decryptor_addr)
    lines.append('continue')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f'gdb 跟踪脚本已生成: {output_file}')
    print(f'  解密器地址: 0x{decryptor_addr:x}')
    print(f'  最大调用次数: {max_calls}')


def generate_frida_script(decryptor_addr, output_file):
    """生成 Frida 跟踪脚本"""
    script = f'''// T盾 统一解密器跟踪 Frida 脚本
// 自动生成
// 解密器地址: 0x{decryptor_addr:x}

const decryptorAddr = ptr("0x{decryptor_addr:x}");
let callCount = 0;
const funcIdMap = {{}};

Interceptor.attach(decryptorAddr, {{
    onEnter: function(args) {{
        callCount++;
        this.callId = callCount;
        
        const sp = this.context.sp;
        this.sp = sp;
        
        // 搜索函数ID（32位值，高32位为0）
        this.funcId = 0;
        for (let offset = 0; offset < 0x200; offset += 4) {{
            try {{
                const val = sp.add(offset).readU32();
                if (val > 0x10000 && val < 0xffffffff) {{
                    // 记录第一个可能的函数ID
                    if (this.funcId === 0) {{
                        this.funcId = val;
                        this.funcIdOffset = offset;
                    }}
                }}
            }} catch(e) {{}}
        }}
        
        console.log(`[Decryptor] #${{callCount}} funcId=0x${{this.funcId.toString(16)}} sp=${{sp}}`);
    }},
    
    onLeave: function(retval) {{
        const addr = retval;
        console.log(`[Decryptor] #${{this.callId}} -> decrypted at ${{addr}}`);
        
        // 记录映射
        if (this.funcId !== 0) {{
            if (!funcIdMap[this.funcId]) {{
                funcIdMap[this.funcId] = {{
                    funcId: this.funcId,
                    addr: addr.toString(),
                    count: 1,
                }};
                console.log(`[+] New function: ID=0x${{this.funcId.toString(16)}} addr=${{addr}}`);
                
                // dump 前64字节
                try {{
                    const code = addr.readByteArray(64);
                    console.log(hexdump(code, {{ offset: 0, length: 64, header: false, ansi: false }}));
                }} catch(e) {{}}
            }} else {{
                funcIdMap[this.funcId].count++;
            }}
        }}
    }}
}});

// 定期输出统计
setInterval(function() {{
    console.log(`\\n[*] Stats: ${{callCount}} calls, ${{Object.keys(funcIdMap).length}} unique functions`);
}}, 10000);

// 退出时输出映射表
process.on('detached', function() {{
    console.log("\\n=== Function ID Mapping ===");
    console.log("func_id,address,call_count");
    for (const funcId in funcIdMap) {{
        const info = funcIdMap[funcId];
        console.log(`0x${{parseInt(funcId).toString(16)}},${{info.addr}},${{info.count}}`);
    }}
}});

console.log("[+] T盾 解密器跟踪已启动");
console.log(`[+] 解密器地址: ${{decryptorAddr}}`);
'''

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(script)

    print(f'Frida 跟踪脚本已生成: {output_file}')
    print(f'  解密器地址: 0x{decryptor_addr:x}')


def parse_gdb_log(log_file, output_file=None):
    """解析 gdb 跟踪日志，提取函数ID映射"""
    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    # 提取每次调用的信息
    calls = []
    # 匹配 "=== Decryptor Call #N ==="
    call_pattern = re.compile(r'=== Decryptor Call #(\d+) ===')
    # 匹配栈内容
    stack_pattern = re.compile(r'0x([0-9a-f]+):\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)')

    call_matches = list(call_pattern.finditer(content))

    for i, match in enumerate(call_matches):
        call_num = int(match.group(1))
        # 获取这次调用到下一次调用之间的内容
        start = match.end()
        end = call_matches[i + 1].start() if i + 1 < len(call_matches) else len(content)
        section = content[start:end]

        # 提取栈上的值
        stack_values = []
        for sm in stack_pattern.finditer(section):
            stack_values.append(int(sm.group(2), 16))
            stack_values.append(int(sm.group(3), 16))

        # 寻找可能的函数ID（32位，高32位为0）
        func_id = 0
        for val in stack_values:
            if 0x10000 < val < 0xffffffff and (val >> 32) == 0:
                func_id = val
                break

        calls.append({
            'call_num': call_num,
            'func_id': func_id,
            'stack_values': stack_values[:16],  # 只保留前16个
        })

    # 统计唯一函数ID
    unique_funcs = {}
    for call in calls:
        fid = call['func_id']
        if fid != 0:
            if fid not in unique_funcs:
                unique_funcs[fid] = {'count': 0, 'first_call': call['call_num']}
            unique_funcs[fid]['count'] += 1

    result = {
        'total_calls': len(calls),
        'unique_functions': len(unique_funcs),
        'calls': calls,
        'function_mapping': {
            f'0x{k:08x}': v for k, v in sorted(unique_funcs.items())
        },
    }

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f'解析结果已保存: {output_file}')

    print(f'总调用次数: {len(calls)}')
    print(f'唯一函数ID: {len(unique_funcs)}')
    print()
    print('函数ID映射:')
    print(f'{"函数ID":>12} {"调用次数":>8} {"首次调用":>8}')
    print('-' * 40)
    for fid, info in sorted(unique_funcs.items()):
        print(f'0x{fid:08x} {info["count"]:>8} {info["first_call"]:>8}')

    return result


def main():
    parser = argparse.ArgumentParser(description='T盾 统一解密器动态跟踪辅助工具')
    parser.add_argument('--elf', help='ELF 文件路径（自动检测解密器地址）')
    parser.add_argument('--decryptor', help='统一解密器地址（十六进制）')
    parser.add_argument('--gdb-script', help='生成 gdb 跟踪脚本')
    parser.add_argument('--frida-script', help='生成 Frida 跟踪脚本')
    parser.add_argument('--parse-log', help='解析 gdb 跟踪日志')
    parser.add_argument('--output', help='输出文件')
    parser.add_argument('--max-calls', type=int, default=1000, help='最大跟踪调用次数')
    args = parser.parse_args()

    decryptor_addr = None

    if args.elf:
        try:
            elf = ELFParser(args.elf)
            decryptor_addr = find_decryptor(elf)
            if decryptor_addr:
                print(f'从 ELF 中检测到统一解密器: 0x{decryptor_addr:x}')
            else:
                print('警告: 未能从 ELF 中检测到统一解密器')
        except Exception as e:
            print(f'错误: {e}')

    if args.decryptor:
        decryptor_addr = int(args.decryptor, 16)

    if args.parse_log:
        parse_gdb_log(args.parse_log, args.output)
        return

    if not decryptor_addr:
        print('错误: 需要指定 --elf 或 --decryptor')
        parser.print_help()
        return

    if args.gdb_script:
        generate_gdb_script(decryptor_addr, args.gdb_script, args.max_calls)

    if args.frida_script:
        generate_frida_script(decryptor_addr, args.frida_script)

    if not args.gdb_script and not args.frida_script:
        print(f'统一解密器地址: 0x{decryptor_addr:x}')
        print('使用 --gdb-script 或 --frida-script 生成跟踪脚本')


if __name__ == '__main__':
    main()
