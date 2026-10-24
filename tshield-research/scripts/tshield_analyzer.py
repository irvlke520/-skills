#!/usr/bin/env python3
"""
T盾 (T-Protector) Android ELF 专用分析器
基于真实样本 T1_904_0414.sh 的分析结果

功能：
1. 快速识别 T盾 加壳
2. ELF 结构分析（PHDR/SHDR/动态段）
3. Stub 模式识别与函数ID提取
4. 统一解密器定位
5. 熵分析
6. 生成分析报告

用法：
    python3 tshield_analyzer.py <elf_file>
    python3 tshield_analyzer.py <elf_file> --full
    python3 tshield_analyzer.py <elf_file> --report report.txt
"""

import sys
import struct
import argparse
import math
from collections import defaultdict

# ============================================================
# ELF 结构定义
# ============================================================

ELF_MAGIC = b'\x7fELF'

# e_type
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4

# e_machine
EM_NONE = 0
EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

# p_type
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552

# sh_type
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11

# d_tag
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33

# ============================================================
# ELF 解析器
# ============================================================

class ELFParser:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            self.data = f.read()
        self.size = len(self.data)
        self._parse_elf_header()
        self._parse_program_headers()
        self._parse_section_headers()
        self._parse_dynamic()

    def _parse_elf_header(self):
        """解析 ELF 头"""
        d = self.data
        if d[:4] != ELF_MAGIC:
            raise ValueError("Not an ELF file")

        self.ei_class = d[4]  # 1=32位, 2=64位
        self.ei_data = d[5]   # 1=小端, 2=大端
        self.ei_version = d[6]
        self.ei_osabi = d[7]

        if self.ei_class != 2:
            raise ValueError("Only 64-bit ELF supported")

        endian = '<' if self.ei_data == 1 else '>'
        self.endian = endian

        self.e_type = struct.unpack_from(endian + 'H', d, 0x10)[0]
        self.e_machine = struct.unpack_from(endian + 'H', d, 0x12)[0]
        self.e_version = struct.unpack_from(endian + 'I', d, 0x14)[0]
        self.e_entry = struct.unpack_from(endian + 'Q', d, 0x18)[0]
        self.e_phoff = struct.unpack_from(endian + 'Q', d, 0x20)[0]
        self.e_shoff = struct.unpack_from(endian + 'Q', d, 0x28)[0]
        self.e_flags = struct.unpack_from(endian + 'I', d, 0x30)[0]
        self.e_ehsize = struct.unpack_from(endian + 'H', d, 0x34)[0]
        self.e_phentsize = struct.unpack_from(endian + 'H', d, 0x36)[0]
        self.e_phnum = struct.unpack_from(endian + 'H', d, 0x38)[0]
        self.e_shentsize = struct.unpack_from(endian + 'H', d, 0x3a)[0]
        self.e_shnum = struct.unpack_from(endian + 'H', d, 0x3c)[0]
        self.e_shstrndx = struct.unpack_from(endian + 'H', d, 0x3e)[0]

    def _parse_program_headers(self):
        """解析 Program Headers"""
        self.phdrs = []
        e = self.endian
        for i in range(self.e_phnum):
            offset = self.e_phoff + i * self.e_phentsize
            d = self.data
            p_type = struct.unpack_from(e + 'I', d, offset)[0]
            p_flags = struct.unpack_from(e + 'I', d, offset + 4)[0]
            p_offset = struct.unpack_from(e + 'Q', d, offset + 8)[0]
            p_vaddr = struct.unpack_from(e + 'Q', d, offset + 16)[0]
            p_paddr = struct.unpack_from(e + 'Q', d, offset + 24)[0]
            p_filesz = struct.unpack_from(e + 'Q', d, offset + 32)[0]
            p_memsz = struct.unpack_from(e + 'Q', d, offset + 40)[0]
            p_align = struct.unpack_from(e + 'Q', d, offset + 48)[0]
            self.phdrs.append({
                'index': i,
                'p_type': p_type,
                'p_flags': p_flags,
                'p_offset': p_offset,
                'p_vaddr': p_vaddr,
                'p_paddr': p_paddr,
                'p_filesz': p_filesz,
                'p_memsz': p_memsz,
                'p_align': p_align,
            })

    def _parse_section_headers(self):
        """解析 Section Headers"""
        self.shdrs = []
        e = self.endian
        for i in range(self.e_shnum):
            offset = self.e_shoff + i * self.e_shentsize
            d = self.data
            sh_name = struct.unpack_from(e + 'I', d, offset)[0]
            sh_type = struct.unpack_from(e + 'I', d, offset + 4)[0]
            sh_flags = struct.unpack_from(e + 'Q', d, offset + 8)[0]
            sh_addr = struct.unpack_from(e + 'Q', d, offset + 16)[0]
            sh_offset = struct.unpack_from(e + 'Q', d, offset + 24)[0]
            sh_size = struct.unpack_from(e + 'Q', d, offset + 32)[0]
            sh_link = struct.unpack_from(e + 'I', d, offset + 40)[0]
            sh_info = struct.unpack_from(e + 'I', d, offset + 44)[0]
            sh_addralign = struct.unpack_from(e + 'Q', d, offset + 48)[0]
            sh_entsize = struct.unpack_from(e + 'Q', d, offset + 56)[0]
            self.shdrs.append({
                'index': i,
                'sh_name': sh_name,
                'sh_type': sh_type,
                'sh_flags': sh_flags,
                'sh_addr': sh_addr,
                'sh_offset': sh_offset,
                'sh_size': sh_size,
                'sh_link': sh_link,
                'sh_info': sh_info,
                'sh_addralign': sh_addralign,
                'sh_entsize': sh_entsize,
            })

        # 解析 section 名称
        if self.e_shstrndx < len(self.shdrs):
            shstr = self.shdrs[self.e_shstrndx]
            self.shstrtab = self.data[shstr['sh_offset']:shstr['sh_offset'] + shstr['sh_size']]
            for sh in self.shdrs:
                name_end = self.shstrtab.find(b'\x00', sh['sh_name'])
                if name_end == -1:
                    name_end = len(self.shstrtab)
                sh['name'] = self.shstrtab[sh['sh_name']:name_end].decode('utf-8', errors='replace')
        else:
            for sh in self.shdrs:
                sh['name'] = ''

    def _parse_dynamic(self):
        """解析动态段"""
        self.dynamic_entries = []
        self.dynstr = b''
        self.needed_libs = []
        self.preinit_array_addr = 0
        self.preinit_array_size = 0
        self.init_array_addr = 0
        self.init_array_size = 0

        # 找到 PT_DYNAMIC 段
        dyn_phdr = None
        for ph in self.phdrs:
            if ph['p_type'] == PT_DYNAMIC:
                dyn_phdr = ph
                break

        if not dyn_phdr:
            return

        e = self.endian
        offset = dyn_phdr['p_offset']
        size = dyn_phdr['p_filesz']

        i = 0
        while i < size:
            d_tag = struct.unpack_from(e + 'q', self.data, offset + i)[0]
            d_val = struct.unpack_from(e + 'Q', self.data, offset + i + 8)[0]
            self.dynamic_entries.append({'d_tag': d_tag, 'd_val': d_val})
            if d_tag == DT_NULL:
                break
            i += 16

        # 找到 .dynstr
        dynstr_addr = 0
        dynstr_size = 0
        for entry in self.dynamic_entries:
            if entry['d_tag'] == DT_STRTAB:
                dynstr_addr = entry['d_val']
            elif entry['d_tag'] == DT_STRSZ:
                dynstr_size = entry['d_val']
            elif entry['d_tag'] == DT_NEEDED:
                self.needed_libs.append(entry['d_val'])
            elif entry['d_tag'] == DT_PREINIT_ARRAY:
                self.preinit_array_addr = entry['d_val']
            elif entry['d_tag'] == DT_PREINIT_ARRAYSZ:
                self.preinit_array_size = entry['d_val']
            elif entry['d_tag'] == DT_INIT_ARRAY:
                self.init_array_addr = entry['d_val']
            elif entry['d_tag'] == DT_INIT_ARRAYSZ:
                self.init_array_size = entry['d_val']

        # 读取 .dynstr
        if dynstr_addr and dynstr_size:
            dynstr_offset = self._vaddr_to_offset(dynstr_addr)
            if dynstr_offset is not None:
                self.dynstr = self.data[dynstr_offset:dynstr_offset + dynstr_size]

        # 解析依赖库名称
        self.needed_lib_names = []
        for offset_idx in self.needed_libs:
            if offset_idx < len(self.dynstr):
                name_end = self.dynstr.find(b'\x00', offset_idx)
                if name_end == -1:
                    name_end = len(self.dynstr)
                name = self.dynstr[offset_idx:name_end].decode('utf-8', errors='replace')
                self.needed_lib_names.append(name)

    def _vaddr_to_offset(self, vaddr):
        """虚拟地址转文件偏移"""
        for ph in self.phdrs:
            if ph['p_type'] == PT_LOAD:
                if ph['p_vaddr'] <= vaddr < ph['p_vaddr'] + ph['p_filesz']:
                    return ph['p_offset'] + (vaddr - ph['p_vaddr'])
        return None

    def read_vaddr(self, vaddr, size):
        """从虚拟地址读取数据"""
        offset = self._vaddr_to_offset(vaddr)
        if offset is None:
            return None
        return self.data[offset:offset + size]

    def get_interp(self):
        """获取解释器路径"""
        for ph in self.phdrs:
            if ph['p_type'] == PT_INTERP:
                return self.data[ph['p_offset']:ph['p_offset'] + ph['p_filesz']].rstrip(b'\x00').decode('utf-8', errors='replace')
        return None


def decode_stub(insns, base_addr):
    """通用 T盾 Stub 解码（寄存器无关）。

    实测样本的 Stub 寄存器并不固定：参考样本用 x13，
    CODM 杰尼龟55 样本（45MB ARM64）用的是 x7 / x15 / x25 / x28。
    写成写死 x13 会一个 Stub 都扫不到。

    模式（Rt 任意）:
        str  xR, [sp,#-0x10]!
        mov  wR, #imm16
        movk wR, #imm16, lsl #16
        str  xR, [sp,#8]
        b    <统一解密器>
    返回 (func_id, decryptor_addr)，不匹配返回 None
    """
    if len(insns) < 5:
        return None
    i0, i1, i2, i3, i4 = insns[0], insns[1], insns[2], insns[3], insns[4]
    if (i0 & 0xffffffe0) != 0xf81f0fe0:      # str xR,[sp,#-0x10]!
        return None
    rt = i0 & 0x1f
    if (i1 & 0xff800000) != 0x52800000 or (i1 & 0x1f) != rt:   # mov wR,#imm16
        return None
    if (i2 & 0xffe00000) != 0x72a00000 or (i2 & 0x1f) != rt:   # movk wR,#imm16,lsl#16
        return None
    if (i3 & 0xffffffe0) != 0xf90007e0 or (i3 & 0x1f) != rt:   # str xR,[sp,#8]
        return None
    if (i4 & 0xfc000000) != 0x14000000:                         # b
        return None
    func_id = (((i2 >> 5) & 0xffff) << 16) | ((i1 >> 5) & 0xffff)
    disp = i4 & 0x03ffffff
    if disp & 0x02000000:
        disp -= 0x04000000
    return func_id, base_addr + 16 + disp * 4


# ============================================================
# T盾 识别
# ============================================================

class TShieldDetector:
    def __init__(self, elf):
        self.elf = elf
        self.features = []
        self.score = 0
        self._check_all()

    def _check_all(self):
        """执行所有检测"""
        self._check_section_count()
        self._check_entry_stub()
        self._check_load_segment()
        self._check_tprotector_string()
        self._check_preinit_stub()
        self._check_unified_decryptor()
        self._check_entropy()

    def _check_section_count(self):
        """检测1：Section 数量极少"""
        count = self.elf.e_shnum
        if count <= 6:
            self.features.append(('section_count', True, f'Section 数量={count}（正常20+，加壳特征）'))
            self.score += 20
        else:
            self.features.append(('section_count', False, f'Section 数量={count}'))

    def _check_entry_stub(self):
        """检测2：入口点是 5 指令 Stub"""
        entry = self.elf.e_entry
        code = self.elf.read_vaddr(entry, 20)
        if code is None or len(code) < 20:
            self.features.append(('entry_stub', False, '无法读取入口点代码'))
            return

        e = self.elf.endian
        insns = [struct.unpack_from(e + 'I', code, i * 4)[0] for i in range(5)]

        # 检查 Stub 模式：
        # str x13,[sp,#-16]! = 0xf81f0fed
        # mov w13,#imm16 = 0x52800000 | (imm16 << 5)
        # movk w13,#imm16,lsl#16 = 0x72a00000 | (imm16 << 5)
        # str x13,[sp,#8] = 0xf90007ed
        # b #offset = 0x14000000 | offset

        is_stub = False
        func_id = None
        decryptor_addr = None

        decoded = decode_stub(insns, entry)
        if decoded:
            is_stub = True
            func_id, decryptor_addr = decoded

        if is_stub:
            self.features.append(('entry_stub', True,
                f'入口点是5指令Stub，函数ID=0x{func_id:08x}，统一解密器=0x{decryptor_addr:x}'))
            self.score += 25
            self.entry_func_id = func_id
            self.decryptor_addr = decryptor_addr
        else:
            self.features.append(('entry_stub', False, '入口点不是标准Stub模式'))
            self.entry_func_id = None
            self.decryptor_addr = None

    def _check_load_segment(self):
        """检测3：第一个 LOAD 段 filesz << memsz"""
        for ph in self.elf.phdrs:
            if ph['p_type'] == PT_LOAD and ph['p_vaddr'] == 0:
                ratio = ph['p_memsz'] / max(ph['p_filesz'], 1)
                if ratio > 100:
                    self.features.append(('load_segment', True,
                        f'第一个LOAD段 filesz=0x{ph["p_filesz"]:x}, memsz=0x{ph["p_memsz"]:x}, 比值={ratio:.0f}x'))
                    self.score += 20
                else:
                    self.features.append(('load_segment', False,
                        f'第一个LOAD段 filesz=0x{ph["p_filesz"]:x}, memsz=0x{ph["p_memsz"]:x}'))
                return
        self.features.append(('load_segment', False, '未找到第一个LOAD段'))

    def _check_tprotector_string(self):
        """检测4：包含 T-Protector 字符串"""
        # 在整个文件中搜索
        found = False
        for keyword in [b'T-Protector', b'T_Protector', b'TProtector', b'tshield', b'TShield']:
            if keyword in self.elf.data:
                found = True
                self.features.append(('tprotector_string', True, f'找到字符串: {keyword.decode()}'))
                self.score += 15
                break
        if not found:
            self.features.append(('tprotector_string', False, '未找到 T-Protector 特征字符串'))

    def _check_preinit_stub(self):
        """检测5：PREINIT_ARRAY 也是 Stub"""
        if not self.elf.preinit_array_addr or not self.elf.preinit_array_size:
            self.features.append(('preinit_stub', False, '无 PREINIT_ARRAY'))
            return

        # 读取 PREINIT_ARRAY
        data = self.elf.read_vaddr(self.elf.preinit_array_addr, self.elf.preinit_array_size)
        if data is None:
            self.features.append(('preinit_stub', False, '无法读取 PREINIT_ARRAY'))
            return

        e = self.elf.endian
        count = self.elf.preinit_array_size // 8
        preinit_funcs = []
        for i in range(count):
            addr = struct.unpack_from(e + 'Q', data, i * 8)[0]
            if addr != 0 and addr != 0xffffffffffffffff:
                preinit_funcs.append(addr)

        if not preinit_funcs:
            self.features.append(('preinit_stub', False, 'PREINIT_ARRAY 为空'))
            return

        # 检查第一个 PREINIT 函数是否是 Stub
        first_func = preinit_funcs[0]
        code = self.elf.read_vaddr(first_func, 20)
        if code is None or len(code) < 20:
            self.features.append(('preinit_stub', False, '无法读取 PREINIT 函数代码'))
            return

        insns = [struct.unpack_from(e + 'I', code, i * 4)[0] for i in range(5)]
        decoded = decode_stub(insns, first_func)
        is_stub = decoded is not None

        if is_stub:
            func_id = decoded[0]
            self.features.append(('preinit_stub', True,
                f'PREINIT_ARRAY[0]=0x{first_func:x} 也是Stub，函数ID=0x{func_id:08x}'))
            self.score += 10
        else:
            self.features.append(('preinit_stub', False, 'PREINIT 函数不是Stub'))

    def _check_unified_decryptor(self):
        """检测6：统一解密器存在且被混淆"""
        if not hasattr(self, 'decryptor_addr') or self.decryptor_addr is None:
            self.features.append(('unified_decryptor', False, '未定位统一解密器'))
            return

        # 读取解密器前40条指令
        code = self.elf.read_vaddr(self.decryptor_addr, 160)
        if code is None or len(code) < 160:
            self.features.append(('unified_decryptor', False, '无法读取解密器代码'))
            return

        e = self.elf.endian
        insns = [struct.unpack_from(e + 'I', code, i * 4)[0] for i in range(40)]

        # 统计 OLLVM 混淆指令
        obfuscation_count = 0
        for insn in insns:
            # ror: 0x9ac00000 (32位) / 0x9ac00000 (64位)
            if (insn & 0xff800000) == 0x9ac00000:
                obfuscation_count += 1
            # orn: 0x2a200000 (32位) / 0xaa200000 (64位)
            elif (insn & 0xff200000) in (0x2a200000, 0xaa200000):
                obfuscation_count += 1
            # eon: 0x7a200000 (32位) / 0xca200000 (64位)
            elif (insn & 0xff200000) in (0x7a200000, 0xca200000):
                obfuscation_count += 1
            # rev: 0x5ac00000 (32位) / 0xdac00000 (64位)
            elif (insn & 0xffc00000) in (0x5ac00000, 0xdac00000):
                obfuscation_count += 1
            # ubfx: 0x53000000 (32位) / 0xd3000000 (64位)
            elif (insn & 0xffc00000) in (0x53000000, 0xd3000000):
                obfuscation_count += 1
            # neg: 0x4b0003e0 (32位) / 0xcb0003e0 (64位)
            elif (insn & 0xffffffe0) in (0x4b0003e0, 0xcb0003e0):
                obfuscation_count += 1

        if obfuscation_count >= 10:
            self.features.append(('unified_decryptor', True,
                f'统一解密器=0x{self.decryptor_addr:x}，前40条指令中{obfuscation_count}条是OLLVM混淆指令'))
            self.score += 10
        else:
            self.features.append(('unified_decryptor', False,
                f'统一解密器=0x{self.decryptor_addr:x}，混淆指令较少({obfuscation_count}/40)'))

    def _check_entropy(self):
        """检测7：高熵 payload 段"""
        max_entropy = 0
        max_entropy_seg = None
        for ph in self.elf.phdrs:
            if ph['p_type'] == PT_LOAD and ph['p_filesz'] > 0x10000:
                offset = ph['p_offset']
                size = min(ph['p_filesz'], 0x100000)  # 最多分析1MB
                data = self.elf.data[offset:offset + size]
                entropy = calculate_entropy(data)
                if entropy > max_entropy:
                    max_entropy = entropy
                    max_entropy_seg = ph

        if max_entropy > 7.5:
            self.features.append(('high_entropy', True,
                f'高熵段 vaddr=0x{max_entropy_seg["p_vaddr"]:x}, 熵={max_entropy:.2f} bits/byte（加密数据特征）'))
            self.score += 10
        else:
            self.features.append(('high_entropy', False, f'最高熵={max_entropy:.2f}'))

    def is_tshield(self):
        """判断是否是 T盾 加壳"""
        return self.score >= 60

    def get_verdict(self):
        """获取判定结果"""
        if self.score >= 80:
            return '高度确认是 T盾 / T-Protector 加壳'
        elif self.score >= 60:
            return '很可能是 T盾 / T-Protector 加壳'
        elif self.score >= 40:
            return '可能是某种加壳（T盾特征不完整）'
        else:
            return '未检测到 T盾 加壳特征'


# ============================================================
# 工具函数
# ============================================================

def calculate_entropy(data):
    """计算数据的熵（bits/byte）"""
    if not data:
        return 0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0
    length = len(data)
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def format_flags(flags):
    """格式化权限标志"""
    r = 'R' if flags & 4 else '-'
    w = 'W' if flags & 2 else '-'
    x = 'X' if flags & 1 else '-'
    return f'{r}{w}{x}'


def ptype_name(ptype):
    """Program Header 类型名称"""
    names = {
        PT_NULL: 'NULL', PT_LOAD: 'LOAD', PT_DYNAMIC: 'DYNAMIC',
        PT_INTERP: 'INTERP', PT_NOTE: 'NOTE', PT_SHLIB: 'SHLIB',
        PT_PHDR: 'PHDR', PT_TLS: 'TLS',
        PT_GNU_EH_FRAME: 'GNU_EH_FRAME', PT_GNU_STACK: 'GNU_STACK',
        PT_GNU_RELRO: 'GNU_RELRO',
    }
    return names.get(ptype, f'0x{ptype:x}')


def shtype_name(shtype):
    """Section 类型名称"""
    names = {
        SHT_NULL: 'NULL', SHT_PROGBITS: 'PROGBITS', SHT_SYMTAB: 'SYMTAB',
        SHT_STRTAB: 'STRTAB', SHT_RELA: 'RELA', SHT_HASH: 'HASH',
        SHT_DYNAMIC: 'DYNAMIC', SHT_NOTE: 'NOTE', SHT_NOBITS: 'NOBITS',
        SHT_REL: 'REL', SHT_SHLIB: 'SHLIB', SHT_DYNSYM: 'DYNSYM',
    }
    return names.get(shtype, f'0x{shtype:x}')


def machine_name(machine):
    """架构名称"""
    names = {
        EM_NONE: 'None', EM_386: 'x86', EM_ARM: 'ARM',
        EM_X86_64: 'x86_64', EM_AARCH64: 'AArch64 (ARM64)',
    }
    return names.get(machine, f'0x{machine:x}')


def etype_name(etype):
    """ELF 类型名称"""
    names = {
        ET_NONE: 'NONE', ET_REL: 'REL', ET_EXEC: 'EXEC',
        ET_DYN: 'DYN (PIE)', ET_CORE: 'CORE',
    }
    return names.get(etype, f'0x{etype:x}')


# ============================================================
# Stub 提取器
# ============================================================

class StubExtractor:
    """批量提取所有函数 Stub 和函数ID"""

    def __init__(self, elf):
        self.elf = elf
        self.stubs = []

    def scan_segment(self, vaddr, size, decryptor_addr=None):
        """扫描指定段中的所有 Stub"""
        data = self.elf.read_vaddr(vaddr, size)
        if data is None:
            return

        e = self.elf.endian
        count = len(data) // 4

        i = 0
        while i < count - 4:
            insns = [struct.unpack_from(e + 'I', data, (i + j) * 4)[0] for j in range(5)]

            # 检查是否是 Stub 模式
            if decode_stub(insns, 0) is not None:
                stub_vaddr = vaddr + i * 4
                func_id, target = decode_stub(insns, stub_vaddr)

                # 如果指定了解密器地址，只匹配跳转到该地址的 Stub
                if decryptor_addr is None or target == decryptor_addr:
                    self.stubs.append({
                        'vaddr': stub_vaddr,
                        'func_id': func_id,
                        'target': target,
                    })

                i += 5  # Stub 占5条指令
            else:
                i += 1

    def scan_all(self, decryptor_addr=None):
        """扫描所有可执行段中的 Stub"""
        self.stubs = []
        for ph in self.elf.phdrs:
            if ph['p_type'] == PT_LOAD and (ph['p_flags'] & 1) and ph['p_filesz'] > 0:
                self.scan_segment(ph['p_vaddr'], ph['p_filesz'], decryptor_addr)
        return self.stubs

    def get_stats(self):
        """获取统计信息"""
        if not self.stubs:
            return {'count': 0}
        func_ids = [s['func_id'] for s in self.stubs]
        return {
            'count': len(self.stubs),
            'unique_func_ids': len(set(func_ids)),
            'min_func_id': min(func_ids),
            'max_func_id': max(func_ids),
            'targets': list(set(s['target'] for s in self.stubs)),
        }


# ============================================================
# 主程序
# ============================================================

def print_basic_info(elf):
    """打印基本信息"""
    print('=' * 70)
    print('基本信息')
    print('=' * 70)
    print(f'文件: {elf.filepath}')
    print(f'大小: {elf.size:,} 字节 ({elf.size / 1024 / 1024:.2f} MB)')
    print(f'架构: {machine_name(elf.e_machine)}')
    print(f'类型: {etype_name(elf.e_type)}')
    print(f'字节序: {"小端" if elf.ei_data == 1 else "大端"}')
    print(f'入口点: 0x{elf.e_entry:x}')
    interp = elf.get_interp()
    if interp:
        print(f'解释器: {interp}')
    print(f'Program Headers: {elf.e_phnum} 个')
    print(f'Section Headers: {elf.e_shnum} 个')
    print()


def print_program_headers(elf):
    """打印 Program Headers"""
    print('=' * 70)
    print('Program Headers')
    print('=' * 70)
    print(f'{"#":>3} {"类型":<14} {"权限":<6} {"文件偏移":>12} {"虚拟地址":>12} {"文件大小":>12} {"内存大小":>12}')
    print('-' * 70)
    for ph in elf.phdrs:
        print(f'{ph["index"]:>3} {ptype_name(ph["p_type"]):<14} {format_flags(ph["p_flags"]):<6} '
              f'0x{ph["p_offset"]:010x} 0x{ph["p_vaddr"]:010x} '
              f'0x{ph["p_filesz"]:010x} 0x{ph["p_memsz"]:010x}')
    print()


def print_section_headers(elf):
    """打印 Section Headers"""
    print('=' * 70)
    print('Section Headers')
    print('=' * 70)
    print(f'{"#":>3} {"名称":<16} {"类型":<12} {"地址":>12} {"偏移":>12} {"大小":>12}')
    print('-' * 70)
    for sh in elf.shdrs:
        print(f'{sh["index"]:>3} {sh["name"]:<16} {shtype_name(sh["sh_type"]):<12} '
              f'0x{sh["sh_addr"]:010x} 0x{sh["sh_offset"]:010x} 0x{sh["sh_size"]:010x}')
    print()


def print_dynamic_info(elf):
    """打印动态段信息"""
    print('=' * 70)
    print('动态链接信息')
    print('=' * 70)
    if elf.needed_lib_names:
        print('依赖库:')
        for lib in elf.needed_lib_names:
            print(f'  - {lib}')
    if elf.preinit_array_addr:
        print(f'PREINIT_ARRAY: 0x{elf.preinit_array_addr:x} (大小: {elf.preinit_array_size} 字节)')
    if elf.init_array_addr:
        print(f'INIT_ARRAY: 0x{elf.init_array_addr:x} (大小: {elf.init_array_size} 字节)')
    print()


def print_tshield_detection(detector):
    """打印 T盾 检测结果"""
    print('=' * 70)
    print('T盾 (T-Protector) 检测')
    print('=' * 70)
    print(f'检测得分: {detector.score}/100')
    print(f'判定: {detector.get_verdict()}')
    print()
    print('检测项:')
    for name, matched, desc in detector.features:
        status = '[+]' if matched else '[-]'
        print(f'  {status} {desc}')
    print()


def print_stub_analysis(elf, detector):
    """打印 Stub 分析"""
    print('=' * 70)
    print('Stub 分析')
    print('=' * 70)

    decryptor_addr = getattr(detector, 'decryptor_addr', None)

    # 扫描所有 Stub
    extractor = StubExtractor(elf)
    stubs = extractor.scan_all(decryptor_addr)
    stats = extractor.get_stats()

    print(f'找到 Stub 数量: {stats.get("count", 0)}')
    print(f'唯一函数ID数量: {stats.get("unique_func_ids", 0)}')
    if stats.get('count', 0) > 0:
        print(f'函数ID范围: 0x{stats["min_func_id"]:08x} - 0x{stats["max_func_id"]:08x}')
        print(f'跳转目标: {[f"0x{t:x}" for t in stats.get("targets", [])]}')

    # 打印前10个 Stub
    if stubs:
        print()
        print('前10个 Stub:')
        print(f'{"虚拟地址":>12} {"函数ID":>10} {"跳转目标":>12}')
        for stub in stubs[:10]:
            print(f'0x{stub["vaddr"]:010x} 0x{stub["func_id"]:08x} 0x{stub["target"]:010x}')
        if len(stubs) > 10:
            print(f'... 还有 {len(stubs) - 10} 个')
    print()


def print_entropy_analysis(elf):
    """打印熵分析"""
    print('=' * 70)
    print('熵分析')
    print('=' * 70)
    print(f'{"段类型":<14} {"虚拟地址":>12} {"大小":>12} {"熵(bits/byte)":>14}')
    print('-' * 70)
    for ph in elf.phdrs:
        if ph['p_type'] == PT_LOAD and ph['p_filesz'] > 0:
            offset = ph['p_offset']
            size = min(ph['p_filesz'], 0x100000)
            data = elf.data[offset:offset + size]
            entropy = calculate_entropy(data)
            level = '高熵(加密)' if entropy > 7.5 else ('中熵' if entropy > 6 else '低熵(明文)')
            print(f'{ptype_name(ph["p_type"]):<14} 0x{ph["p_vaddr"]:010x} '
                  f'0x{ph["p_filesz"]:010x} {entropy:>10.2f}  {level}')
    print()


def print_unpacking_guide(detector, elf):
    """打印脱壳建议"""
    print('=' * 70)
    print('脱壳方向建议')
    print('=' * 70)

    if not detector.is_tshield():
        print('未检测到 T盾 加壳，无需脱壳。')
        print()
        return

    print('推荐方法：动态内存 Dump')
    print('  1. 在 Android 模拟器/真机上运行程序')
    print('  2. 触发所有功能（让所有函数被解密）')
    print('  3. dump 解密后代码段（运行时分配的匿名 r-xp 段）')
    print('  4. 修复 ELF 结构')
    print('  5. 用 IDA/Ghidra 加载验证')
    print()

    decryptor_addr = getattr(detector, 'decryptor_addr', None)
    if decryptor_addr:
        print(f'统一解密器地址: 0x{decryptor_addr:x}')
        print('  - 可以用 gdb 在该地址下断点，跟踪函数解密过程')
        print('  - 可以用 Frida hook 该地址，批量收集解密后的函数')
        print()

    # 找到解密后代码段（filesz=0, memsz>0, RE）
    for ph in elf.phdrs:
        if (ph['p_type'] == PT_LOAD and ph['p_filesz'] == 0 and
            ph['p_memsz'] > 0x10000 and (ph['p_flags'] & 1)):
            print(f'解密后代码段（运行时填充）:')
            print(f'  虚拟地址: 0x{ph["p_vaddr"]:x} - 0x{ph["p_vaddr"] + ph["p_memsz"]:x}')
            print(f'  大小: {ph["p_memsz"]:,} 字节 ({ph["p_memsz"] / 1024 / 1024:.2f} MB)')
            print(f'  权限: {format_flags(ph["p_flags"])}')
            print()
            break

    print('详细脱壳步骤请参考 references/10-unpacking-dynamic-dump.md')
    print('ELF 修复请参考 references/13-elf-repair.md')
    print()


def main():
    parser = argparse.ArgumentParser(description='T盾 (T-Protector) Android ELF 专用分析器')
    parser.add_argument('elf_file', help='要分析的 ELF 文件路径')
    parser.add_argument('--full', action='store_true', help='完整分析（包括所有段的详细信息）')
    parser.add_argument('--report', help='将分析报告保存到文件')
    parser.add_argument('--stubs', action='store_true', help='仅扫描所有 Stub')
    args = parser.parse_args()

    try:
        elf = ELFParser(args.elf_file)
    except Exception as e:
        print(f'错误: 无法解析 ELF 文件: {e}')
        sys.exit(1)

    detector = TShieldDetector(elf)

    # 如果指定了报告文件，重定向输出
    output_file = None
    if args.report:
        output_file = open(args.report, 'w', encoding='utf-8')
        import sys as _sys
        _sys.stdout = output_file

    try:
        print_basic_info(elf)
        print_tshield_detection(detector)

        if args.stubs:
            print_stub_analysis(elf, detector)
        else:
            print_program_headers(elf)
            print_section_headers(elf)
            print_dynamic_info(elf)
            print_stub_analysis(elf, detector)
            print_entropy_analysis(elf)
            print_unpacking_guide(detector, elf)

        if args.full:
            # 完整分析：打印所有动态段条目
            print('=' * 70)
            print('动态段详细条目')
            print('=' * 70)
            dt_names = {
                DT_NULL: 'NULL', DT_NEEDED: 'NEEDED', DT_PLTRELSZ: 'PLTRELSZ',
                DT_PLTGOT: 'PLTGOT', DT_HASH: 'HASH', DT_STRTAB: 'STRTAB',
                DT_SYMTAB: 'SYMTAB', DT_RELA: 'RELA', DT_RELASZ: 'RELASZ',
                DT_RELAENT: 'RELAENT', DT_STRSZ: 'STRSZ', DT_SYMENT: 'SYMENT',
                DT_INIT: 'INIT', DT_FINI: 'FINI', DT_SONAME: 'SONAME',
                DT_INIT_ARRAY: 'INIT_ARRAY', DT_FINI_ARRAY: 'FINI_ARRAY',
                DT_INIT_ARRAYSZ: 'INIT_ARRAYSZ', DT_FINI_ARRAYSZ: 'FINI_ARRAYSZ',
                DT_PREINIT_ARRAY: 'PREINIT_ARRAY', DT_PREINIT_ARRAYSZ: 'PREINIT_ARRAYSZ',
            }
            for entry in elf.dynamic_entries:
                name = dt_names.get(entry['d_tag'], f'0x{entry["d_tag"]:x}')
                print(f'  {name:<20} = 0x{entry["d_val"]:x}')
            print()

    finally:
        if output_file:
            output_file.close()

    # 如果检测到 T盾，返回退出码 0；否则返回 1
    sys.exit(0 if detector.is_tshield() else 1)


if __name__ == '__main__':
    main()
