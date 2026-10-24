---
name: tshield-research
description: T盾/T-Protector Android ELF 加壳深度分析与脱壳。覆盖技术架构（函数级加密+Stub分发+统一解密器+OLLVM混淆）、识别特征、静态/动态分析流程、3 种脱壳方法（动态内存dump/Frida hook解密器/静态逆向）、ELF 修复、反调试绕过。触发词：T盾、T-Protector、T-Protector T、函数级加密、Stub 分发、统一解密器、ELF 脱壳、tshield。
agent_created: true
description_zh: 用于 tshield-research 相关工作流。
description_en: Skill for tshield-research workflows.
version: 1.0.0
author: Xiaotao
---

# T盾 / T-Protector 分析与脱壳

## 架构（一句话）

**函数级加密 + Stub 分发 + 统一解密器**：原 ELF 每个函数体被加密搬进高熵 payload 段，
原位置换成 5 条指令的 Stub（存函数 ID → `b` 到解密器），
解密器按 ID 查映射表解密到内存再跳过去执行。**函数第一次被调用时才解密。**

## 识别速查

| 特征 | 判据 |
|---|---|
| Section 极少 | 通常 4 个（NULL/.dynstr/.dynamic/.shstrtab），`readelf -S` |
| 入口是 5 指令 Stub | `str / mov / movk / str / b` |
| 所有函数都是 Stub | 入口模式相同，只有 32 位立即数（函数 ID）不同 |
| 统一解密器 | 所有 Stub 的 `b` 跳向同一处，被 OLLVM 混淆（ror/orn/eon/rev/ubfx） |
| 高熵 payload 段 | 熵 > 7.5 |
| `p_filesz << p_memsz` | 第一个 LOAD 段，`readelf -l` |
| 特征串 | `strings -a x \| grep -i T-Protector` |

满足 ≥3 条即可确认。上手先跑 `python3 scripts/tshield_analyzer.py sample.elf`。

## 工作流

```
1 识别        上面那张表 + tshield_analyzer.py
2 选路径      静态逆向（难） / 动态 dump（推荐） / Frida hook（需授权注入）
3 分析        静态 01-05 ｜ 动态 06-09
4 脱壳        10 / 11 / 12 三选一
5 修复        references/13-elf-repair.md
```

## References（按需读，别一次全开）

| 文件 | 内容 |
|---|---|
| `references/01-elf-structure-analysis.md` | ELF 结构深度分析 |
| `references/02-stub-pattern-analysis.md` | Stub 模式与函数 ID 提取 |
| `references/03-unified-decryptor-analysis.md` | 统一解密器逆向 |
| `references/04-mapping-table-analysis.md` | 函数 ID → 加密代码映射表 |
| `references/05-encryption-algorithm.md` | 加密算法逆向与复现 |
| `references/06-dynamic-environment.md` | 动态环境准备 |
| `references/07-runtime-memory-analysis.md` | `/proc/pid/maps` 与解密段定位 |
| `references/08-function-trigger-strategy.md` | 全功能触发（未调用的函数不解密） |
| `references/09-decryptor-dynamic-tracing.md` | 解密器动态跟踪 |
| `references/10-unpacking-dynamic-dump.md` | 动态 dump 脱壳（**推荐**） |
| `references/11-unpacking-frida-hook.md` | Frida hook 脱壳 |
| `references/12-unpacking-static-reverse.md` | 静态逆向脱壳 |
| `references/13-elf-repair.md` | ELF 头/PHDR/SHDR/重定位/导入表修复 |
| `references/14-anti-debug-and-bypass.md` | 反调试（ptrace/TracerPid/时间差）与绕过 |
| `references/15-case-study-t1-904.md` | 案例：T1_904_0414.sh（46MB ARM64） |
| `references/16-field-notes-jinli55.md` | 案例：CODM 杰尼龟55（45MB ARM64） |

## 脚本（scripts/）

`tshield_analyzer.py` 快速识别/Stub 提取/解密器定位/熵分析 ｜ `stub_extractor.py` 批量 Stub+ID ｜
`decryptor_trace.py` gdb 脚本生成 ｜ `elf_repair.py` 脱壳后修复 ｜
`memory_dumper.py` dump 工具 ｜ `frida_hook_decryptor.js` hook 模板

## ★ 换样本必改的三处（实测踩过）

参考样本（T1_904）用 `x13`，换样本照抄会得到 **0 个 Stub**：

1. **Stub 寄存器不固定** —— 杰尼龟55 用 `x7 / x15 / x25 / x28`。
   必须寄存器无关匹配（`decode_stub()` 已修）。写死某个 xN 必漏。
2. **解密器可能不止一个** —— 杰尼龟55 的 53 个 Stub 跳向 **5 个** OLLVM 块。
   只用入口点那个目标过滤会漏掉 4/5。
3. **`movk` 掩码** —— `0x72a0000d` 的正确掩码 `0xffe0001f`，
   写 `0xff80001f` 永远匹配不上。

**脱壳落点**：解密后代码在 **`base + 原vaddr`**，不在 `base + 原vaddr + <payload段偏移>`。
从 payload 段（如 LOAD[6]，偏移 `0x34F0000`）dump 出来的是**密文**。
验证方法：用 `.eh_frame_hdr` 恢复函数地址，正确 dump 的函数开头是
`paciasp / sub sp,sp,#N / stp x29,x30,[sp,#M]`，密文是乱码。

## 原则

- **当前构建映射**：所有偏移/地址从当前样本重新算，不跨样本复用
- **证据优先**：每个结论要有指令级/结构级/动态级证据
- **角色化命名**：按功能命名（unified_decryptor / function_stub / payload_table），不按地址

## 关联

走 T3 网络验证的样本 → 同级 `t3-kami-bypass` 包（卡密绕过，与脱壳是两件事）。
