#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
# 分发内含魔改 bash 的产物时必须提供对应完整源码。
# -*- coding: utf-8 -*-
"""
elf_anti_disasm.py —— ELF anti-disassembly 后处理（与 v7_build.sh 5b 步骤同源）

作用：抹除「节区」这一层视图，使 GNU binutils 系列工具失去分析支点。
    readelf -S   → There are no sections in this file.
    objdump -d   → 0 条指令（GNU objdump 无节区表时不做线性反汇编）
    nm / objdump -t → 无符号可用

原理：ELF 有「两种视图」——
    · 链接视图（Linking view）：靠 Section Header Table，仅在链接/调试时用
    · 执行视图（Execution view）：靠 Program Header Table，加载器（ld.so / 内核）用它
  运行时只依赖执行视图，故整表抹零不影响程序行为。

【安全边界（必须如实告知，勿夸大）】
  本步骤只能挡住「依赖节区表的工具」：objdump / readelf / nm / gdb(符号部分)。
  Ghidra / IDA / radare2 / BinaryNinja / capstone 等基于 Program Header 做
  递归下降或线性反汇编的工具，**不受影响**（实测反汇编条数与处理前完全一致）。
  因此这是「抬高自动化批量分析门槛」，不是「消除静态分析能力」。

用法：
    python3 elf_anti_disasm.py <ELF文件>          # 原地处理
    python3 elf_anti_disasm.py <输入> -o <输出>   # 输出到新文件
    python3 elf_anti_disasm.py <ELF文件> --check  # 仅体检，不改写
"""
import struct
import sys


def process(data: bytearray) -> str:
    """抹除节区层视图，返回处理摘要。"""
    if data[:4] != b"\x7fELF":
        raise SystemExit("错误：不是 ELF 文件（magic 不符）")

    ei_class = data[4]
    if ei_class == 2:      # ELF64
        e_shoff, = struct.unpack_from("<Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        Shdr = 64
    elif ei_class == 1:    # ELF32
        e_shoff, = struct.unpack_from("<I", data, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x2E)
        Shdr = 40
    else:
        raise SystemExit("错误：未知 ELF class %d" % ei_class)

    if e_shoff == 0 or e_shnum == 0:
        return "已处理过（e_shoff=0 或 e_shnum=0），跳过"

    # 1) 整表抹零（含 .symtab/.strtab/.text 等元信息）
    table_end = e_shoff + e_shentsize * e_shnum
    if table_end <= len(data):
        for i in range(e_shoff, table_end):
            data[i] = 0
        wiped = table_end - e_shoff
    else:
        wiped = 0
        table_end = len(data)

    # 2) ELF header 内节区指针/计数清零（e_shentsize 一并清零，比 v7_build.sh 更彻底）
    if ei_class == 2:
        struct.pack_into("<Q", data, 0x28, 0)              # e_shoff
        struct.pack_into("<HHH", data, 0x3A, 0, 0, 0)      # e_shentsize, e_shnum, e_shstrndx
    else:
        struct.pack_into("<I", data, 0x20, 0)
        struct.pack_into("<HHH", data, 0x2E, 0, 0, 0)

    return ("抹除节区表 %d 字节 (0x%x..0x%x)，原 e_shnum=%d e_shentsize=%d e_shstrndx=%d"
            % (wiped, e_shoff, table_end, e_shnum, e_shentsize, e_shstrndx))


def check(path: str) -> int:
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF":
        print("%s: 非 ELF" % path); return 1
    if d[4] == 2:
        shoff, = struct.unpack_from("<Q", d, 0x28)
        _esz, shnum, _idx = struct.unpack_from("<HHH", d, 0x3A)
    else:
        shoff, = struct.unpack_from("<I", d, 0x20)
        _esz, shnum, _idx = struct.unpack_from("<HHH", d, 0x2E)
    ok = (shoff == 0 and shnum == 0)
    print("%s: %s (e_shoff=0x%x e_shnum=%d)" % (
        path, "✅ 已无节区视图" if ok else "❌ 仍保留节区视图", shoff, shnum))
    return 0 if ok else 1


def main(argv):
    path = out = None
    check_only = False
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-o":
            i += 1; out = argv[i]
        elif a == "--check":
            check_only = True
        elif a in ("-h", "--help"):
            sys.stdout.write(__doc__ or ""); return 0
        else:
            args.append(a)
        i += 1

    if not args:
        sys.stderr.write(__doc__ or "")
        return 2

    # 体检模式支持两种语序：<file> --check  与  --check <file>
    if check_only:
        return check(args[0])

    path = args[0]
    data = bytearray(open(path, "rb").read())
    print(process(data))
    target = out or path
    with open(target, "wb") as f:
        f.write(bytes(data))
    print("写出: %s (%d 字节，大小不变)" % (target, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
