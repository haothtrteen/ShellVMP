#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vmp_targets.py — 从 **已 strip / 已抹 section header** 的 ELF 里，
自动定位 TShell V7 的保护逻辑函数，输出 VMP/代码虚拟化的候选名单。

设计动机
--------
r10 的 anti-disassembly 后处理会做两件事：
    objcopy -R .symtab -R .strtab ... && strip --strip-all
    再把 e_shoff / e_shnum / e_shstrndx 清零
于是 IDA / Ghidra / VMP 工具打开后只会看到一片 sub_200040 / sub_200078 / …
2747 个函数里 2700+ 是静态链接进来的 libc / libgcc 噪音，
真正的保护逻辑只有十几个。本脚本就是把这十几个挑出来。

用法
----
    python3 vmp_targets.py Tshell.so.elf                 # 自动模式（启发式）
    python3 vmp_targets.py Tshell.so.elf --map x.map     # 有符号表时（推荐）
    python3 vmp_targets.py Tshell.so.elf --depth 3 --json out.json

生成符号表（必须在 strip 之前！）
--------------------------------
    readelf -sW build/Tshell.so.elf | awk '$4=="FUNC"{print "0x"$2, $3, $8}' > Tshell.so.map
或
    nm -S --defined-only build/Tshell.so.elf | awk '$2=="T"||$2=="t"{print "0x"$1,$2,$4}' > Tshell.so.map

输出三档：
    [MUST]   不保护就等于没保护 —— 密钥派生 / 完整性校验 / HMAC / SHA 压缩
    [SHOULD] 值得保护 —— 反调试、exec 路径、兜底落盘
    [SKIP]   千万别碰 —— libc / libgcc 静态链接噪音，VMP 后大概率崩或体积爆炸
"""

import argparse
import json
import re
import struct
import sys
from collections import defaultdict, deque

# --------------------------------------------------------------------------
# 1. ELF 解析（不依赖 section header —— 那玩意已经被我们清零了）
# --------------------------------------------------------------------------

class ELF:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        if d[:4] != b'\x7fELF':
            raise SystemExit('[!] 不是 ELF 文件')
        self.bits = 64 if d[4] == 2 else 32
        if self.bits == 64:
            (self.entry, self.phoff) = struct.unpack_from('<QQ', d, 24)
            (self.phentsize, self.phnum) = struct.unpack_from('<HH', d, 54)
        else:
            (self.entry, self.phoff) = struct.unpack_from('<II', d, 24)
            (self.phentsize, self.phnum) = struct.unpack_from('<HH', d, 42)
        self.segs = []
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            if self.bits == 64:
                p_type = struct.unpack_from('<I', d, o)[0]
                p_off, p_va, _pa, p_fsz, p_msz = struct.unpack_from('<QQQQQ', d, o + 8)
            else:
                p_type = struct.unpack_from('<I', d, o)[0]
                p_off, p_va, _pa, p_fsz, p_msz = struct.unpack_from('<IIII', d, o + 4)
            if p_type == 1:  # PT_LOAD
                self.segs.append(dict(off=p_off, va=p_va, fsz=p_fsz, msz=p_msz))
        self.exec_seg = None
        for s in self.segs:
            if s['fsz'] > 0:
                if self.exec_seg is None or s['fsz'] > self.exec_seg['fsz']:
                    self.exec_seg = s
        if self.exec_seg is None:
            raise SystemExit('[!] 找不到可执行的 PT_LOAD 段')

    def va2off(self, va):
        for s in self.segs:
            if s['va'] <= va < s['va'] + s['fsz']:
                return s['off'] + (va - s['va'])
        return None

    def rd(self, va, n):
        o = self.va2off(va)
        if o is None or o + n > len(self.d):
            return None
        return self.d[o:o + n]

    def find_all(self, pat):
        """在文件里搜字节串，返回虚拟地址列表"""
        out, i = [], 0
        while True:
            p = self.d.find(pat, i)
            if p < 0:
                break
            va = None
            for s in self.segs:
                if s['off'] <= p < s['off'] + s['fsz']:
                    va = p - s['off'] + s['va']
                    break
            if va is not None:
                out.append(va)
            i = p + 1
        return out


# --------------------------------------------------------------------------
# 2. 指令扫描：ADRP/ADD 常量引用 + BL 调用图
#    （纯位运算，不用 capstone，2.5MB 代码 2 秒扫完）
# --------------------------------------------------------------------------

def scan(elf):
    seg = elf.exec_seg
    base, off, size = seg['va'], seg['off'], seg['fsz']
    n = size // 4
    buf = elf.d[off:off + n * 4]
    words = struct.unpack('<%dI' % n, buf)

    const_refs = []          # (insn_va, target_va)
    calls = []               # (from_va, target_va)
    for i, w in enumerate(words):
        va = base + i * 4
        if (w & 0x9F000000) == 0x90000000:               # ADRP
            rd = w & 0x1F
            imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
            if imm & (1 << 20):
                imm -= (1 << 21)
            page = (va & ~0xFFF) + (imm << 12)
            for j in range(1, 13):                        # 向后找配对的 ADD
                if i + j >= n:
                    break
                w2 = words[i + j]
                if (w2 & 0x7F800000) == 0x11000000:       # ADD imm
                    if (w2 & 0x1F) == rd and ((w2 >> 5) & 0x1F) == rd:
                        imm12 = (w2 >> 10) & 0xFFF
                        if ((w2 >> 22) & 3) == 1:
                            imm12 <<= 12
                        const_refs.append((va, page + imm12))
                        break
                if (w2 & 0xFC000000) == 0x94000000:
                    break
        elif (w & 0xFC000000) == 0x94000000:              # BL
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            calls.append((va, va + imm26 * 4))

    # aarch64 标准序言：stp x29, x30, [sp, #imm]  /  stp x29, x30, [sp, #-imm]!
    prologues = []
    for i, w in enumerate(words):
        if (w & 0xFFC07FFF) in (0xA9007BFD, 0xA9807BFD, 0xA9A07BFD):
            prologues.append(base + i * 4)
    return const_refs, calls, prologues


# --------------------------------------------------------------------------
# 3. 特征库
# --------------------------------------------------------------------------

# 这些字符串是 elfrun.c 里的硬编码常量，绝大多数情况下能直接命中
FEATURE_STRINGS = {
    'V7ENC':            ('v7_keys 的加密密钥标签', 40),
    'V7MAC':            ('v7_keys 的认证密钥标签', 40),
    'TracerPid':        ('反调试：读取 proc status', 30),
    '/proc/self/status': ('反调试 / 自检', 30),
    # r10.3 新增：Level 3 的两个新函数无 map 时也必须能被直接锚定
    # （否则只能靠 main 调用闭包带出，档位会掉到 SHOULD 甚至"无特征"）
    'frida':            ('反调试⑤：frida 注入痕迹扫描', 28),
    'gum-js-loop':      ('frida gum 线程特征', 22),
    'linjector':        ('frida linjector 注入特征', 22),
    '/proc/%d/status':  ('执行期 TracerPid 轮询（子进程）', 26),
    'LD_PRELOAD':       ('反注入', 25),
    '/proc/self/fd':    ('memfd exec 路径', 20),
    '/data/local/tmp':  ('兜底落盘 exec', 20),
    '/data/data/com.termux': ('Termux 环境判定', 15),
    'memfd_create':     ('memfd 创建', 15),
    'V7PASS':           ('口令模式', 20),
    'V7WB':             ('白盒模式', 20),
    'BASH_ENV':         ('bash 环境封闭', 15),
    # r16：B 线魔改 bash（isa_hook.c 编译进 bash 二进制）的特征。
    # 'V7ISA' 是 isa 表 magic 常量（#define ISA_MAGIC），可锚定 isa_load；
    # 'V7_ISA_TABLE' 是 MVP 表装载环境变量名。
    'V7ISA':            ('isa 表 magic（B 线魔改 bash）', 40),
    'V7_ISA_TABLE':     ('isa 表装载环境变量', 20),
}

# SHA-256 K 表（小端存储的头 8 个 word）
K256 = b''.join(struct.pack('<I', v) for v in struct.unpack('>8I', bytes.fromhex(
    '428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5')))

# 只从 map 里挑这些前缀 —— 它们才是 TShell 自有代码
OWN_PREFIX = ('v7_', 'blob_', 'passkey_', 'traced', 'now_ms', 'main', 'xdec_',
              'anti_', '_am', 'die_', 'self_')

MUST_KEYWORDS = ('v7_keys', 'v7_crypt', 'v7_tag', 'v7_ct_eq', 'v7_wb_decode',
                 'v7_stream', 'v7_scrypt', 'v7_pbkdf2', 'blob_verify',
                 'blob_decrypt', 'passkey_derive', 'hmac', 'sha256', 'sha256_compress',
                 # r16：四层随机化表（isa_hook.c）—— 用户硬性验收项，
                 # 表数据 + 翻译逻辑一旦被旁路，随机化即等于明文
                 'v7_isa')
SHOULD_KEYWORDS = ('traced', 'blob_open', 'anti', 'now_ms', 'exec', 'spawn')


# --------------------------------------------------------------------------
# 4. 主流程
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument('elf')
    ap.add_argument('--map', default=None, help='strip 之前导出的符号表')
    ap.add_argument('--depth', type=int, default=2, help='从锚点向下追溯的调用层数')
    ap.add_argument('--json', default=None)
    ap.add_argument('--base', default=None, help='手动指定 IDA 里的 imagebase（默认取 PT_LOAD vaddr）')
    args = ap.parse_args()

    elf = ELF(args.elf)
    base = elf.exec_seg['va']
    print('[*] 架构      : %s-bit' % elf.bits)
    print('[*] entry     : 0x%x' % elf.entry)
    print('[*] imagebase : 0x%x  (exec PT_LOAD 0x%x, %d 字节)'
          % (base, base, elf.exec_seg['fsz']))

    print('[*] 扫描指令流 ...', file=sys.stderr)
    const_refs, calls, prologues = scan(elf)
    ref2insn = defaultdict(list)
    for insn, tgt in const_refs:
        ref2insn[tgt].append(insn)
    callers = defaultdict(list)
    for _src, t in calls:
        callers[t].append(_src)
    # 函数起点 = bl 目标 ∪ 标准序言 ∪ entry
    starts = sorted(set(t for _, t in calls) | set(prologues) | {elf.entry})
    # bl 目标落在 `sub sp,sp` 上、序言落在下一条 `stp x29,x30` 上 —— 会重复，
    # 挨得 ≤8 字节的合并成最小的那个
    merged = []
    for s in starts:
        if merged and s - merged[-1] <= 8:
            continue
        merged.append(s)
    starts = merged
    print('[*] ADRP/ADD 常量引用 %d 条，BL 调用 %d 处，函数起点 %d 个'
          % (len(const_refs), len(calls), len(starts)), file=sys.stderr)

    def func_of(va):
        """va 落在哪个函数里（按 bl 目标集合近似划分）"""
        import bisect
        i = bisect.bisect_right(starts, va) - 1
        if i < 0:
            return None
        return starts[i]

    def fsize(a):
        import bisect
        i = bisect.bisect_left(starts, a)
        return (starts[i + 1] - a) if i + 1 < len(starts) else 0

    # 调用边要按"函数 -> 函数"建，不能按"指令 -> 函数"
    callees = defaultdict(set)
    for src, t in calls:
        f = func_of(src)
        if f is not None:
            callees[f].add(t)

    # ---- 4a. 特征字符串定位 -------------------------------------------------
    print('\n' + '=' * 78)
    print(' 步骤 1  特征字符串定位')
    print('=' * 78)
    anchors = {}          # func_start -> {reason: score}
    hit_str = {}
    for s, (why, score) in FEATURE_STRINGS.items():
        for va in elf.find_all(s.encode()):
            hit_str.setdefault(s, []).append(va)
            for insn in ref2insn.get(va, []):
                f = func_of(insn)
                if f is None:
                    continue
                anchors.setdefault(f, {})
                anchors[f][s] = score
    if not hit_str:
        print(' [!] 一个特征串都没命中 —— 说明常量已经被混淆/加密，见文末建议')
    for s, vas in sorted(hit_str.items()):
        print('  %-22s @ %s' % (s, ', '.join('0x%x' % v for v in vas[:4])))

    # ---- 4b. SHA-256 K 表 ---------------------------------------------------
    kvas = elf.find_all(K256)
    for kv in kvas:
        for insn, tgt in const_refs:
            dist = abs(tgt - kv)
            if dist > 0x800:
                continue
            f = func_of(insn)
            if f is None:
                continue
            anchors.setdefault(f, {})
            # 精确命中表头 = 真的在跑 SHA-256；命中附近 = 可能只是同一页里的别的表
            anchors[f]['SHA256_K' if dist <= 0x100 else 'SHA~'] = 35 if dist <= 0x100 else 8
    print('  SHA-256 K 表         @ %s' % (', '.join('0x%x' % v for v in kvas) or '未找到'))

    # ---- 4c. 有符号表就直接翻译 ---------------------------------------------
    sym = {}
    if args.map:
        for line in open(args.map, errors='ignore'):
            p = line.split()
            if len(p) < 3:
                continue
            try:
                a = int(p[0], 16)
            except ValueError:
                continue
            sym[a] = p[-1]
        print('\n[*] 载入符号表 %d 条' % len(sym))

    # ---- 4d. 打分排序 -------------------------------------------------------
    print('\n' + '=' * 78)
    print(' 步骤 2  候选函数打分（MUST / SHOULD / SKIP）')
    print('=' * 78)

    def name_of(a):
        if a in sym:
            return sym[a]
        for cand in (a, a + 4):
            if cand in sym:
                return sym[cand]
        return 'sub_%X' % a

    # main = 命中特征字符串种类最多的那个函数（elfrun.c 的 main 里塞满了
    # 反调试 / 环境判定 / exec 路径，特征最集中，这个启发式非常稳）
    main_va = max(anchors, key=lambda f: (len(anchors[f]), -f)) if anchors else None
    if main_va is not None:
        print('\n  >> 判定 main = sub_%X  (0x%x, %d 字节, 命中 %d 类特征)'
              % (main_va, main_va, fsize(main_va), len(anchors[main_va])))

    scored = []
    for f, why in anchors.items():
        score = sum(why.values())
        nm = name_of(f)
        scored.append((score, f, nm, why))
    scored.sort(reverse=True, key=lambda x: x[0])

    grade = {}
    print('\n  %-12s %-10s %-8s %-6s %s' % ('地址', '大小', '被调次数', '档位', '命中特征'))
    print('  ' + '-' * 74)
    for score, f, nm, why in scored[:40]:
        cnt = len(callers.get(f, []))
        nml = nm.lower()
        strong = ('V7ENC' in why or 'V7MAC' in why or 'SHA256_K' in why
                  or any(k in nml for k in MUST_KEYWORDS))
        # 离 main 太远的几乎一定是静态链接进来的 libc/libgcc
        far = main_va is not None and abs(f - main_va) > 0x20000
        if strong and not far:
            g = 'MUST'
        elif far:
            g = 'SKIP'                    # 远在天边 —— libc 噪音
        elif cnt >= 8:
            g = 'SKIP'                    # 被到处调用 —— libc 工具函数
        elif strong:
            g = 'MUST'
        else:
            g = 'SHOULD'
        grade[f] = g
        print('  0x%-10x %-10d %-8d %-6s %s' % (f, fsize(f), cnt, g, ','.join(sorted(why))))

    # ---- 4e. 调用闭包 -------------------------------------------------------
    print('\n' + '=' * 78)
    print(' 步骤 3  从锚点向下 %d 层的调用闭包' % args.depth)
    print('=' * 78)
    roots = [f for score, f, nm, why in scored if grade.get(f) in ('MUST', 'SHOULD')]
    if main_va is not None and main_va not in roots:
        roots.append(main_va)
    seen, q = set(), deque()
    for r in roots:
        q.append((r, 0))
    closure = {}
    while q:
        f, dep = q.popleft()
        if f in closure and closure[f] <= dep:
            continue
        closure[f] = dep
        if dep >= args.depth:
            continue
        for c in callees.get(f, ()):
            if c not in closure:
                q.append((c, dep + 1))
    # 小于 64 字节的基本是 libc 的 getter / wrapper，去掉噪音
    small = [f for f in closure if fsize(f) < 64 and grade.get(f) != 'MUST']
    for f in small:
        closure.pop(f, None)
    print('  闭包规模 %d 个函数（全库 %d 个，占比 %.1f%%）'
          % (len(closure), len(starts), 100.0 * len(closure) / max(1, len(starts))))
    for f in sorted(closure):
        tag = ''
        if f not in anchors and f != main_va:
            tag = '  (无特征命中，由调用关系带出)'
        print('   depth=%d  0x%-10x sub_%X  size=%-7d %s%s'
              % (closure[f], f, f, fsize(f), sym.get(f, ''), tag))

    # ---- 4f. 结论 -----------------------------------------------------------
    print('\n' + '=' * 78)
    print(' 结论：VMP / 代码虚拟化 勾选清单')
    print('=' * 78)
    must = [f for f in closure if grade.get(f) == 'MUST']
    should = [f for f in closure if grade.get(f) == 'SHOULD']
    print('\n  [MUST] 必须保护（%d 个）' % len(must))
    for f in sorted(must):
        print('     sub_%X   (0x%x, %d 字节)  %s' % (f, f, fsize(f), sym.get(f, '')))
    print('\n  [SHOULD] 建议保护（%d 个）' % len(should))
    for f in sorted(should):
        print('     sub_%X   (0x%x, %d 字节)  %s' % (f, f, fsize(f), sym.get(f, '')))
    print('\n  [SKIP] 其余 %d 个 —— 静态链接的 libc / libgcc，别碰。'
          % (len(starts) - len(must) - len(should)))

    print("""
 ---------------------------------------------------------------------------
 三个提醒
 ---------------------------------------------------------------------------
 1) sub_ 命名的地址 = 函数第一条指令的虚拟地址。不同工具可能把起点定在
    `sub sp,sp` 还是 `stp x29,x30` 上，差 4 字节很正常；以"大小 + 命中特征"
    为准，别死磕地址末位。
 2) -O2 会把 static 的 v7_crypt / v7_tag / v7_wb_decode / v7_stream_xor /
    passkey_derive_seed 全部内联进 main。它们在函数列表里**不存在**，
    只能整块保护它们所在的宿主函数。想让它们独立可见，编译时要：
        -fno-inline -fno-inline-small-functions -fno-ipa-cp-clone
    或者给它们加 __attribute__((noinline))。
 3) VMP 之前先用 V7_RAND_LABEL=1 重新构建：
        V7_RAND_LABEL=1 bash v7/v7_build.sh app.sh out.elf
    它会把 "V7ENC"/"V7MAC"/".v7x."/V7_PASSFD 这些语义路标全部随机化，
    自查：strings out.elf | grep -E 'V7ENC|V7MAC|V7_PASS|\\.v7x\\.'  → 应为空
    再叠 V7_LABEL_OBF=1 连随机串都不进 rodata（运行时 XOR 解开）。
    TracerPid / LD_PRELOAD / /proc/self/status 是系统接口名，随机化不了，
    留在 strings 里属正常 —— 别拿它们当判断依据。
""")

    if args.json:
        json.dump(dict(must=['sub_%X' % f for f in sorted(must)],
                       should=['sub_%X' % f for f in sorted(should)],
                       detail={('sub_%X' % f): dict(va=f, size=fsize(f),
                                                    name=sym.get(f, ''),
                                                    grade=grade.get(f))
                               for f in closure}),
                  open(args.json, 'w'), indent=2)
        print('[*] 已写出 %s' % args.json)


if __name__ == '__main__':
    main()
