#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# -*- coding: utf-8 -*-
"""
vmp_apply.py —— TShell × VMPacker 自动化保护脚本

把 V7 产物中的保护逻辑（crypto / 校验 / 反调试 / 解密）批量交给 VMPacker 虚拟化。

前置条件：
  1. 用 V7_VMP=1 构建产物（自动开 V7_NOINLINE=1 + -mgeneral-regs-only）：
       V7_VMP=1 V7_CC=aarch64-linux-gnu-gcc bash v7/v7_build.sh app.sh out.elf
  2. 构建会同时产出 out.elf.map（地址 名字），本脚本靠它定位函数。

为什么必须先 V7_VMP=1：
  - V7_NOINLINE=1  → 关键函数不被 -O2 内联进 main，才"存在"为独立函数
  - -mgeneral-regs-only → 运行时代码零 NEON/FP 指令；VMPacker 的 VM 只有
    通用寄存器(GPR)，遇到 q/d/v/s 类指令会直接 abort 拒绝保护

用法:
  python3 tools/vmp_apply.py out.elf                      # 保护默认目标集
  python3 tools/vmp_apply.py out.elf --dry-run            # 只列出要保护什么
  python3 tools/vmp_apply.py out.elf --list               # 列出符号表里所有候选
  python3 tools/vmp_apply.py out.elf --check-neon         # 只做 NEON 体检
  python3 tools/vmp_apply.py out.elf -o out.vmp.elf --vmpacker /path/to/vmpacker
  python3 tools/vmp_apply.py out.elf --include "v7_keys,v7_tag"   # 只保护指定函数
  python3 tools/vmp_apply.py out.elf --qemu qemu-aarch64-static --run-args "--help"
"""

import argparse
import os
import re
import subprocess
import sys

# 默认保护目标：TShell 的信任链核心
# 命中规则按"函数名前缀/子串"匹配（map 里可能是 v7_keys.constprop.0 这种带后缀的）
DEFAULT_PATTERNS = [
    r'v7_keys',            # 密钥派生根（K_enc/K_mac）
    r'v7_tag',             # HMAC 标签计算
    r'v7_crypt',           # 加解密主体
    r'v7_keystream',       # 密钥流
    r'v7_stream_init',     # 流式解密初始化
    r'v7_stream_xor',      # 流式解密 XOR
    r'v7_scrypt_kdf',      # 内存硬 KDF
    r'v7_wb_decode',       # 白盒解混淆
    r'blob_verify',        # 完整性校验（Encrypt-then-MAC）
    r'blob_decrypt_to_fd', # 分块解密落 memfd（r10.3 起仅内嵌 bash 走这条）
    # r10.3 Level2：骨架流式解密直写 pipe —— 核心机密路径，必须可单独保护
    r'blob_decrypt_to_pipe',
    r'passkey_derive_seed',# 口令派生
    # r10.3：用 traced$ 而非 ^traced$ —— 同时覆盖 traced（自身 TracerPid）
    # 与 child_being_traced（执行期子进程 TracerPid 轮询）
    r'traced$',            # 反调试 TracerPid（含 child_being_traced）
    r'anti_frida',         # 反调试⑤：frida 注入痕迹扫描
    r'hmac_sha256',        # HMAC
    r'sha256_compress',    # SHA-256 压缩函数
    # r16：B 线魔改 bash 的四层随机化表（isa_hook.c，用户硬性验收项）。
    # v7_isa_init / v7_isa_translate_cmd / v7_isa_translate_kw 三个全局函数
    # 跨 TU 不内联，map 里按前缀即可全命中；static isa_load 会被 -O2
    # 内联进 v7_isa_init，随宿主一起虚拟化，无需单列。
    r'v7_isa_init',
    r'v7_isa_translate',
]

# 明确排除：libc / libgcc 噪音 + 明显不是保护逻辑的
EXCLUDE_PATTERNS = [
    r'^_', r'^__', r'^\.', r'^frame_dummy', r'^deregister_tm', r'^register_tm',
]

# NEON / FP 判定：capstone 解码后出现这些寄存器或指令即视为含 NEON
NEON_MNEMONICS = re.compile(
    r'^(movi|fmov|fadd|fsub|fmul|fdiv|fabs|fneg|fsqrt|fmadd|fmsub|fnmadd|fnmsub|'
    r'fcmp|fsel|fcvt\w*|scvtf|ucvtf|fcvtzs|fcvtzu|fccmp\w*|fcsel|'
    r'ins|dup|ext|tbl|tbx|uzp|zip|trn|rev|addv|smaxv|uminv|'  # 仅 NEON 变体出现时再看寄存器
    r')$', re.I)
NEON_REG = re.compile(r'\b[qdvs](\d+|[0-9]+)\b', re.I)


def load_map(path):
    """读取 out.elf.map（格式: 0x地址 名字），返回 [(addr:int, name:str)]"""
    syms = []
    with open(path, 'r', errors='replace') as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split()
            if len(parts) < 2:
                continue
            try:
                a = int(parts[0], 16)
            except ValueError:
                continue
            syms.append((a, parts[1]))
    syms.sort(key=lambda x: x[0])
    return syms


def func_end(syms, idx):
    """函数结束地址 = 下一个符号地址（数值相邻）。
    这只是【硬上界】，真实边界由 detect_func_end() 用反汇编精修。"""
    if idx + 1 < len(syms):
        return syms[idx + 1][0]
    return syms[idx][0] + 0x200   # 最后一个不知道边界，保守猜


def detect_func_end(elf_path, load_off, start, hard_limit):
    """用反汇编精修函数结束地址。

    为什么不能直接用"下一个符号地址"当结束：符号表里两个相邻符号之间，
    可能夹着【没有符号的本地函数】（gcc 会给静态/冷路径函数生成无名或使用
    .constprop/.isra/.part 后缀的符号，且我们的 .map 可能未收录全部）。
    实测 traced 的下一个符号是 0x400DD0，但 0x400CD0 就是另一个函数的序言
    （stp x29,x30,[sp,#-0x40]!）—— 若把整段圈进去，VMPacker 会把那个无辜函数
    一起加密/替换，运行时落到被加密的指令上直接 SIGILL(rc=132)。

    判定：从 start 起扫指令，遇到【新函数序言】（stp x29,x30... 且 addr>start）
    立即停止，返回最后一个 ret 之后的位置。
    """
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        return hard_limit, 'no-capstone'

    code = read_range(elf_path, load_off, start, hard_limit)
    if not code:
        return hard_limit, 'no-code'

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    last_ret_end = None
    # 只认【预索引】形式 stp x29, x30, [sp, #-N]! —— 这才是真正的栈帧建立。
    # 不能只匹配 "x29, x30"：有些函数自己的序言是
    #   sub sp, sp, #N ; stp x29, x30, [sp, #M]      ← 非预索引
    # 若按宽松匹配，本函数自己的序言会被当成"下一个函数"而提前截断
    # （实测 hmac_sha256 被截成 12 字节就是这个坑）。
    prologue = re.compile(r'^x29,\s*x30,\s*\[sp,\s*#-')
    for i in md.disasm(code, start):
        # 新函数序言：不是本函数开头那条
        if i.mnemonic == 'stp' and prologue.match(i.op_str or '') and i.address > start:
            if last_ret_end:
                return last_ret_end, 'prologue@0x%x' % i.address
            return i.address, 'prologue@0x%x(no-ret)' % i.address
        if i.mnemonic == 'ret':
            last_ret_end = i.address + 4
    return (last_ret_end or hard_limit), 'hard-limit'


def read_range(elf_path, load_off, va_start, va_end):
    """按 vaddr 读文件字节。load_off: vaddr→file offset 的差值"""
    s = va_start - load_off
    e = va_end - load_off
    if s < 0 or e < s:
        return b''
    with open(elf_path, 'rb') as f:
        f.seek(s)
        return f.read(e - s)


def elf_image_end(elf_path):
    """返回 ELF 本体（所有 PT_LOAD 段）在文件中的结束偏移。

    B 线（单进程 bash）产物把 blob v3 密文**追加在 ELF 段之后**，
    zread 层靠 /proc/self/exe 读到文件尾来解密。VMPacker 重写 ELF 时
    只输出自己的 image，会**丢掉这段尾部附加数据** → 产物必然 rc=114。
    本函数用于识别这类"ELF + 尾附数据"布局，以便保护后原样接回。"""
    import struct
    with open(elf_path, 'rb') as f:
        d = f.read(64)
    if len(d) < 64 or d[:4] != b'\x7fELF':
        sys.exit('[!] 不是 ELF: %s' % elf_path)
    is64 = d[4] == 2
    with open(elf_path, 'rb') as f:
        if is64:
            e_phoff = struct.unpack_from('<Q', d, 32)[0]
            e_phentsize = struct.unpack_from('<H', d, 54)[0]
            e_phnum = struct.unpack_from('<H', d, 56)[0]
            f.seek(e_phoff)
            ph = f.read(e_phentsize * e_phnum)
            end = 0
            for i in range(e_phnum):
                o = i * e_phentsize
                if struct.unpack_from('<I', ph, o)[0] != 1:   # 只要 PT_LOAD
                    continue
                p_offset = struct.unpack_from('<Q', ph, o + 8)[0]
                p_filesz = struct.unpack_from('<Q', ph, o + 32)[0]
                end = max(end, p_offset + p_filesz)
            return end
        # 32 位：PT_LOAD 偏移不同（p_offset@4 p_filesz@16）
        e_phoff = struct.unpack_from('<I', d, 28)[0]
        e_phentsize = struct.unpack_from('<H', d, 42)[0]
        e_phnum = struct.unpack_from('<H', d, 44)[0]
        f.seek(e_phoff)
        ph = f.read(e_phentsize * e_phnum)
        end = 0
        for i in range(e_phnum):
            o = i * e_phentsize
            if struct.unpack_from('<I', ph, o)[0] != 1:
                continue
            p_offset = struct.unpack_from('<I', ph, o + 4)[0]
            p_filesz = struct.unpack_from('<I', ph, o + 16)[0]
            end = max(end, p_offset + p_filesz)
        return end


def read_tail_attachment(elf_path, verbose=True):
    """读出 ELF 段之后的尾部附加数据（blob）。无附加数据则返回 b''。

    这是 B 线产物的核心载荷所在：VMPacker 只认识 ELF image，
    保护后必须由本脚本把这段原样接回，否则产物直接坏掉。"""
    end = elf_image_end(elf_path)
    size = os.path.getsize(elf_path)
    if size <= end:
        return b''
    with open(elf_path, 'rb') as f:
        f.seek(end)
        tail = f.read(size - end)
    if verbose:
        print('[i] 检测到 ELF 尾部附加数据 %d 字节（B 线 blob；保护后自动接回）'
              % len(tail))
    return tail


def reattach_tail(protected_path, tail, verbose=True):
    """把 tail 接回保护后的产物末尾。

    注意：VMPacker 输出的 image 结束位置可能与原产物不同
    （它会把新段追加在文件尾），所以这里**按保护后产物自身的段边界**
    重新计算附加点，而不是沿用旧偏移。"""
    if not tail:
        return
    end = elf_image_end(protected_path)
    with open(protected_path, 'r+b') as f:
        f.seek(end)
        f.write(tail)
        f.truncate()
    if verbose:
        print('[+] 已接回尾部附加数据 %d 字节 → %s'
              % (len(tail), protected_path))


def get_load_offset(elf_path):
    """取可执行 PT_LOAD 的 (vaddr - offset)，用于 vaddr→文件偏移换算"""
    import struct
    with open(elf_path, 'rb') as f:
        d = f.read(64)
    if len(d) < 64 or d[:4] != b'\x7fELF':
        sys.exit('[!] 不是 ELF: %s' % elf_path)
    is64 = d[4] == 2
    if is64:
        e_phoff = struct.unpack_from('<Q', d, 32)[0]
        e_phentsize = struct.unpack_from('<H', d, 54)[0]
        e_phnum = struct.unpack_from('<H', d, 56)[0]
        with open(elf_path, 'rb') as f:
            f.seek(e_phoff)
            ph = f.read(e_phentsize * e_phnum)
        for i in range(e_phnum):
            o = i * e_phentsize
            p_type = struct.unpack_from('<I', ph, o)[0]
            if p_type != 1:
                continue
            p_offset = struct.unpack_from('<Q', ph, o + 8)[0]
            p_vaddr = struct.unpack_from('<Q', ph, o + 16)[0]
            p_flags = struct.unpack_from('<I', ph, o + 4)[0]
            if p_flags & 1:      # PT_LOAD 可执行
                return p_vaddr - p_offset
    return 0


def scan_neon(elf_path, load_off, va_start, va_end):
    """用 capstone 扫描函数区间，返回 (是否含NEON, 指令总数, NEON指令样例)"""
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        return (None, 0, [])     # 没装 capstone，跳过检查

    code = read_range(elf_path, load_off, va_start, va_end)
    if not code:
        return (None, 0, [])
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    total, neon_hits = 0, []
    for i in md.disasm(code, va_start):
        total += 1
        op = i.op_str or ''
        # 判定：寄存器以 q/d/v/s 开头（排除常规 x/w 寄存器），或助记符是 FP/NEON 专有
        if NEON_REG.search(op) or NEON_MNEMONICS.match(i.mnemonic or ''):
            if len(neon_hits) < 5:
                neon_hits.append('0x%x %s %s' % (i.address, i.mnemonic, op))
    return (len(neon_hits) > 0, total, neon_hits)


def run_baseline(qemu, elf, run_args, passkey=None, extra_env=None, self_mode=True):
    """基线运行：记录原产物的 (rc, stdout, stderr)，作为行为对比基准。
    qemu 可选：不传则直接运行本机二进制（Termux 原生 aarch64 场景）。
    用干净环境（避免宿主 LD_PRELOAD 之类干扰反调试检测）。

    self_mode：注入 V7_SELF=1。B 线（单进程魔改 bash）**必须**有该变量
    才会激活透明解密（zread.c 里 `if (getenv("V7_SELF") == NULL) return;`）；
    缺了它 bash 就退化成普通解释器，把喂进去的 passkey 当命令执行
    （表现为 `line 1: xxx: command not found` + rc=127），基线完全失真。

    passkey：B 线内层 passkey（V6 密钥分离）。该口令走 **stdin**，
    不是环境变量；不喂它时产物只会走到"缺 passkey"分支。
    extra_env：追加环境变量（如 B 线外层口令 V7_PASS）。"""
    cmd = []
    if qemu:
        cmd.append(qemu)
    cmd.append(elf)
    cmd.extend(run_args.split())
    env = {'V7_DIAG': '1', 'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
    if self_mode:
        env['V7_SELF'] = '1'
    if extra_env:
        env.update(extra_env)
    stdin_data = None
    if passkey is not None:
        stdin_data = (passkey + '\n').encode()
    try:
        if stdin_data is None:
            r = subprocess.run(cmd, capture_output=True, env=env, timeout=90,
                               stdin=subprocess.DEVNULL)
        else:
            r = subprocess.run(cmd, capture_output=True, env=env, timeout=90,
                               input=stdin_data)
    except OSError as e:
        if e.errno == 8:    # Exec format error
            sys.exit('[!] 产物与本机架构不符，无法直接运行。\n'
                     '    x86 主机请加 --qemu qemu-aarch64-static；'
                     'Termux/真机 aarch64 原生可跑，不用 --qemu。')
        raise
    out = r.stdout.decode('utf-8', 'replace') if isinstance(r.stdout, bytes) else r.stdout
    err = r.stderr.decode('utf-8', 'replace') if isinstance(r.stderr, bytes) else r.stderr
    return (r.returncode, out, err)


def _norm(s):
    """归一化非确定性输出：计时（4ms→Nms）、memfd 编号等。
    否则每次运行 stderr 都不一样，所有函数被误判'行为变化'。"""
    if not s:
        return s
    s = re.sub(r'（\d+ms）', '（Nms）', s)
    s = re.sub(r'\(\d+ms\)', '(Nms)', s)
    s = re.sub(r'\d+ms', 'Nms', s)
    s = re.sub(r'memfd=(\d+)', 'memfd=N', s)
    s = re.sub(r'fd=(\d+)', 'fd=N', s)
    s = _strip_env_noise(s)
    return s


# qemu-user 环境噪音：模拟器对 getcwd/chdir 的处理与真机不一致，
# 会让被模拟的 bash 刷出成百上千行 "cannot access parent directories"。
# 这属于**模拟器缺陷**，与产物行为无关；不清掉它，--verify 的 stderr
# 逐字节比对必然全部失败（实测 900+ 行且行数随环境浮动）。
_ENV_NOISE = re.compile(
    r'^.*(?:shell-init|job-working-directory|error retrieving current directory'
    r'|cannot access parent directories).*$\n?',
    re.M)


def _strip_env_noise(s):
    """剔除模拟器/宿主的 cwd 噪音行，只保留产物自身输出。"""
    if not s:
        return s
    return _ENV_NOISE.sub('', s)


def verify_one(qemu, elf, specs, run_args, baseline, workdir, vmpacker,
               tail=b'', passkey=None, extra_env=None, self_mode=True):
    """对单个函数做保护+运行验证，返回 (是否通过, 输出文件, 失败原因)。

    tail：原产物 ELF 段之后的附加数据（B 线 blob）。VMPacker 会丢弃它，
    这里必须接回，否则每个候选函数都会因"缺 blob"被误判为破坏行为。"""
    out = os.path.join(workdir, 'try_%d.elf' % abs(hash(specs)) )
    out = out.replace('-', '_')
    if os.path.exists(out):
        os.remove(out)
    cmd = [vmpacker, '-addr', specs, '-o', out, elf]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, None, 'vmpacker 超时'
    if r.returncode != 0 or not os.path.isfile(out):
        return False, None, 'vmpacker rc=%d %s' % (
            r.returncode, (r.stderr or r.stdout or '').strip().splitlines()[-1][:100]
            if (r.stderr or r.stdout) else '')
    reattach_tail(out, tail, verbose=False)
    try:
        env = {'V7_DIAG': '1',
               'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
               'V7_SELF': '1'}      # B 线透明解密的激活开关，缺了基线必失真
        if extra_env:
            env.update(extra_env)
        run_cmd = []
        if qemu:
            run_cmd.append(qemu)
        run_cmd.append(out)
        run_cmd.extend(run_args.split())
        stdin_data = None
        if passkey is not None:
            stdin_data = (passkey + '\n').encode()
        if stdin_data is None:
            p = subprocess.run(run_cmd, capture_output=True, env=env,
                               timeout=90, stdin=subprocess.DEVNULL)
        else:
            p = subprocess.run(run_cmd, capture_output=True, env=env,
                               timeout=90, input=stdin_data)
    except subprocess.TimeoutExpired:
        os.remove(out)
        return False, None, '运行超时（疑似死循环）'
    p_out = p.stdout.decode('utf-8', 'replace') if isinstance(p.stdout, bytes) else p.stdout
    p_err = p.stderr.decode('utf-8', 'replace') if isinstance(p.stderr, bytes) else p.stderr
    got = (p.returncode, _norm(p_out), _norm(p_err))
    if got == (baseline[0], baseline[1], baseline[2]):
        return True, out, ''
    why = []
    if got[0] != baseline[0]:
        why.append('rc %d!=%d' % (got[0], baseline[0]))
    if got[2] != baseline[2]:
        why.append('stderr 变化')
    if got[1] != baseline[1]:
        why.append('stdout 变化')
    os.remove(out)
    return False, None, '; '.join(why)


def do_verify(qemu, vmpacker, elf, run_args, ok, out_path, verbose,
              passkey=None, outer_pass=None):
    """--verify 主流程：逐函数保护+验证，自动剔除破坏行为的函数，
    最后用幸存清单做最终批量保护。返回幸存函数列表。"""
    import tempfile
    print('\n[*] --verify 模式：逐函数单独保护 + 运行验证'
          + ('（qemu）' if qemu else '（本机原生）'))
    # B 线运行契约：内层 passkey 走 stdin、外层口令走 V7_PASS
    extra_env = {'V7_PASS': outer_pass} if outer_pass else None
    if passkey:
        print('    [i] 基线将以 --passkey 喂入内层口令（stdin）')
    if outer_pass:
        print('    [i] 基线将注入外层口令环境变量 V7_PASS')
    # 基线判定：跑两次、归一化后一致即认为可验证。
    # 不预设退出码/输出形态 —— qemu 下 exec bash 失败是 rc=1 无输出，
    # Termux 原生 exec bash 成功是 rc=0 带脚本输出，两种都是合法基线。
    # （旧版假设 rc=1，导致 Termux 上生产构建被误判"基线行为异常"。）
    raw1 = run_baseline(qemu, elf, run_args, passkey, extra_env)
    raw2 = run_baseline(qemu, elf, run_args, passkey, extra_env)
    b1 = (raw1[0], _norm(raw1[1]), _norm(raw1[2]))
    b2 = (raw2[0], _norm(raw2[1]), _norm(raw2[2]))
    base = b1
    print('    基线: rc=%d stdout=%dB stderr=%dB'
          % (base[0], len(base[1]), len(base[2])))
    if b1 != b2:
        print('    第1次: %r' % (b1[2][:200] or b1[1][:200],))
        print('    第2次: %r' % (b2[2][:200] or b2[1][:200],))
        sys.exit('[!] 基线两次运行结果不一致，产物本身不确定，验证不可信')
    if '解密完成' in base[2]:
        print('    诊断构建：按阶段输出精细对比')
    elif base[0] == 1 and not base[2]:
        print('    [i] 生产构建 + 模拟器（exec bash 失败，按解密链路对比）。')
        print('        建议 V7_DIAG=1 构建后验证 —— 阶段输出可精确定位哪段被破坏。')
    else:
        print('    [i] 生产构建 + 本机原生运行（按 rc/输出对比）。')

    workdir = tempfile.mkdtemp(prefix='vmpverify_')
    # B 线产物：blob 追加在 ELF 段之后，VMPacker 不认，必须自行接回
    tail = read_tail_attachment(elf)
    keep, drop = [], []
    for a, n, e in ok:
        specs = '0x%x-0x%x:%s' % (a, e, re.sub(r'[^A-Za-z0-9_]', '_', n))
        okv, outf, why = verify_one(qemu, elf, specs, run_args, base,
                                    workdir, vmpacker, tail,
                                    passkey=passkey, extra_env=extra_env)
        tag = '✅ 保留' if okv else '❌ 剔除 (%s)' % why
        print('    %-28s 0x%x-0x%x  %s' % (n[:28], a, e, tag))
        if verbose and not okv and why:
            print('        %s' % why)
        (keep if okv else drop).append((a, n, e))

    print('\n[*] 验证结果：%d 个安全，%d 个破坏行为' % (len(keep), len(drop)))
    if not keep:
        print('[!] 所有候选函数单独保护后都破坏行为 —— VMPacker 对该产物不可用，')
        print('    维持 V7_VMP=1 的常量随机化/符号抹除等现有加固即可。')
        return []

    # 幸存清单批量保护
    specs = ['0x%x-0x%x:%s' % (a, e, re.sub(r'[^A-Za-z0-9_]', '_', n))
             for a, n, e in keep]
    cmd = [vmpacker, '-addr', ','.join(specs), '-o', out_path, elf]
    print('[*] 幸存清单批量保护 (%d 函数) → %s' % (len(keep), out_path))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0 or not os.path.isfile(out_path):
        sys.stdout.write(r.stdout[-2000:])
        sys.exit('[!] 批量保护失败 rc=%d' % r.returncode)
    reattach_tail(out_path, tail)

    # 最终产物全量验证
    raw2 = run_baseline(qemu, out_path, run_args, passkey, extra_env)
    base2 = (raw2[0], _norm(raw2[1]), _norm(raw2[2]))
    if base2 == base:
        print('[+] 最终产物行为与基线一致 ✅ (%d 字节, 原 %d, +%d)'
              % (os.path.getsize(out_path), os.path.getsize(elf),
                 os.path.getsize(out_path) - os.path.getsize(elf)))
    else:
        # 完整打印三元组差异（只打 stderr 曾把 rc=113 空输出误报成 ''）
        print('[!] 最终产物行为不一致 ❌（逐个验证的交互问题）：')
        if base2[0] != base[0]:
            print('    rc:     %d != %d（基线）' % (base2[0], base[0]))
        if base2[1] != base[1]:
            print('    stdout: %r' % (base2[1][:160],))
            print('            基线 %r' % (base[1][:160],))
        if base2[2] != base[2]:
            print('    stderr: %r' % (base2[2][:160],))
            print('            基线 %r' % (base[2][:160],))
        if base2[0] == 113:
            print('    [i] rc=113 = 反调试拒绝。旧版产物可能被"解密耗时>3000ms"'
                  ' 时间侧信道误杀 ——')
            print('        VM 解释执行天然慢；请更新 v7_build.sh/elfrun.c'
                  '（V7_VMP_BUILD 已关闭该检测）后重新构建。')
        else:
            print('    可用 --include 手动缩小幸存清单再试（二分定位冲突函数）。')
    print('\n[*] 安全保护清单（下次可直接 --include 跳过逐个验证）：')
    print('    ' + ','.join(n for _, n, _ in keep))
    return keep


def main():
    ap = argparse.ArgumentParser(
        description='TShell × VMPacker 自动化保护',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('elf', help='待保护的 V7 产物（建议 V7_VMP=1 构建）')
    ap.add_argument('--map', default=None, help='符号表快照（默认 <elf>.map）')
    ap.add_argument('--vmpacker', default=None, help='vmpacker 可执行文件路径')
    ap.add_argument('-o', '--out', default=None, help='输出文件（默认 <elf>.vmp）')
    ap.add_argument('--include', default=None,
                    help='只保护匹配这些正则的函数（逗号分隔），覆盖默认目标集')
    ap.add_argument('--exclude', default=None, help='额外排除正则（逗号分隔）')
    ap.add_argument('--dry-run', action='store_true', help='只列出计划，不执行保护')
    ap.add_argument('--list', action='store_true', help='列出符号表里的候选函数')
    ap.add_argument('--check-neon', action='store_true', help='只做 NEON 体检，不保护')
    ap.add_argument('--allow-neon', action='store_true',
                    help='即使函数含 NEON 也尝试保护（大概率会被 VMPacker 拒绝）')
    ap.add_argument('--qemu', default=None,
                    help='qemu 路径（可选；不填则直接运行本机二进制，'
                         'Termux 原生 aarch64 场景）')
    ap.add_argument('--run-args', default='', help='传给被保护程序的运行参数')
    ap.add_argument('--passkey', default=None,
                    help='产物内层 passkey（B 线密钥分离）。走 stdin 喂给产物，'
                         '让基线反映真实行为；不填则产物按"无 passkey"运行')
    ap.add_argument('--outer-pass', default=None,
                    help='B 线外层口令（V7_PASS 环境变量），供基线运行使用')
    ap.add_argument('--verify', action='store_true',
                    help='逐函数保护+运行验证，自动剔除会破坏行为的函数'
                         '（--qemu 可选）')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    # 路径统一 abs：产物/vmpacker 可能被以相对路径传入，运行时 cwd 一变就找不到
    elf = os.path.abspath(args.elf)
    mapf = os.path.abspath(args.map) if args.map else (elf + '.map')
    if not os.path.isfile(elf):
        sys.exit('[!] 找不到 ELF: %s' % elf)
    if not os.path.isfile(mapf):
        sys.exit('[!] 找不到符号表: %s\n    （用 V7_VMP=1 构建会同时生成 .map）' % mapf)

    syms = load_map(mapf)
    if not syms:
        sys.exit('[!] 符号表为空: %s' % mapf)
    print('[*] 符号表 %s：%d 条' % (mapf, len(syms)))

    # 目标筛选
    if args.include:
        pats = [re.compile(p) for p in args.include.split(',')]
    else:
        pats = [re.compile(p) for p in DEFAULT_PATTERNS]
    exc = [re.compile(p) for p in EXCLUDE_PATTERNS]
    if args.exclude:
        exc += [re.compile(p) for p in args.exclude.split(',')]

    # vaddr→文件偏移基准（函数边界精修与 NEON 扫描都需要，必须在循环前算好）
    load_off = get_load_offset(elf)

    cands = []
    for i, (a, n) in enumerate(syms):
        if any(e.search(n) for e in exc):
            continue
        if not any(p.search(n) for p in pats):
            continue
        hard = func_end(syms, i)
        end, why = detect_func_end(elf, load_off, a, hard)
        cands.append((a, n, end, why, hard))
    cands.sort(key=lambda x: x[0])

    if not cands:
        sys.exit('[!] 没有匹配到任何目标函数（试试 --include）')

    # NEON 体检
    print('[*] vaddr→file offset 基准: 0x%x' % load_off)
    print('\n%-30s %-12s %-10s %-10s %s' % ('函数', '地址', '大小', 'NEON', '状态'))
    print('-' * 78)
    ok, bad = [], []
    for a, n, e, why, hard in cands:
        has_neon, total, hits = scan_neon(elf, load_off, a, e)
        size = e - a
        if has_neon is None:
            st, neon_s = '未检查', '?'
            ok.append((a, n, e))       # 无法检查时照常尝试
        elif has_neon:
            st, neon_s = '含NEON', 'YES'
            bad.append((a, n, e, hits))
            if args.allow_neon:
                ok.append((a, n, e))
        else:
            st, neon_s = '可保护', 'no'
            ok.append((a, n, e))
        print('%-30s 0x%-10x %-10d %-10s %s' % (n[:30], a, size, neon_s, st))

    print('\n[*] 可保护 %d 个，含 NEON %d 个' % (len(ok), len(bad)))
    # capstone 缺失 → 边界只用"下一符号"硬上界，可能圈进 literal pool/无符号函数
    try:
        import capstone  # noqa: F401
    except ImportError:
        print('[i] 未安装 capstone：函数边界未精修（NEON 列显示"?"），')
        print('    边界可能偏大圈进字面量池。建议: pip install capstone')
    if bad and not args.allow_neon:
        print('[!] 以下函数含 NEON，VMPacker 会拒绝；')
        print('    请用 V7_VMP=1 重新构建（-mgeneral-regs-only 可消除 NEON），')
        print('    或加 --allow-neon 强行尝试（预期失败）：')
        for a, n, e, hits in bad:
            print('      %-28s 0x%x  %s' % (n, a, hits[0] if hits else ''))

    if args.dry_run or args.check_neon or args.list:
        if args.list:
            print('\n[*] 符号表全部候选（前 40）：')
            for a, n in syms[:40]:
                print('    0x%-10x %s' % (a, n))
        return

    if not ok:
        sys.exit('[!] 没有可保护的函数，终止')

    # 定位 vmpacker
    vp = args.vmpacker or os.environ.get('VMPACKER')
    if not vp:
        for c in ['/tmp/vmp/VMPacker-master/build/vmpacker',
                  os.path.expanduser('~/VMPacker/build/vmpacker'),
                  './vmpacker']:
            if os.path.isfile(c):
                vp = c
                break
    if not vp or not os.path.isfile(vp):
        sys.exit('[!] 找不到 vmpacker，用 --vmpacker 指定路径')
    print('\n[*] vmpacker: %s' % vp)

    # --verify：逐函数验证 → 自动剔除坏函数 → 幸存清单批量保护
    if args.verify:
        out_path = os.path.abspath(args.out) if args.out else (elf + '.vmp')
        do_verify(args.qemu, vp, elf, args.run_args, ok, out_path, args.verbose,
                  passkey=args.passkey, outer_pass=args.outer_pass)
        return

    # 组装 -addr（逗号分隔，批量一次保护）
    specs = ['0x%x-0x%x:%s' % (a, e, re.sub(r'[^A-Za-z0-9_]', '_', n))
             for a, n, e in ok]
    out = args.out or (elf + '.vmp')
    # B 线产物：blob 追加在 ELF 段之后，VMPacker 输出会丢掉，先取出来
    tail = read_tail_attachment(elf)
    cmd = [vp, '-addr', ','.join(specs)]
    if args.verbose:
        cmd.append('-v')
    cmd += ['-o', out, elf]

    print('[*] 保护 %d 个函数：' % len(ok))
    for a, n, e in ok:
        print('    0x%x-0x%x  %s' % (a, e, n))
    print()
    r = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.stderr:
        sys.stderr.write(r.stderr)

    if r.returncode != 0 or not os.path.isfile(out):
        sys.exit('[!] VMPacker 失败（rc=%d）' % r.returncode)
    # B 线产物：把 VMPacker 丢弃的尾部 blob 接回
    reattach_tail(out, tail)

    print('\n[+] 保护完成: %s (%d 字节, 原 %d 字节, +%d)'
          % (out, os.path.getsize(out), os.path.getsize(elf),
             os.path.getsize(out) - os.path.getsize(elf)))

    # 运行验证
    if args.qemu:
        print('\n[*] 运行验证 (%s)...' % args.qemu)
        env = dict(os.environ)
        env['ANDROID_GATE'] = os.environ.get('ANDROID_GATE', '0')
        base = subprocess.run([args.qemu, elf] + args.run_args.split(),
                              capture_output=True, text=True, env=env, timeout=120)
        prot = subprocess.run([args.qemu, out] + args.run_args.split(),
                              capture_output=True, text=True, env=env, timeout=120)
        print('    原产物   rc=%d  输出 %d 字节' % (base.returncode, len(base.stdout)))
        print('    保护后   rc=%d  输出 %d 字节' % (prot.returncode, len(prot.stdout)))
        if base.returncode == prot.returncode and base.stdout == prot.stdout:
            print('    [+] 行为一致 ✅')
        else:
            print('    [!] 行为不一致 ❌ —— 不要分发该产物')
            if base.stdout != prot.stdout:
                print('    原: %r' % base.stdout[:200])
                print('    新: %r' % prot.stdout[:200])


if __name__ == '__main__':
    main()
