#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# -*- coding: utf-8 -*-
"""
v7_isa.py —— r16 四层随机化表：生成器 + 第 1/2 层命令位置改写器 + 校验器
================================================================================

设计背景（r16 立项，见 R10_CHANGES.md G.1.5）：
  攻击者即使逆穿 C 执行器拿到 payload 明文，四层随机化表让明文
  "不像 shell、不可理解、脱离解释器不可分发"：
    L1 builtin 换名     ：echo/printf... → 随机名（C 层 hook 复用 bash 现成 builtin 实现）
    L2 external 名映射  ：getprop/am/... → 随机名（C 层 hook 还原真名后 PATH 透传）
    L3 语法关键字整族   ：if/then/...   → 随机名（bash reserved_word 识别处 hook；MVP 14 词，
                                           { } [[ ]] 易碎暂缓）
    L4 变量/常量预绑定  ：$1..$9 $@ $# $* 与 /data /system 等路径 → 随机变量名
                                           （C 执行器启动期绑定真值；检测到 shift 自动跳过）
  表随 blob 配方分发（C 端运行时读表安装 hook），**bash 不随构建重编**；
  表内容参与 blob 层 HMAC 校验（改一字节 = 篡改 = 拒跑）。

随机名规则：
  4~6 位，[a-z0-9]，首字符 [a-z]（合法变量/命令名）；
  黑名单 = bash 保留字 + bash builtin 全集 + 常见 Unix 命令 + 表内互斥
  （宁多勿少：撞名 = 产物行为歧义）。

改写器（本轮实现 L1/L2）：
  词法状态机，**宁缺勿滥**——只改写"确定是命令位置"的词：
    命令位 = 行首 / ; | && || 后 / $( ` 后 / ( 后 / then do else 后的语句首
    不动   = 单引号内 / 双引号内（$( 内部除外）/ 注释 / heredoc / 算术
             $((..)) 与 [[ ]] 内 / 赋值左侧 NAME= / for 头部（变量与 in）
  未改写位置用原命令名照常执行（C hook 只拦表内随机名）→ 改写是增强
  不是依赖，兼容性 100%，降级路径天生存在。
  L3/L4 改写器属后续迭代（表生成已支持）；L3 改写后必须过魔改 bash
  `-n` 语法预检（关键字层无运行时兜底）。

用法：
  python3 v7_isa.py gen  --seed 12345 -o table.bin --json table.json
  python3 v7_isa.py rewrite --table table.json --in in.sh --out out.sh
  python3 v7_isa.py check --table table.bin
  python3 v7_isa.py selftest

序列化格式（table.bin，配方头段，最终嵌入 blob）：
  "V7ISA" magic(5B) + ver(1B) + n(2B LE)
  每项: layer(1B) + orig_len(1B) + orig + alias_len(1B) + alias
  layer: 1=builtin 2=external 3=keyword 4=param 5=path
"""
import argparse
import hashlib
import hmac as _hmac
import json
import os
import random
import sys

MAGIC = b"V7IST"
VERSION = 3          # r21：v3 = 表体加密 + 诱饵条目（v2 明文符号表废弃）

# ---------------------------------------------------------------- r21 表加密
#
# 为什么要加密（用户 r20 复盘原话）：「还是加密然后解释器在内存里再解密，
# 或者中间流程想个再稍微复杂一点，就算很难拿到完整的表或者可能拿到错误的，
# 让它必须分析整个 c 层」。
#
# v2 的问题：表虽已去语义（alias→sym id），但 alias→编号 的**对应关系**
# 仍是明文。攻击者拿到表即可批量套用同一份 bash 产物的符号表。
#
# v3 三层递进，任一层单独失守都不足以还原：
#   ① 主密钥 KM（32B）不落盘、不以连续明文存在于 rodata：拆 8×u32 与随机
#      掩码异或后分两串存放（v7_isa_key.h），运行期现场重组。
#   ② 每份表带 16B 随机 salt，实际密钥 K = HMAC(KM, label||salt)
#      —— 同一把 KM 下每份产物表密钥都不同，逆一次不等于通杀。
#   ③ 表体 Encrypt-then-MAC（HMAC-SHA256 截断 16B），篡改 = 解密失败 = 静默
#      空转（fail-closed，绝不"用半张坏表继续跑"）。
#
# 解密只在 C 层内存里做：python 侧落盘的永远是密文，运行期释放到临时目录的
# 也是密文，**任何时刻磁盘上没有明文表**。要还原必须逆 C 层的
# v7_isa_derive / isa_load（均在 VMP 保护清单内）。

def _hmac_sha256(key, msg):
    """与 crypto_core.h hmac_sha256 完全一致（标准 HMAC-SHA256）。"""
    return _hmac.new(key, msg, hashlib.sha256).digest()


def _isa_derive(km, salt):
    """主密钥 + salt → (kenc, kmac)。对应 C 侧 v7_isa_derive。"""
    return (_hmac_sha256(km, b"V7ISA-ENC" + salt),
            _hmac_sha256(km, b"V7ISA-MAC" + salt))


def _isa_keystream(kenc, blk):
    """密钥流块：HMAC(kenc, BE64(blk))，32B/块。对应 v7_keystream。"""
    return _hmac_sha256(kenc, blk.to_bytes(8, "big"))


def _isa_crypt(kenc, data):
    """CTR-XOR，加解密同一函数。对应 v7_crypt。"""
    out = bytearray()
    blk, off = 0, 0
    while off < len(data):
        ks = _isa_keystream(kenc, blk)
        blk += 1
        chunk = data[off:off + 32]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        off += 32
    return bytes(out)


def _isa_tag(kmac, data):
    """Encrypt-then-MAC 标签：HMAC(kmac, data) 截断 16B。对应 v7_tag。"""
    return _hmac_sha256(kmac, data)[:16]


# ---------------------------------------------------------------- 主密钥
#
# 存放位置：v7/bash_poc/v7_isa_key.h（与 v7_isa_syms.h 同目录），
# 编 bash 时一起 include。python 侧序列化/校验通过 V7_ISA_KEY_H 定位它。
# 每次**编 bash** 生成一次（build_poc.sh：不存在才生成），之后固定 ——
# 表与 bash 必须配套；不配套时 C 层解密失败 → ISA 静默空转（不崩，降级运行）。
def _key_h_default_path():
    return os.environ.get("V7_ISA_KEY_H") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "v7", "bash_poc", "v7_isa_key.h")


def _parse_key_h(path):
    """从 v7_isa_key.h 解析出 32B 主密钥（X ^ M）。"""
    import re
    with open(path, "r") as f:
        txt = f.read()

    def _arr(name):
        m = re.search(r"v7_isa_km_%s\[8\]\s*=\s*\{([^}]*)\}" % name, txt)
        if not m:
            raise ValueError("%s 中缺少 v7_isa_km_%s" % (path, name))
        vals = [int(v, 0) & 0xFFFFFFFF
                for v in re.findall(r"0x[0-9A-Fa-f]+|\d+", m.group(1))]
        if len(vals) != 8:
            raise ValueError("%s 中 v7_isa_km_%s 不是 8 项" % (path, name))
        return vals

    x, m = _arr("x"), _arr("m")
    return b"".join(((x[i] ^ m[i])).to_bytes(4, "little") for i in range(8))


def emit_key(path, seed=None):
    """生成主密钥头文件。返回 32B 主密钥。"""
    rng = random.Random(seed)
    km = bytes(rng.randrange(256) for _ in range(32))
    xi = [int.from_bytes(km[i * 4:i * 4 + 4], "little") for i in range(8)]
    mi = [rng.randrange(1 << 32) for _ in range(8)]
    lines = [
        "/* 自动生成，勿手改 —— 由 tools/v7_isa.py emit-key 生成。",
        " *",
        " * r21：ISA 第一层表的**主密钥**。不以连续明文存在于 rodata：",
        " *   32B 拆 8×u32，每份与随机掩码异或后分两串（_x / _m）存放。",
        " *   单看任一一串都是无意义随机数据，必须二者相异或才得主密钥。",
        " * 运行期由 v7_isa_master()（VMP 保护）现场重组后立即擦除栈副本。",
        " *",
        " * 换掉本文件 = 换密钥 = 既有表全部作废（解密失败 → ISA 静默空转）。",
        " * 与 v7_isa_syms.h 同属「一次编 bash 生成、之后固定」的配对产物。 */",
        "#ifndef V7_ISA_KEY_H",
        "#define V7_ISA_KEY_H",
        "",
        "static const unsigned int v7_isa_km_x[8] = {",
    ]
    for i in range(0, 8, 4):
        lines.append("    " + ", ".join("0x%08xu" % v for v in xi[i:i + 4]) + ",")
    lines += ["};", "", "static const unsigned int v7_isa_km_m[8] = {"]
    for i in range(0, 8, 4):
        lines.append("    " + ", ".join("0x%08xu" % v for v in mi[i:i + 4]) + ",")
    lines += ["};", "", "#endif /* V7_ISA_KEY_H */", ""]
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return km


def _load_master():
    p = _key_h_default_path()
    if not os.path.exists(p):
        raise ValueError(
            "缺少主密钥文件 %s —— 先执行:\n"
            "  python3 tools/v7_isa.py emit-key -o v7/bash_poc/v7_isa_key.h\n"
            "（每次重编 bash 会随之生成新密钥；换了密钥必须重生成表）" % p)
    return _parse_key_h(p)

# ---------------------------------------------------------------- 层定义
# MVP 决策（用户确认的 14 builtin/external 基础上按 r16 讨论扩展）：
#   L1 8 个：语义稳定、复用 bash 现成实现、零 fork 零风险
#   L2 9 个：Android 身份特征 + 高频运维命令，名字映射透传
#   L3 14 词：if/loop/case/function 整族，{ } [[ ]] 易碎 MVP 排除
#   L4：位置参数 13 形态 + 路径 5（表内记录原名形态，C 端启动期绑定）
LAYER1 = ["echo", "printf", "export", "local", "unset", "read", "true", "false"]
LAYER2 = ["getprop", "setprop", "am", "pm", "mount", "umount", "find", "mkdir", "date"]
LAYER3 = ["if", "then", "elif", "else", "fi",
          "while", "until", "do", "done", "for",
          "case", "esac", "function"]
# 注："in" 终版不表化（r16 实测裁决）：bison 的 for/case 产生式对 IN token
# 位置有深层耦合（newline_list/word_list 形态），经宏还原的 "in" 触发
# "syntax error near unexpected token 'in'"。孤立 "in" 不构成语义指纹，
# for/case 头部的 in 保留原名；改写器在 for 头部本就跳过 in。
LAYER4_PARAM = ["$0", "$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9",
                "$@", "$#", "$*"]
LAYER4_PATH = ["/data", "/system", "/system/bin", "/data/adb", "/sdcard"]

# ---- r27（ShellVMP T1）：L6 参数密文令牌 ----
# 与 L1-L5 的**根本差异**：L6 的真名（业务字符串）是**无限的、产物相关的**，
# 不可能像 L1-L5 那样写死进 ISA_SYMBOLS 符号表。
#
# 因此 L6 采用**独立机制**：
#   - 真名随表走（表体已加密 + MAC，落盘无明文）
#   - sym 字段对 L6 无意义（置 0），真名以「伴随串」形式紧随表项
#   - C 层查表即得真名，无需第二层符号索引
#
# 安全边界（必须记住）：
#   L1-L5 的"真名只在二进制里（受 VMP 保护）"这一性质，L6 **不具备** ——
#   L6 真名在表里（虽然加密）。代价换来的是"参数可随业务无限扩展、无需重编 bash"。
#   取舍：攻击者要拿 L6 真名，必须同时破表密钥 + 定位解密函数（VMP 保护）。
LAYER5_PARAM_TOKEN = 6          # layer 编号（C 侧 isa_entry.layer 需同步）
ISA_MAX_ORIG = 512              # L6 真名上限（r33d.1：192→512B，≈170 汉字；
                                # 与 isa_hook.c 的 ISA_MAX_ORIG 必须同步改）

# ---- r20 符号化：表内不再出现真名 ----
# 固定符号表：sym id = 本列表下标。顺序必须与 C 层 v7_isa_syms[] 严格一致
# （由 `emit-c` 生成头文件，编 bash 时 include）。
# 表项在内存中仍带 orig（改写器要用），但**序列化时不落盘 orig**，只落 sym id。
# 攻击者即便拿到表，看到的也只是 alias→整数编号，无语义；要还原必须逆 C 层
# 那张符号表（而它位于 VMP 保护的函数上下文里）。
ISA_SYMBOLS = []
SYM_INDEX = {}


def _build_symbols():
    for _layer, _names in ((1, LAYER1), (2, LAYER2), (3, LAYER3),
                           (4, LAYER4_PARAM), (5, LAYER4_PATH)):
        for _n in _names:
            SYM_INDEX[(_layer, _n)] = len(ISA_SYMBOLS)
            ISA_SYMBOLS.append(_n)


_build_symbols()


def emit_c(path):
    """输出 C 符号表头文件（sym id → 真名），供编 bash 时 include。"""
    lines = [
        "/* 自动生成，勿手改 —— 由 tools/v7_isa.py emit-c 生成。",
        " * 顺序与 ISA_SYMBOLS 严格一致：sym id 即下标。",
        " * 表内只存 sym id，真名仅存在于本文件（编进二进制，受 VMP 保护）。 */",
        "#ifndef V7_ISA_SYMS_H",
        "#define V7_ISA_SYMS_H",
        "",
        "static const char *const v7_isa_syms[] = {",
    ]
    for s in ISA_SYMBOLS:
        esc = s.replace("\\", "\\\\").replace('"', '\\"')
        lines.append('    "%s",' % esc)
    lines += [
        "};",
        "",
        "#define V7_ISA_NSYMS ((int)(sizeof(v7_isa_syms) / sizeof(v7_isa_syms[0])))",
        "",
        "#endif /* V7_ISA_SYMS_H */",
        "",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return len(ISA_SYMBOLS)

# ---------------------------------------------------------------- 黑名单
# bash 保留字（含 L3 全部 + 未表化的易碎关键字——绝不能给随机名撞上）
BASH_RESERVED = {
    "if", "then", "elif", "else", "fi", "while", "until", "do", "done",
    "for", "in", "case", "esac", "function", "select", "time", "coproc",
    "{", "}", "[[", "]]", "!",
}
# bash builtin 全集（compgen -b 常见集合；撞名 = C hook 后行为歧义）
BASH_BUILTINS = {
    "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command",
    "compgen", "complete", "compopt", "continue", "declare", "dirs",
    "disown", "echo", "enable", "eval", "exec", "exit", "export", "false",
    "fc", "fg", "getopts", "hash", "help", "history", "jobs", "kill",
    "let", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd",
    "read", "readarray", "readonly", "return", "set", "shift", "shopt",
    "source", "suspend", "test", "times", "trap", "true", "type",
    "typeset", "ulimit", "umask", "unalias", "unset", "wait", "[",
}
# 常见 Unix/Android 命令（撞名 = 改写后原命令被遮蔽或误导 C hook）
UNIX_COMMON = {
    "ls", "cp", "mv", "rm", "rmdir", "touch", "ln", "cat", "grep", "sed",
    "awk", "cut", "tr", "head", "tail", "sort", "uniq", "wc", "find",
    "chmod", "chown", "chgrp", "dd", "tar", "gzip", "gunzip", "zcat",
    "base64", "od", "xxd", "hexdump", "date", "sleep", "uname", "id",
    "whoami", "groups", "env", "printenv", "seq", "sha1sum", "sha256sum",
    "sha512sum", "md5sum", "cksum", "openssl", "mount", "umount", "getprop",
    "setprop", "start", "stop", "am", "pm", "pm", "ps", "top", "df", "du",
    "free", "stat", "sync", "reboot", "poweroff", "insmod", "rmmod",
    "lsmod", "dmesg", "logcat", "log", "adb", "su", "sudo", "sh", "bash",
    "zsh", "ash", "dash", "mksh", "ksh", "toybox", "busybox", "which",
    "whereis", "locate", "tee", "xargs", "dirname", "basename", "readlink",
    "realpath", "patch", "diff", "cmp", "comm", "join", "paste", "split",
    "fmt", "fold", "column", "pr", "tac", "rev", "vi", "vim", "nano",
    "less", "more", "clear", "reset", "tput", "stty", "tty", "mesg",
    "write", "wall", "at", "crontab", "nice", "nohup", "timeout", "watch",
    "strace", "ltrace", "gdb", "objdump", "readelf", "nm", "strings",
    "file", "xz", "bzip2", "lzma", "zstd", "curl", "wget", "nc", "ncat",
    "socat", "ssh", "scp", "rsync", "git", "make", "gcc", "clang", "ld",
    "ar", "ranlib", "python", "python3", "perl", "ruby", "lua", "node",
    "ping", "ip", "ifconfig", "netstat", "ss", "route", "iptables",
    "tcpdump", "traceroute", "nslookup", "dig", "host", "arp", "w",
    "last", "who", "finger", "users", "uptime", "hostname", "uname",
    "qemu", "qemu-aarch64-static", "v7", "v6", "zread", "elfrun",
}

BLACKLIST = BASH_RESERVED | BASH_BUILTINS | UNIX_COMMON


# ---------------------------------------------------------------- 随机名
#
# r17-1（A5 血案）：别名必须带**专属前缀**且**足够长**。
#
# 事故：路径层别名曾用 4~6 位纯 [a-z0-9]，例 "/data" → "f054"。
#   C 层 v7_isa_translate_paths 对每个词做 **无锚定子串替换**（strstr），
#   于是任何**数据**里随机出现 "f054" 都会被改写成 "/data"。
#   sha512 摘要（128 个 [0-9a-f]）在 kdf_builtin 的 300 轮链里，
#   单轮撞上 4 字符 hex 别名概率 ≈ 128/16^4 ≈ 0.2%，
#   300 轮累积 ≈ 45% —— 命中即令运行期 _k1 与构建期分叉，
#   _I 解出乱码 → gzip 失败 → _D 空 → exit 1（静默崩，无任何提示）。
#
# 修法（两层防御，缺一不可）：
#   ① 本文：别名 = PREFIX + 长随机段，字符集含下划线，长度 ≥14。
#      碰撞概率从 1/16^4≈1.5e-5 降到 ~1/36^10≈3e-16，300 轮下可忽略。
#   ② isa_hook.c：路径层改为**词首锚定 + 整词/段边界**匹配，
#      不再裸 strstr —— 见 v7_isa_translate_paths。
ALIAS_PREFIX = "v7p_"
ALIAS_RAND_LEN = 10          # 随机段长度（不含前缀）；总长 = 4 + 10 = 14
_ALIAS_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_"


def _gen_alias(rng, taken):
    """PREFIX + 10 位 [a-z0-9_]；撞黑名单/已用名则重试。

    前缀 v7p_ 使随机段在**任意数据**（哈希摘要、base64、用户文本）中
    自然出现的概率降到可忽略，且肉眼可辨、便于排障定位。
    """
    for _ in range(4096):
        s = ALIAS_PREFIX + "".join(rng.choice(_ALIAS_ALPHABET)
                                   for _ in range(ALIAS_RAND_LEN))
        if s not in BLACKLIST and s not in taken:
            taken.add(s)
            return s
    raise RuntimeError("随机名空间耗尽（黑名单过大？）")


# r21 掺假强度（可用 --decoy / --shadow 覆盖，0 = 关闭）
#   幻影：与真条目同形态但 alias 不出现在 payload 里的假条目
#   影子：复用真 alias、错 sym、排在真条目之后的假条目（C 层永不命中）
# 总数 48 + 24 + 8 = 80 < C 侧 ISA_MAX_ENTRIES(128)，留有余量。
DECOY_DEFAULT = 24
SHADOW_DEFAULT = 8


def gen_table(seed=None, n_decoy=DECOY_DEFAULT, n_shadow=SHADOW_DEFAULT):
    """生成四层表（含诱饵）。返回 (table_list, taken)。

    r21 掺假：表内除 48 条真条目外，再混入两类诱饵，让攻击者**拿不到
    完整可信的对照**，甚至拿到错误的：

      A. 幻影条目（decoy）：形态与真条目完全一致（同前缀、同长度分布、
         合法 sym id、合法 layer），但 alias 在 payload 里根本不出现 ——
         攻击者无法把它和真条目区分开。sym 取**同层**随机符号：语义相近，
         用错会得到"看起来合理"的错误答案（如把某 builtin 认成 printf）。

      B. 影子条目（shadow）：复用某个**真条目**的 alias，但 sym 指向同层
         另一个错误符号，且**排在真条目之后**。C 层查表是顺序扫描取首个
         命中 ⇒ 影子永不生效；攻击者按表顺序读却可能读到影子，得到错误
         映射，且两条"都合法"，无从判断哪条生效。

    顺序约束（硬）：影子必须严格位于其 alias 对应的真条目之后，否则 C 层
    会先命中影子 → 产物行为错乱。下面用 pos >= idx+1 保证。
    """
    rng = random.Random(seed)  # seed=None → 每构建随机；给定 → 可复现
    taken = set()
    real = []
    for layer, names in ((1, LAYER1), (2, LAYER2), (3, LAYER3),
                         (4, LAYER4_PARAM), (5, LAYER4_PATH)):
        for name in names:
            real.append({"layer": layer, "orig": name,
                         "sym": SYM_INDEX[(layer, name)],
                         "alias": _gen_alias(rng, taken)})

    # 每层的合法 sym id 集合（诱饵只在本层内挑，保证"语义相近地错"）
    layer_syms = {}
    for (_l, _n), _s in SYM_INDEX.items():
        layer_syms.setdefault(_l, []).append(_s)

    body = list(real)
    for _ in range(max(0, n_decoy)):
        layer = rng.choice(sorted(layer_syms))
        sym = rng.choice(layer_syms[layer])
        body.append({"layer": layer, "sym": sym, "orig": ISA_SYMBOLS[sym],
                     "alias": _gen_alias(rng, taken), "decoy": True})

    rng.shuffle(body)          # 真/幻影交错，顺序不再透露真假

    shadows = []
    if n_shadow > 0:
        for t in rng.sample(real, min(n_shadow, len(real))):
            cands = [s for s in layer_syms[t["layer"]] if s != t["sym"]]
            if not cands:
                continue
            shadows.append({"layer": t["layer"], "sym": rng.choice(cands),
                            "alias": t["alias"], "decoy": True, "shadow": True})
    for sh in shadows:
        idx = next(i for i, t in enumerate(body) if t["alias"] == sh["alias"])
        # 必须插在真条目之后（含紧邻其后），否则 C 层会先命中影子
        body.insert(rng.randint(idx + 1, len(body)), sh)
        sh["orig"] = ISA_SYMBOLS[sh["sym"]]

    return body, taken


def serialize(table, km=None, salt=None):
    """→ table.bin 字节串（r21：表体加密 + MAC，落盘永不为明文）。

    布局：
      "V7IST"(5B) + ver(1B) + salt(16B) + n(2B LE) + ct + tag(16B)
      K_enc/K_mac = HMAC(KM, "V7ISA-ENC"/"MAC" || salt)
      tag = HMAC(K_mac, 文件除末 16B 外的全部)[:16]   —— Encrypt-then-MAC

    表项编码（r27 起分两种，靠 layer 区分）：
      L1-L5（layer 1..5）：
        { layer(1B) + sym(2B LE) + alias_len(1B) + alias }
        —— 真名不入表，靠 C 侧 ISA_SYMBOLS[sym]（VMP 保护）
      L6（layer 6，参数密文令牌）：
        { layer(1B) + orig_len(2B LE) + alias_len(1B) + alias + orig }
        —— 真名**随表走**（表体已加密），因为业务字符串无法预先编表
    """
    if km is None:
        km = _load_master()
    if salt is None:
        salt = os.urandom(16)

    pt = bytearray()
    for item in table:
        alias = item["alias"].encode()
        if len(alias) > 255:
            raise ValueError("表项超长：%r" % item)
        layer = item["layer"]
        if layer >= LAYER5_PARAM_TOKEN:
            # L6：真名随表走
            orig = item.get("orig", "").encode()
            if len(orig) > ISA_MAX_ORIG:
                raise ValueError("L6 真名超长（%d > %d）：%r"
                                 % (len(orig), ISA_MAX_ORIG, item.get("orig")))
            pt.append(layer)
            pt += len(orig).to_bytes(2, "little")
            pt.append(len(alias))
            pt += alias
            pt += orig
        else:
            sym = item.get("sym")
            if sym is None:
                sym = SYM_INDEX.get((layer, item["orig"]), 0)
            pt.append(layer)
            pt += int(sym).to_bytes(2, "little")
            pt.append(len(alias))
            pt += alias

    kenc, kmac = _isa_derive(km, salt)
    ct = _isa_crypt(kenc, bytes(pt))

    out = bytearray(MAGIC)
    out.append(VERSION)
    out += salt
    out += len(table).to_bytes(2, "little")
    out += ct
    out += _isa_tag(kmac, bytes(out))
    return bytes(out)


def deserialize(data, km=None):
    """v3 表 → 条目列表（自动解密 + MAC 校验；失败即抛异常，绝不半载）。

    只支持 v3。v2 明文符号表已废弃 —— 保留它就等于给攻击者留一条
    「自己造张明文表喂进去」的降级通道，故不再兼容。
    """
    if data[:5] != MAGIC:
        raise ValueError("magic 不符（非 V7IST 加密表；v2 明文表已废弃，"
                         "请用当前 v7_isa.py 重新 gen）")
    ver = data[5]
    if ver != VERSION:
        raise ValueError("版本不符: %d（当前 %d）" % (ver, VERSION))
    if len(data) < 5 + 1 + 16 + 2 + 16:
        raise ValueError("表过短：%d 字节" % len(data))
    if km is None:
        km = _load_master()

    body, tag = data[:-16], data[-16:]
    salt = data[6:22]
    kenc, kmac = _isa_derive(km, salt)
    if not _hmac.compare_digest(_isa_tag(kmac, body), tag):
        raise ValueError("表 MAC 校验失败（被篡改，或主密钥与生成时不一致）")

    n = int.from_bytes(data[22:24], "little")
    pt = _isa_crypt(kenc, data[24:-16])
    pos, table = 0, []
    for _ in range(n):
        if pos + 1 > len(pt):
            raise ValueError("解密后表体截断（layer）")
        layer = pt[pos]; pos += 1
        if layer >= LAYER5_PARAM_TOKEN:
            # L6：layer + orig_len(2B) + alias_len(1B) + alias + orig
            if pos + 3 > len(pt):
                raise ValueError("解密后表体截断（L6 头）")
            olen = int.from_bytes(pt[pos:pos + 2], "little"); pos += 2
            la = pt[pos]; pos += 1
            if pos + la + olen > len(pt):
                raise ValueError("解密后表体截断（L6 体）")
            alias = pt[pos:pos + la].decode(); pos += la
            orig = pt[pos:pos + olen].decode(); pos += olen
            table.append({"layer": layer, "sym": 0, "orig": orig,
                          "alias": alias})
        else:
            if pos + 3 > len(pt):
                raise ValueError("解密后表体截断")
            sym = int.from_bytes(pt[pos:pos + 2], "little"); pos += 2
            la = pt[pos]; pos += 1
            if pos + la > len(pt):
                raise ValueError("解密后表体截断（alias）")
            alias = pt[pos:pos + la].decode(); pos += la
            orig = ISA_SYMBOLS[sym] if sym < len(ISA_SYMBOLS) else "?"
            table.append({"layer": layer, "sym": sym, "orig": orig,
                          "alias": alias})
    return table


# ---------------------------------------------------------------- 改写器
# 命令位置改写（L1/L2）。状态机原则：宁可漏改（原名照跑兜底），不可误改。
_WORD_OPS = ";|&()"          # 触发"下一个词是命令位"的操作符（换行另算）
_CMD_KEYWORDS_AFTER = {"then", "do", "else"}   # 这些关键字后的词是命令位
_FOR_HEAD_SKIP = False        # for 头部（for VAR in ...）内不改写——用状态跟踪


def _is_ident(s):
    return bool(s) and (s[0] == "_" or s[0].isalpha()) and \
        all(c == "_" or c.isalnum() for c in s)


def build_rewrite_map(table, layers):
    """与 C 端查表语义严格对齐的 orig→alias 改写映射（层过滤版）。

    C 端还原：顺序扫描，取**首个** alias 命中的条目，还原为该条目的 orig
    （== ISA_SYMBOLS[sym]）。因此改写侧唯一安全规则：orig=B 只允许替换成
    "首个命中会还原回 B"的别名。

    诱饵（幻影/影子）刻意不落盘标记（反取证：表里真假不可分）——所以
    这里**不区分真伪**，而是按条目顺序模拟 C 端首个命中，一切自然对齐：
      · 影子（复用真 alias、sym 指向别的词、恒排在真条目后）：首个命中
        恒为真条目 ⇒ 影子被跳过，绝不污染映射；
      · 幻影（自造 alias、orig/sym 为同层真词）：首个命中是它自己，还原
        回它的 orig ⇒ 它也是该词的合法改写别名（还原结果相同，任选）。

    旧写法 `{it["orig"]: it["alias"] for it in table}` 是 orig→alias 方向
    的后写覆盖——影子条目（orig=B、alias=A 的别名）后写时会把 B 的真映射
    顶掉，B 被替换成"运行时还原成 A"的别名 ⇒ 语义错乱。mksh L3 冒烟
    （seed 20260914）实测炸出 `if ...; then` 位被写成 done 的别名，产物
    报 `syntax error: unexpected 'done'`。bash 历史全绿纯属该 seed 下
    影子恰好没命中用例词——潜伏的随机炸弹，勿回退。
    """
    first_hit = {}                  # alias → (orig, layer)：模拟 C 端首个命中
    for it in table:
        a = it.get("alias")
        if a and a not in first_hit:
            first_hit[a] = (it["orig"], it["layer"])
    amap = {}
    for a, (orig, layer) in first_hit.items():
        if layer in layers and orig not in amap:
            amap[orig] = a
    return amap


def rewrite_l12(text, table):
    """L1/L2/L3 命令位置改写 + L4 路径常量（词内子串）。返回 (新文本, 改写计数, 跳过计数)。

    r16-5：首次把 L3 关键字与 L4 路径纳入改写流水线——此前只有 L1/L2 自动
    改写，L3 测试脚本全是手写字面别名，流水线并不完整（重要缺口）。
      L3：关键字天然只被词法器在命令位识别（出现在别处就是普通词），故与
        L1/L2 共用同一套命令位判定，无需另设门；
      L4 路径：对所有 emit 出的词做子串替换。单引号/注释/heredoc 主体不会
        流经此处（各自独立透传分支），天然豁免；运行时会原样还原为原路径，
        故"任何位置被替换"都不改变语义（不像 $@ 这类有上下文语义的东西）。
    """
    alias_map = build_rewrite_map(table, (1, 2, 3))
    if not alias_map:
        return text, 0, 0
    path_hits = 0

    out = []
    i, n = 0, len(text)
    cmd_pos = True          # 行首即命令位
    dquote_depth_paren = 0  # 双引号内 $( 嵌套深度
    in_single = False
    in_double = False
    in_comment = False
    in_arith_or_test = 0    # (( 与 [[ 深度
    in_for_head = 0         # for 头部深度（for 后到 in/do 之间）
    replaced = skipped = 0
    line_buf = []

    def is_cmd_pos_here(word=None):
        # r16-5：for 头部里唯一仍是命令位的词是【收尾的 do】——它必须能被替换，
        # 否则 `for x in 1; do` 的 do 落为原名，后面的命令位/for 跟踪一起错乱
        # （自测 case8/case11 首次挂在这里；word=None 时等价于旧严格判定）
        if in_for_head and word != "do":
            return False
        return cmd_pos and not in_single and not in_comment \
            and in_arith_or_test == 0

    # r16-5：状态转移必须以【语义原名】判定 —— 词一旦被替换成别名，
    # `then`→kwb 之后其后的命令会丢掉命令位、`for`/`do` 的头部跟踪也会断
    # （自测 case8 首跑就是这么挂的）。两条路径（替换/未替换）统一调用它。
    def advance(word_orig):
        nonlocal cmd_pos, in_for_head
        if word_orig == "for":
            in_for_head = 1
            cmd_pos = False
        elif in_for_head == 1 and word_orig == "in":
            in_for_head = 2
            cmd_pos = False
        elif in_for_head and word_orig == "do":
            in_for_head = 0
            cmd_pos = True
        elif in_for_head:
            cmd_pos = False          # for 头部其余词（变量名/词表）一律非命令位
        elif word_orig in _CMD_KEYWORDS_AFTER:
            cmd_pos = True
        else:
            cmd_pos = False

    while i < n:
        c = text[i]

        # ---- 注释：到行尾 ----
        if in_comment:
            out.append(c)
            if c == "\n":
                in_comment = False
                cmd_pos = True
            i += 1
            continue
        if not in_single and not in_double and c == "#" and \
                (not out or out[-1] in " \t\n;" + _WORD_OPS or cmd_pos):
            in_comment = True
            out.append(c)
            i += 1
            continue

        # ---- 单引号：原样透传，内容绝不动 ----
        if in_single:
            out.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if not in_double and c == "'":
            in_single = True
            out.append(c)
            i += 1
            continue

        # ---- 双引号：仅 $( 命令替换内部可继续改写 ----
        if in_double:
            if text.startswith("$(", i):
                dquote_depth_paren += 1
                cmd_pos = True          # $( 后是命令位
                out.append("$(")
                i += 2
                continue
            out.append(c)
            if c == ")":
                if dquote_depth_paren:
                    dquote_depth_paren -= 1
                    cmd_pos = False
            elif c == '"':
                in_double = False
                dquote_depth_paren = 0
            elif c == "\n":
                cmd_pos = True
            i += 1
            continue
        if c == '"':
            in_double = True
            out.append(c)
            i += 1
            continue

        # ---- heredoc / herestring：<<[-]DELIM 主体透传到结束行；<<< 词透传 ----
        if text.startswith("<<", i) and text[i + 2:i + 3] != "<":
            out.append("<<")
            i += 2
            # 吃掉可能的 - 与空白
            while i < n and text[i] in "- \t":
                out.append(text[i]); i += 1
            # 读 delimiter
            delim = ""
            q = ""
            while i < n and (text[i] not in " \t\n;&|)" or q):
                if not q and text[i] in "'\"":
                    q = text[i]; i += 1; continue
                if q and text[i] == q:
                    q = ""; i += 1; continue
                delim += text[i]; out.append(text[i]); i += 1
            if not delim:
                continue
            # 透传到独占一行的 delim（保留每行换行符——r16 初版曾在此丢 \n 粘行）
            while i < n:
                eol = text.find("\n", i)
                line = text[i:] if eol == -1 else text[i:eol]
                out.append(line if eol == -1 else line + "\n")
                i = n if eol == -1 else eol + 1
                if line.strip() == delim:
                    break
                if eol == -1:
                    break
            cmd_pos = True
            continue

        # ---- 算术 / [[ 深度：内部不改写 ----
        if text.startswith("((", i) or text.startswith("[[", i):
            in_arith_or_test += 1
            out.append(text[i:i + 2])
            i += 2
            continue
        if in_arith_or_test:
            out.append(c)
            if text.startswith("))", i) or text.startswith("]]", i):
                in_arith_or_test -= 1
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue

        # ---- $(( 算术替换同样内部不动 ----
        if text.startswith("$((", i):
            # 简化：当作命令替换进入但内容按算术透传到 ))
            j = text.find("))", i + 3)
            seg = text[i:(j + 2) if j != -1 else n]
            out.append(seg)
            i = len(seg) and (i + len(seg))
            cmd_pos = False
            continue

        # ---- 操作符与空白：重置命令位 ----
        if c in _WORD_OPS:
            out.append(c)
            cmd_pos = True
            i += 1
            continue
        if c == "\n":
            out.append(c)
            cmd_pos = True
            in_comment = False
            i += 1
            continue
        if c in " \t":
            out.append(c)
            i += 1
            continue

        # ---- herestring <<<：只透传到行尾（后续词是字符串不是 heredoc 主体）----
        if text.startswith("<<<", i):
            eol = text.find("\n", i)
            seg = text[i:] if eol == -1 else text[i:eol]
            out.append(seg)
            i += len(seg)
            cmd_pos = True
            continue

        # ---- 词：提取到下一个操作符/空白 ----
        j = i
        while j < n and text[j] not in " \t\n" and text[j] not in _WORD_OPS \
                and text[j] not in "\"'#" and not text.startswith("<<", j) \
                and not text.startswith("$((", j) \
                and not (text.startswith("((", j) or text.startswith("[[", j)):
            j += 1
        word = text[i:j]
        if not word:
            # '<' '>' 等未归类字符：单字符透传，绝不空转（r15 教训同源：静默卡死最致命）
            out.append(c)
            i += 1
            continue

        # 赋值前缀 NAME=...：赋值词不动；右侧若是 $(...) 交给上面的状态机
        # （词内含 = 且合法变量名开头 → 赋值；此后下一词仍是命令位）
        m_word_is_assign = "=" in word and not word.startswith("=") and \
            _is_ident(word.split("=", 1)[0]) and word.split("=", 1)[1] != ""

        if is_cmd_pos_here(word) and not m_word_is_assign and word in alias_map:
            out.append(alias_map[word])
            replaced += 1
            advance(word)   # r16-5：传原名（then/do/for 虽被换名，转移照原名）
            i = j
            continue

        # ---- 关键字状态转移（无条件执行，不依赖 is_cmd_pos_here 门——
        #      r16 初版把 do/in 的转移放进门内，for 头部状态卡死殃及全篇）----
        advance(word)

        # r16-5：L4 路径常量（词内子串替换，长串优先）—— 见 rewrite_l4_path。
        # 词级只处理"裸词"；双引号内的内容是逐字符透传的（不进词提取），
        # 由 rewrite_l4_path 统一覆盖（双引号恰好是路径最常见的栖身之处）。

        out.append(word)
        i = j
        continue

    return "".join(out), replaced, skipped


# ---------------------------------------------------------------- L4 路径常量
def rewrite_l4_path(text, table):
    """L4 路径常量改写（子串级，独立 pass）。

    为什么不做命令位判定：路径 token 在任何位置都会在运行时被原样还原，
    替换不改变语义（不像 $@ 这类有上下文语义的东西）。因此唯一必须跳过的
    是【单引号内容】——那里既不展开、运行时也不还原，改了才会真变语义；
    注释同样跳过（纯文本，改它毫无意义）。
    heredoc / 双引号 / 裸词一体通吃，代价远小于在词级状态机里追引号状态
    （初版就踩了：双引号分支逐字符透传，根本不进词提取，引号内全漏改）。
    长串优先：/system/bin 必须先于 /system，否则被短串切碎。
    """
    pm = build_rewrite_map(table, (5,))
    if not pm:
        return text, 0
    keys = sorted(pm, key=len, reverse=True)

    out = []
    i, n = 0, len(text)
    in_single = False
    in_comment = False
    hits = 0

    while i < n:
        c = text[i]
        if in_comment:
            out.append(c)
            if c == "\n":
                in_comment = False
            i += 1
            continue
        if not in_single and c == "#" and \
                (not out or out[-1] in " \t\n;|&("):
            in_comment = True
            out.append(c)
            i += 1
            continue
        if in_single:
            out.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "'":
            in_single = True
            out.append(c)
            i += 1
            continue
        hit = None
        for k in keys:
            if text.startswith(k, i):
                hit = k
                break
        if hit is not None:
            out.append(pm[hit])
            hits += 1
            i += len(hit)
            continue
        out.append(c)
        i += 1

    return "".join(out), hits


# ---------------------------------------------------------------- L4 位置参数
def rewrite_l4_param(text, table):
    """L4 位置参数改写：$N / ${N} → ${alias}（运行时经 find_variable 取当前值）。

    只在真正会展开的上下文改写：单引号内、注释内一律不动；
    `${N` 后接展开操作符（:- :+ # % / = ? [ …）跳过 —— 形参表达式语义复杂，
    宁缺勿滥（漏改处原名照跑，运行时兜底 100% 兼容）。

    运行时语义 = "查别名变量 → 返回当前位置参数"，故取的是**执行到该处时**
    的值：shift 后自动跟随漂移，天然兼容，无需构建期绑定值，也无需像旧设想
    那样做 shift 降级检测。
    注：$# / $@ / $* 不由本层处理（它们走 SPECIAL_VAR / 数组路径，不是
    ordinary 变量，hook find_variable 覆盖不到）。

    ⚠⚠ 红线（r16-5 实测，务必读完再启用）：**本层的 C 端 hook 目前是无效的**。
    bash 的位置参数展开根本不走变量查找——subst.c `param_expand()` 里对
    '$' 后的字符做 switch，case '0'..'9' 直接取全局数组 `dollar_vars[]`
    （见 subst.c ~L10257），与 `legal_number()` 那套并存；只有普通变量名才
    会落到 find_variable。所以 hook find_variable 恒取不到值（实测产物里
    所有 $N 位置全空），且**不会报错**（空变量 = 空串，静默降级，比报错更危险）。
    正确 hook 点在 param_expand（switch 之前把别名还原为数字），但那要在 bash
    核心展开器里复制 splice/quoted 处理，属高风险改动 —— 留到 #28 执行器阶段
    （那一步本就要重写展开层）一起做。
    """
    pmap = build_rewrite_map(table, (4,))
    if not pmap:
        return text, 0

    out = []
    i, n = 0, len(text)
    in_single = False
    in_comment = False
    hits = 0

    while i < n:
        c = text[i]
        if in_comment:
            out.append(c)
            if c == "\n":
                in_comment = False
            i += 1
            continue
        if not in_single and c == "#" and \
                (not out or out[-1] in " \t\n;|&("):
            in_comment = True
            out.append(c)
            i += 1
            continue
        if in_single:
            out.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "'":
            in_single = True
            out.append(c)
            i += 1
            continue
        if c == "$" and i + 1 < n:
            nxt = text[i + 1]
            key = "$" + nxt
            # $N：后随任意字符都安全（bash 只吃一位数字），${alias} 保证定界
            if nxt.isdigit() and key in pmap:
                out.append("${" + pmap[key] + "}")
                hits += 1
                i += 2
                continue
            # ${N}：仅收尾就是 } 的纯形式；${1##*/} 之类一律跳过
            if nxt == "{" and i + 3 < n and text[i + 2].isdigit() and \
                    text[i + 3] == "}" and ("$" + text[i + 2]) in pmap:
                out.append("${" + pmap["$" + text[i + 2]] + "}")
                hits += 1
                i += 4
                continue
        out.append(c)
        i += 1

    return "".join(out), hits


def rewrite_all(text, table, with_param=False):
    """四层全改写流水线。返回 (新文本, 计数字典)。

    顺序：命令位词级（L1/L2/L3）→ L4 路径 → L4 位置参数。

    L4 位置参数默认【关闭】（with_param=False）——原因见 rewrite_l4_param
    的"红线"说明：bash 的 $N 走 subst.c param_expand 的 case '0'..'9'
    快路径（直接取 dollar_vars[]），不经 find_variable，当前 C 端 hook
    覆盖不到它。Python 侧改写能力已就绪，待 #28（C 批次执行器）把展开层
    一并重构时再默认打开。
    """
    text, n_cmd, skipped = rewrite_l12(text, table)
    text, n_path = rewrite_l4_path(text, table)
    n_param = 0
    if with_param:
        text, n_param = rewrite_l4_param(text, table)
    return text, {"cmd": n_cmd, "path": n_path,
                  "param": n_param, "skipped": skipped}


# ---------------------------------------------------------------- CLI
def _cmd_gen(args):
    seed = args.seed
    if seed is not None and seed == 0:
        seed = None
    table, _ = gen_table(seed, n_decoy=args.decoy, n_shadow=args.shadow)
    bin_data = serialize(table)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(bin_data)
    if args.json:
        # JSON 只落**真条目**（改写器用）。诱饵不进 JSON —— 它们不参与
        # 改写，落进来只会让下游误以为要多替换一批词。
        real = [it for it in table if not it.get("decoy")]
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"seed": seed, "table": real}, f,
                      ensure_ascii=False, indent=1)
    # 摘要
    real = [it for it in table if not it.get("decoy")]
    ndec = sum(1 for it in table if it.get("decoy") and not it.get("shadow"))
    nshd = sum(1 for it in table if it.get("shadow"))
    layers = {}
    for it in real:
        layers.setdefault(it["layer"], []).append(it)
    print("表生成 OK：真条目 %d 项 + 幻影 %d + 影子 %d = 表内 %d 项（seed=%s）"
          % (len(real), ndec, nshd, len(table),
             seed if seed is not None else "随机"))
    for ln, items in sorted(layers.items()):
        name = {1: "L1 builtin", 2: "L2 external", 3: "L3 keyword",
                4: "L4 param", 5: "L4 path"}[ln]
        sample = ", ".join("%s→%s" % (it["orig"], it["alias"])
                           for it in items[:4])
        print("  %s（%d）: %s%s" % (name, len(items), sample,
                                    " ..." if len(items) > 4 else ""))
    if args.out:
        print("加密表: %s（%d 字节，表体已加密+MAC，磁盘上无明文）"
              % (args.out, len(bin_data)))


def _cmd_rewrite(args):
    with open(args.table, "r", encoding="utf-8") as f:
        table = json.load(f)["table"]
    with open(args.in_, "r", encoding="utf-8") as f:
        text = f.read()
    # r16-6：结尾字节保真 —— rewrite_l12 的字符级重组会吃掉末尾 \n，
    # 而下游 V6 混淆器按行切块/生成密钥链，最后一行缺 \n 会让块边界错位，
    # 产物运行期密文链中途断裂 → 反篡改摆烂（实测：业务第 1 行输出后 rc=1）。
    had_nl = text.endswith("\n")
    new, cnt = rewrite_all(text, table, with_param=args.with_l4_param)
    if had_nl and not new.endswith("\n"):
        new += "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(new)
    print("改写完成：命令位替换 %d 处（L1 命令 / L2 外部名 / L3 关键字），"
          "路径常量 %d 处，位置参数 %d 处%s"
          % (cnt["cmd"], cnt["path"], cnt["param"],
             "" if args.with_l4_param else
             "（L4 参数默认关：C 端 hook 覆盖不到 $N，见 --with-l4-param）"))
    if args.out:
        print("输出: %s" % args.out)
    return 0  # 勿 return new——sys.exit(str) 会把全文打到 stderr 并 rc=1（r16 初版踩过）


def _cmd_check(args):
    """校验加密表。

    注意：**表里没有真假标记**（刻意不落盘，见 gen_table 注释），所以从
    表文件无从区分真条目/幻影/影子。可校验的只有"结构合法 + 功能完整"：
      ① 解密 + MAC 通过（最要紧：证明密钥配对、未被篡改）
      ② alias 合法（不撞黑名单、是合法标识符）
      ③ layer 分层校验：L1-L5 查层号与 sym 越界；L6（r33d 补）查真名在场
      ④ 48 个真实符号全部被覆盖（否则产物会漏翻译某层；L6 不占符号位，不计入）
    重复项**不能**当错误：幻影复用真 orig、影子复用真 alias 都是设计使然。
    影子位置安全性改由 selftest 守（那里拿得到内存里的标记）。
    """
    with open(args.table, "rb") as f:
        table = deserialize(f.read())

    seen_alias = {}
    for it in table:
        if it["alias"] in BLACKLIST:
            raise ValueError("随机名撞黑名单: %r" % it)
        if not _is_ident(it["alias"]):
            raise ValueError("随机名非法: %r" % it)
        if it["layer"] >= LAYER5_PARAM_TOKEN:
            # r33d：L6 参数密文令牌 —— 记录无 sym（deserialize 置 0），
            # 真名随表走；只校验真名在场（超长已在 serialize 拦）。
            # 此前 check 白名单只认 layer 1..5，混合表校验必炸（层号非法）。
            if not it.get("orig"):
                raise ValueError("L6 条目缺真名: %r" % it)
            seen_alias.setdefault(it["alias"], []).append(it)
            continue
        if not 1 <= it["layer"] <= 5:
            raise ValueError("层号非法: %r" % it)
        if not 0 <= it["sym"] < len(ISA_SYMBOLS):
            raise ValueError("符号 id 越界（无法解析真名）: %r" % it)
        seen_alias.setdefault(it["alias"], []).append(it)

    # L6 条目的 sym 恒为 0，混入统计会把 echo(0) 误标成"已覆盖"
    covered = {it["sym"] for it in table if it["layer"] < LAYER5_PARAM_TOKEN}
    missing = [s for s in range(len(ISA_SYMBOLS)) if s not in covered]
    if missing:
        raise ValueError("表未覆盖 %d 个真实符号（产物会漏翻译）：%s"
                         % (len(missing),
                            ", ".join(ISA_SYMBOLS[s] for s in missing[:8])))

    n_dup = sum(1 for a, g in seen_alias.items() if len(g) > 1)
    print("表校验 OK：%d 项（唯一别名 %d，含影子别名 %d）；"
          "解密+MAC 通过，别名/层号/符号全部合法，48 个真实符号全覆盖"
          % (len(table), len(seen_alias), n_dup))


def _cmd_selftest(_):
    """内置自测：随机化/复现/序列化回环/改写器正反用例。"""
    fails = []

    # r21：自测需要主密钥。仓库里没有就现造一把临时的（不落地到 bash_poc，
    # 免得污染真实配对）—— 只影响本进程内的加解密自洽性验证。
    import tempfile
    if not os.path.exists(_key_h_default_path()):
        _kp = os.path.join(tempfile.mkdtemp(prefix="v7isa_"), "v7_isa_key.h")
        emit_key(_kp, seed=1)
        os.environ["V7_ISA_KEY_H"] = _kp

    def expect(cond, name):
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            fails.append(name)

    # 1. 可复现性 + 随机性
    t1, _ = gen_table(42)
    t2, _ = gen_table(42)
    t3, _ = gen_table(43)
    FIX_SALT = b"\x11" * 16          # 固定 salt 才可比逐字节（实际产物随机）
    expect(serialize(t1, salt=FIX_SALT) == serialize(t2, salt=FIX_SALT),
           "同 seed 两次生成逐字节一致")
    expect(serialize(t1, salt=FIX_SALT) != serialize(t3, salt=FIX_SALT),
           "异 seed 生成不同（随机化）")
    real1 = [it for it in t1 if not it.get("decoy")]
    expect(len({it["alias"] for it in real1}) == len(real1),
           "真条目别名互不重复")

    # 2. 序列化回环（只比四元组：decoy/shadow 标记**刻意不落盘** —— 落了
    #    就等于在表里标注"这条是假的"，掺假立刻失效）
    def _strip(it):
        return {k: it[k] for k in ("layer", "sym", "orig", "alias")}

    rt = deserialize(serialize(t1, salt=FIX_SALT))
    expect([_strip(x) for x in rt] == [_strip(x) for x in t1],
           "加密表序列化/解密回环一致")
    expect(all("decoy" not in x and "shadow" not in x for x in rt),
           "真假标记不落盘（攻击者无法据表区分真假条目）")

    # 2b. r21 表体加密：磁盘产物里搜不到任何 alias 明文
    blob = serialize(t1, salt=FIX_SALT)
    leak = [it["alias"] for it in t1 if it["alias"].encode() in blob]
    expect(not leak, "加密表内无 alias 明文残留（%d 项全检）" % len(t1))
    expect(blob[:5] == b"V7IST" and blob[5] == 3, "表头为 V7IST/v3")

    # 2c. r21 篡改即拒：翻表体任一字节 → MAC 校验失败（fail-closed）
    tampered = bytearray(blob)
    tampered[30] ^= 0x01
    try:
        deserialize(bytes(tampered))
        expect(False, "篡改表体被 MAC 拒绝")
    except ValueError as e:
        expect("MAC" in str(e), "篡改表体被 MAC 拒绝（%s）" % e)

    # 2d. r21 主密钥不匹配即解不开（换把 KM 加密，用默认 KM 解 → 拒）
    km2 = bytes((i * 7 + 3) & 0xFF for i in range(32))
    try:
        deserialize(serialize(t1, salt=FIX_SALT, km=km2))
        expect(False, "主密钥不匹配时解密被拒")
    except ValueError:
        expect(True, "主密钥不匹配时解密被拒")
    # 同一把 KM 加解一致（证明拒因是密钥而非算法）
    expect([_strip(x) for x in
            deserialize(serialize(t1, salt=FIX_SALT, km=km2), km=km2)]
           == [_strip(x) for x in t1], "同主密钥加解自洽")

    # 2e. r21 掺假：幻影/影子存在，且影子严格排在真条目之后
    ndec = sum(1 for it in t1 if it.get("decoy") and not it.get("shadow"))
    nshd = sum(1 for it in t1 if it.get("shadow"))
    expect(ndec > 0 and nshd > 0, "掺假条目已生成（幻影 %d / 影子 %d）"
           % (ndec, nshd))
    shadow_ok = True
    for it in t1:
        if not it.get("shadow"):
            continue
        first = next(t for t in t1 if t["alias"] == it["alias"])
        if first.get("shadow"):
            shadow_ok = False
    expect(shadow_ok, "影子条目均排在其 alias 真条目之后（C 层不会先命中影子）")
    # 幻影 alias 与真 alias 同形态（同前缀同长度）—— 攻击者无法据外形区分
    decoy_alias = [it["alias"] for it in t1
                   if it.get("decoy") and not it.get("shadow")]
    expect(all(a.startswith(ALIAS_PREFIX) and len(a) == len(real1[0]["alias"])
               for a in decoy_alias), "幻影别名与真别名同形态（不可区分）")

    # 3. 改写器正例：命令位替换
    table = [{"layer": 1, "orig": "echo", "alias": "xa9k"},
             {"layer": 2, "orig": "getprop", "alias": "qf2m"}]
    src = 'echo hi\ngetprop ro.build.version | echo ok\n'
    new, cnt, _ = rewrite_l12(src, table)
    expect(cnt == 3 and "xa9k hi" in new and "qf2m ro.build" in new,
           "命令位替换（行首/管道后）")

    # 4. 改写器正反例：引号/注释/heredoc 不动；$() 内部是命令位照常替换
    src2 = ('x="echo notcmd"\ns=\'echo raw\'\n# echo comment\n'
            'echo var\ncat <<EOF\necho in heredoc\nEOF\n'
            'V=$(echo inner)\n')
    new2, cnt2, _ = rewrite_l12(src2, table)
    expect('"echo notcmd"' in new2 and "'echo raw'" in new2
           and "# echo comment" in new2 and "echo in heredoc" in new2
           and "$(xa9k inner)" in new2 and "echo var" not in new2
           and "cat <<EOF\n" in new2 and "\nEOF\n" in new2,
           "引号/注释/heredoc 不误改且换行保留；$()内命令位照常替换")

    # 5. for 头部不误改（in 歧义）
    table3 = [{"layer": 3, "orig": "in", "alias": "kw9"},
              {"layer": 2, "orig": "find", "alias": "fd1"}]
    src3 = 'for x in a b c; do find .; done\necho in\n'
    new3, _, _ = rewrite_l12(src3, table3)
    expect("for x in a b c" in new3 and "fd1 ." in new3,
           "for 头部保留原 in；do 后命令位照常替换")

    # 6. 改写产物语法合法（bash -n）
    import subprocess, tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                     encoding="utf-8") as tf:
        tf.write(new2)
        tmp = tf.name
    r = subprocess.run(["bash", "-n", tmp], capture_output=True)
    os.unlink(tmp)
    expect(r.returncode == 0, "改写产物 bash -n 语法通过")

    # 7. 黑名单防撞：alias 绝不等于原命令名
    bad = [it for it in t1 if it["alias"] in {x["orig"] for x in t1}]
    expect(not bad, "别名不与任何原名冲突")

    # 8. r16-5 L3 关键字：命令位替换，同串出现在非命令位/引号内绝不动
    table_l3 = [{"layer": 3, "orig": "if", "alias": "kwa"},
                {"layer": 3, "orig": "then", "alias": "kwb"},
                {"layer": 3, "orig": "fi", "alias": "kwc"},
                {"layer": 3, "orig": "for", "alias": "kwd"},
                {"layer": 3, "orig": "do", "alias": "kwe"},
                {"layer": 3, "orig": "done", "alias": "kwf"},
                {"layer": 1, "orig": "echo", "alias": "xx1"}]
    src4 = 'if [ -f x ]; then echo hi; fi\nfor i in 1; do echo $i; done\n' \
           'echo "if not kw"\n'
    new4, cnt4, _ = rewrite_l12(src4, table_l3)
    expect("kwa [ -f x ]; kwb xx1 hi; kwc" in new4
           and "kwd i in 1; kwe xx1 $i; kwf" in new4
           and 'xx1 "if not kw"' in new4 and cnt4 >= 7,
           "L3 关键字仅命令位替换（引号内同一串不动，for/do/done 逐一命中）")

    # 9. r16-5 L4 路径常量：词内子串 + 长串优先（/system/bin 先于 /system）
    table_p = [{"layer": 5, "orig": "/system/bin", "alias": "pth9"},
               {"layer": 5, "orig": "/system", "alias": "pth2"},
               {"layer": 5, "orig": "/data", "alias": "pth1"}]
    src5 = 'ls /system/bin/sh\nrm -rf /data/adb\ncp /system/x /data\n' \
           'm="/system/foo"\n' \
           "echo '/system/raw'\n"
    new5, cnt5 = rewrite_l4_path(src5, table_p)
    expect("ls pth9/sh" in new5 and "rm -rf pth1/adb" in new5
           and "cp pth2/x pth1" in new5 and 'm="pth2/foo"' in new5
           and "echo '/system/raw'" in new5,
           "L4 路径常量子串替换（长串优先；双引号内覆盖，单引号内豁免）")

    # 10. r16-5 L4 位置参数：展开处替换；展开操作符/注释/单引号/$@$# 全跳过
    table_a = [{"layer": 4, "orig": "$1", "alias": "pa1x"},
               {"layer": 4, "orig": "$2", "alias": "pa2y"}]
    src6 = 'echo $1 $2x\nout=${1##*/}\nmsg="hi $1"\nl=$2\nc=1 # $1\n' \
           "q='$1'\necho $@ $#\ny=${1}\n"
    new6, cnt6 = rewrite_l4_param(src6, table_a)
    expect("${pa1x} ${pa2y}x" in new6 and "${1##*/}" in new6
           and 'hi ${pa1x}' in new6 and "l=${pa2y}" in new6
           and "c=1 # $1" in new6 and "q='$1'" in new6
           and "$@ $#" in new6 and "y=${pa1x}" in new6 and cnt6 == 5,
           "L4 位置参数：展开处替换，边界形态跳过")

    # 11. 四层流水线产物语法合法
    all_table = table_l3 + table_p + table_a
    src_all = 'if [ -n "$1" ]; then ls /system/bin/cmd $1; fi\n' \
              'for f in /data/x; do echo $f; done\n'
    # L4 参数层默认关闭（$N 快路径红线，见 rewrite_all），本用例就是为它设的
    # ⇒ 必须显式 with_param=True，否则 cnt_all["param"] 恒 0，断言永远假绿/假红。
    new_all, cnt_all = rewrite_all(src_all, all_table, with_param=True)
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                     encoding="utf-8") as tf:
        tf.write(new_all)
        tmp2 = tf.name
    r2 = subprocess.run(["bash", "-n", tmp2], capture_output=True)
    os.unlink(tmp2)
    expect(r2.returncode == 0 and cnt_all["cmd"] > 0 and cnt_all["param"] > 0,
           "四层改写产物 bash -n 语法通过")

    print("=== selftest: %s ===" % ("ALL GREEN" if not fails else "FAIL %d" % len(fails)))
    return 1 if fails else 0


def _cmd_emit_c(args):
    n = emit_c(args.out)
    print("符号表头文件已生成：%s（%d 项）" % (args.out, n))
    return 0


def _cmd_emit_key(args):
    if os.path.exists(args.out) and not args.force:
        print("主密钥已存在，未覆盖：%s（--force 强制重生成；"
              "重生成会让既有表全部作废）" % args.out)
        return 0
    emit_key(args.out, seed=args.seed)
    print("主密钥头文件已生成：%s（32B，X^M 双串存放）" % args.out)
    print("  注意：换密钥 = 既有表全部作废（解密失败 → ISA 静默空转，产物仍可跑）")
    return 0


# ---------------------------------------------------------------- L6 参数令牌
# r27（ShellVMP T1）：把业务脚本里的**静态字符串字面量**换成密文令牌，
# 由自定义 builtin 在 C 层解密后输出。
#
# 核心约束（r24/r26 实测结论，务必遵守）：
#   1. 引号边界**不进 AST** —— `"a"$i"` 与 `"a$i"` 在 AST 里同形。
#      所以令牌化必须在**源码层**做，且令牌必须自包含（可整段 strcmp）。
#   2. 动态变量（$i 等）**不能令牌化**（运行期才有值）。
#   3. 令牌长度**不等长**反而更安全（攻击者无法按长度切分拼接串）。
#
# 提取规则（保守优先，宁可漏改不可误改）：
#   - 只提取**双引号包裹**或**裸词**中「全部由 [A-Za-z0-9 _./:-] 组成」的串
#   - 长度 >= MIN_LEN（太短的令牌化无意义，且易与命令名混淆）
#   - 跳过：单引号内容（不展开语义）、注释、赋值右侧、命令位词
#   - 纯数字/纯路径等有特殊语义的谨慎处理（可配 --skip-numeric）

PARAM_TOKEN_MIN_LEN = 4         # 令牌化的最短字符串长度
PARAM_TOKEN_CHARSET = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " _./:-+=,"
)


def _param_token_safe(content):
    """r33d.1：字符集安全判定（中文字符串支持）。

    r27 初版的纯 ASCII 白名单把中文/全角标点全部拒之门外——业务脚本
    （安卓模块受众）静态串几乎全中文，"字符串令牌化"对它们等于不存在。

    新规则：
      - ASCII 可打印且落在 PARAM_TOKEN_CHARSET 白名单 → 安全
      - **非 ASCII（ord >= 0x80，含中文/全角标点/emoji 等任意 UTF-8）→ 安全**
        依据：L6 链路全程字节级处理（表内 orig 随加密表走、C 端 decode
        是字节 XOR 还原、echo builtin 原样输出），多字节序列不参与
        shell 词法；全角引号「\"\"」不是 ASCII 引号，不构成语法字符。
      - 控制字符（ord < 0x20 与 0x7f）→ 不安全（换行/制表等有词法含义）
    动态类字符（$ ` \\ " '）在调用方 _maybe_add 已先行排除。
    """
    for ch in content:
        if ch in PARAM_TOKEN_CHARSET:
            continue
        o = ord(ch)
        if 0x20 <= o and o != 0x7F and o >= 0x80:
            continue
        return False
    return True


def _gen_param_alias(rng, taken):
    """生成参数令牌名。前缀与 L1-L5 一致（v7p_），但长度**固定为 10**，
    与 L1-L5 的随机段长度分布保持一致，使攻击者无法按长度区分层。"""
    for _ in range(4096):
        s = "v7p_" + "".join(rng.choice(PARAM_TOKEN_ALPHA) for _ in range(10))
        if s not in taken:
            taken.add(s)
            return s
    raise RuntimeError("参数令牌名空间耗尽")


PARAM_TOKEN_ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789_"


def gen_param_tokens(strings, seed=None):
    """为一组业务字符串生成 L6 令牌条目。

    strings: 去重后的字符串列表
    → [{"layer":6, "sym":0, "orig":s, "alias":token}, ...]
    """
    rng = random.Random(seed)
    taken = set()
    out = []
    for s in strings:
        out.append({"layer": LAYER5_PARAM_TOKEN, "sym": 0,
                    "orig": s, "alias": _gen_param_alias(rng, taken)})
    return out


def _is_assignment_rhs(text, quote_pos):
    """判断 quote_pos 处的引号是否是**赋值语句的右侧**（NAME="..."）。

    r27 血案（实测抓到）：`VER="v2.1.3"` 被令牌化成 `VER="v7p_52pafhsg2a"`，
    但随后 `echo "module version $VER"` 里的 `$VER` 展开得到的是**令牌串**，
    而该参数整段（`module version v7p_52pafhsg2a`）不匹配任何令牌
    → 解密失败 → 输出令牌原文。**语义破坏**。

    根因：被赋值的字符串会在**其他位置**（变量展开处）使用，那里不是
    "整词令牌"语境，无法通过整段 strcmp 还原。
    ⇒ 赋值右侧的字符串**一律不令牌化**。

    判定：从 quote_pos 往前扫，跳过空白后若遇到 '='，且 '=' 左侧是合法
    变量名（[A-Za-z_][A-Za-z0-9_]*），则判定为赋值右侧。

    r33d.2 血案（实测抓到）：**数组元素赋值** `_uO[0]="<1021B base64>"`
    未被识别为赋值右侧 —— 回扫变量名时 `[`/`]` 不是 alnum/underscore，
    循环止于 `]`，取出的 name 变成 `"0]"`，首字符是数字 ⇒ 返回 False。
    后果：V6 混淆器产物的指令池 `_uO[i]` / 代码块池 `_3c[i]` 全部被当作
    "普通静态字符串"提取 → 单条 1021B 远超 ISA_MAX_ORIG(512B)
    → serialize() 抛 ValueError，**整条 L6 链路构建失败**。
    修法：回扫前先剥掉一层尾部下标 `[...]`（含 `arr[i]` / `arr[key]`）。
    """
    j = quote_pos - 1
    while j >= 0 and text[j] in " \t":
        j -= 1
    if j < 0 or text[j] != "=":
        return False
    # 排除 == / != / <= / >= 等比较运算符
    if j + 1 < len(text) and text[j+1] == "=":
        return False
    if j > 0 and text[j-1] in "=!<>":
        return False
    # '=' 左侧须是合法变量名（r33d.2：允许尾随数组下标 [expr] / [i][j]）
    k = j - 1
    # 剥掉尾部下标：自右向左整体配对，跳过全部 [..] 片段
    if k >= 0 and text[k] == "]":
        depth = 0
        while k >= 0:
            if text[k] == "]":
                depth += 1
            elif text[k] == "[":
                depth -= 1
                if depth == 0:
                    # 当前 '[' 与某个 ']' 配平；继续左看是否还有相邻下标
                    k -= 1
                    if k >= 0 and text[k] == "]":
                        continue       # 还有前一个下标，继续配对
                    k += 1             # 回退到 '[' 上，作为名字右边界
                    break
            k -= 1
        name_end = k if k >= 0 else j
    else:
        name_end = j
    # 从 name_end 往左扫变量名字符
    k = name_end - 1
    while k >= 0 and (text[k].isalnum() or text[k] == "_"):
        k -= 1
    name = text[k+1:name_end]
    # 剥离下标后 name 必须是纯变量名（防御：下标含空格/表达式时不误判）
    if not name or "[" in name or "]" in name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return True


def extract_static_strings(text, skip_numeric=False, min_len=PARAM_TOKEN_MIN_LEN):
    """从脚本中提取可令牌化的**静态字符串字面量**。

    返回 (字符串列表, 出现位置列表)。
    保守策略：任何拿不准的一律跳过（漏改 = 语义不变，误改 = 产物崩）。
    """
    found = []
    seen = set()
    i, n = 0, len(text)
    in_single = False
    in_comment = False
    in_dquote = False
    dq_start = -1
    dq_is_assign = False

    while i < n:
        c = text[i]
        if in_comment:
            if c == "\n":
                in_comment = False
            i += 1
            continue
        if in_single:
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "#" and (i == 0 or text[i-1] in " \t\n;|&("):
            in_comment = True
            i += 1
            continue
        if c == "'":
            in_single = True
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == '"':
            if in_dquote:
                # 双引号结束：检查内容（赋值右侧跳过 —— 见 _is_assignment_rhs）
                if not dq_is_assign:
                    content = text[dq_start:i]
                    _maybe_add(content, found, seen, skip_numeric, min_len)
                in_dquote = False
            else:
                in_dquote = True
                dq_start = i + 1
                dq_is_assign = _is_assignment_rhs(text, i)
            i += 1
            continue
        if in_dquote:
            i += 1
            continue
        i += 1

    return found


def _maybe_add(content, found, seen, skip_numeric, min_len):
    """判断一个字符串字面量是否值得令牌化。"""
    if len(content) < min_len:
        return
    # 含动态构造（$ ` \ 等）→ 跳过：无法令牌化
    if any(ch in content for ch in ("$", "`", "\\", "'", '"')):
        return
    if not content:
        return
    # 必须全部落在安全字符集内（r33d.1 起：ASCII 白名单 ∪ 任意非 ASCII）
    if not _param_token_safe(content):
        return
    # 纯数字：可能是参数/计数，令牌化收益低且风险高
    if skip_numeric and content.strip().isdigit():
        return
    # 首尾空白不令牌化（引号内空白有语义）
    if content != content.strip():
        return
    if content in seen:
        return
    seen.add(content)
    found.append(content)


def rewrite_param_tokens(text, table):
    """把脚本里的字符串字面量替换为 L6 令牌。

    只处理**双引号包裹**的静态串（与 extract_static_strings 判定一致）。
    返回 (新文本, 替换次数)。
    """
    pm = {it["orig"]: it["alias"] for it in table
          if it["layer"] >= LAYER5_PARAM_TOKEN}
    if not pm:
        return text, 0

    out = []
    i, n = 0, len(text)
    in_single = False
    in_comment = False
    in_dquote = False
    dq_start = -1
    dq_is_assign = False
    hits = 0

    while i < n:
        c = text[i]
        if in_comment:
            out.append(c)
            if c == "\n":
                in_comment = False
            i += 1
            continue
        if in_single:
            out.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "#" and (not out or out[-1] in " \t\n;|&("):
            in_comment = True
            out.append(c)
            i += 1
            continue
        if c == "'":
            in_single = True
            out.append(c)
            i += 1
            continue
        if c == "\\":
            out.append(text[i:i+2])
            i += 2
            continue
        if c == '"':
            if in_dquote:
                content = text[dq_start:i]
                alias = None if dq_is_assign else pm.get(content)
                if alias is not None:
                    out.append(alias)
                    hits += 1
                else:
                    out.append(content)
                out.append('"')
                in_dquote = False
                i += 1
                continue
            in_dquote = True
            dq_start = i + 1
            dq_is_assign = _is_assignment_rhs(text, i)
            out.append('"')
            i += 1
            continue
        if in_dquote:
            i += 1
            continue
        out.append(c)
        i += 1

    return "".join(out), hits


def _cmd_gen_param(args):
    """从脚本提取静态字符串 → 生成 L6 令牌表（可与既有表合并）。"""
    with open(args.in_, "r", encoding="utf-8") as f:
        text = f.read()
    strings = extract_static_strings(text, skip_numeric=args.skip_numeric,
                                     min_len=args.min_len)
    if not strings:
        print("未发现可令牌化的静态字符串（脚本里可能全是动态内容）")
        return 0

    seed = args.seed
    if seed is not None and seed == 0:
        seed = None
    tokens = gen_param_tokens(strings, seed)

    # 合并既有表（若给了 --with-table）
    table = []
    if args.with_table:
        with open(args.with_table, "r", encoding="utf-8") as f:
            table = json.load(f)["table"]
    table = table + tokens

    bin_data = serialize(table)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(bin_data)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"seed": seed, "table": table}, f,
                      ensure_ascii=False, indent=1)

    print("L6 参数令牌生成 OK：%d 条（seed=%s）"
          % (len(tokens), seed if seed is not None else "随机"))
    for t in tokens[:8]:
        print("  %-24s → %s" % (t["orig"][:24], t["alias"]))
    if len(tokens) > 8:
        print("  ...（共 %d 条）" % len(tokens))
    if args.out:
        print("加密表：%s（%d 字节，落盘无明文）" % (args.out, len(bin_data)))
    return 0


def _cmd_rewrite_param(args):
    """把脚本中的静态字符串字面量替换为 L6 令牌。"""
    with open(args.table, "r", encoding="utf-8") as f:
        table = json.load(f)["table"]
    with open(args.in_, "r", encoding="utf-8") as f:
        text = f.read()
    new_text, hits = rewrite_param_tokens(text, table)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(new_text)
    n_tok = sum(1 for it in table if it["layer"] >= LAYER5_PARAM_TOKEN)
    print("L6 参数改写完成：替换 %d 处（表中 %d 条令牌）" % (hits, n_tok))
    print("输出: %s" % args.out)
    return 0


def main():
    ap = argparse.ArgumentParser(description="V7 四层随机化表工具（r16）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="生成四层表（r21：加密 + 掺假）")
    g.add_argument("--seed", type=int, default=None, help="复现种子（缺省随机）")
    g.add_argument("-o", "--out", help="加密表输出路径（.bin）")
    g.add_argument("--json", help="JSON 表输出路径（供改写器/打包器，只含真条目）")
    g.add_argument("--decoy", type=int, default=DECOY_DEFAULT,
                   help="幻影条目数（同形态假条目，默认 %d，0 关闭）"
                        % DECOY_DEFAULT)
    g.add_argument("--shadow", type=int, default=SHADOW_DEFAULT,
                   help="影子条目数（复用真 alias 的错映射，默认 %d，0 关闭）"
                        % SHADOW_DEFAULT)
    g.set_defaults(func=_cmd_gen)

    r = sub.add_parser("rewrite", help="L1/L2 命令位置改写")
    r.add_argument("--table", required=True, help="JSON 表路径")
    r.add_argument("--in", dest="in_", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--with-l4-param", action="store_true",
                   help="一并改写位置参数 $N（默认关：C 端 hook 目前覆盖不到 "
                        "bash 的 $N 快路径，产物会静默取空值——见 rewrite_l4_param 注释）")
    r.set_defaults(func=_cmd_rewrite)

    c = sub.add_parser("check", help="校验二进制表")
    c.add_argument("--table", required=True, help="二进制表路径")
    c.set_defaults(func=_cmd_check)

    e = sub.add_parser("emit-c", help="输出 C 符号表头文件（第二层：sym id → 真名）")
    e.add_argument("-o", "--out", required=True, help="头文件路径（如 v7_isa_syms.h）")
    e.set_defaults(func=_cmd_emit_c)

    k = sub.add_parser("emit-key", help="生成表加密主密钥头文件 v7_isa_key.h")
    k.add_argument("-o", "--out", required=True,
                   help="头文件路径（默认 v7/bash_poc/v7_isa_key.h）")
    k.add_argument("--seed", type=int, default=None, help="复现种子（缺省随机）")
    k.add_argument("--force", action="store_true", help="覆盖已存在的密钥文件")
    k.set_defaults(func=_cmd_emit_key)

    s = sub.add_parser("selftest", help="内置自测")
    s.set_defaults(func=_cmd_selftest)

    # ---- r27（ShellVMP T1）：L6 参数密文令牌 ----
    gp = sub.add_parser("gen-param",
                        help="从脚本提取静态字符串 → 生成 L6 参数令牌表")
    gp.add_argument("--in", dest="in_", required=True, help="业务脚本路径")
    gp.add_argument("-o", "--out", help="加密表输出路径（.bin）")
    gp.add_argument("--json", help="JSON 表输出路径")
    gp.add_argument("--with-table", help="合并既有 JSON 表（L1-L5）")
    gp.add_argument("--seed", type=int, default=None, help="复现种子")
    gp.add_argument("--min-len", type=int, default=PARAM_TOKEN_MIN_LEN,
                    help="令牌化最短长度（默认 %d）" % PARAM_TOKEN_MIN_LEN)
    gp.add_argument("--skip-numeric", action="store_true",
                    help="跳过纯数字字符串（默认不跳，按需开启）")
    gp.set_defaults(func=_cmd_gen_param)

    rp = sub.add_parser("rewrite-param",
                        help="把脚本中静态字符串字面量替换为 L6 令牌")
    rp.add_argument("--table", required=True, help="JSON 表路径")
    rp.add_argument("--in", dest="in_", required=True)
    rp.add_argument("--out", required=True)
    rp.set_defaults(func=_cmd_rewrite_param)

    args = ap.parse_args()
    sys.exit(args.func(args) if args.cmd in ("rewrite", "selftest",
                                             "rewrite-param")
             else args.func(args) or 0)


if __name__ == "__main__":
    main()
