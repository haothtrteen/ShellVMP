#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xtrace_kill.py —— 编译时移除 bash 的调试输出通道（B 线 r15「釜底抽薪」项）

为何要做
--------
`set -x` / `set -v` 是扒壳者最便宜的两招：脚本一旦被解密交给 bash 执行，

    xtrace  —— 打印【展开后】的每条命令
    verbose —— 打印【解密后的原始输入行】，r15 实测 SHELLOPTS=verbose
               可把明文脚本整篇倾倒到 stderr，比 xtrace 泄露更直接

V6 内层已有检测（`[[ $- == *x* ]] && exit 1` + `_am()` 密钥毒化），但那是
「发现就跑」。本脚本换个思路：**让这个能力根本不存在**。

四路处理（都打同一个 V7_KEEP_XTRACE 宏，--keep-xtrace 一次性全恢复）：

  print_cmd.c   xtrace_print_* 共 7 个 void 函数，函数体开头插 return
                —— `set -x` 仍"成功"（$? 0、$- 仍含 x），但零输出
  y.tab.c       parser 读行回显（verbose 主出口）：包 #ifndef
  make_cmd.c    read_secondary_line 回显（verbose 副出口）：包 #ifndef
  shell.c       BASH_ENV 启动前 source（解密前唯一注入点）：整段禁用

为什么 xtrace 用「输出空化」而不是「禁用 -x 标志」
--------------------------------------------------
1. `$-` 保持含 x —— V6 内层把 `$-` 掺进密钥派生（`_7G`），改标志会破坏
   自完整性哈希，导致正常产物解不开；
2. 不产生「illegal option」之类的报错 —— 攻击者无从察觉被阉割；
3. verbose 与 xtrace 共用 V7_KEEP_XTRACE —— 开发者调试时一个开关全恢复。

【明确边界】
    只影响调试**输出**与启动注入点。脚本执行、退出码、参数展开不变。
    y.tab.c 是预生成文件：本脚本只 patch 不 touch parse.y，make 不会
    尝试用 yacc 重新生成（Termux 无 bison 也不影响）。

幂等与失败语义
--------------
已插入则跳过，重复运行不会叠加；任何文件不匹配预期结构一律 sys.exit(1)，
由 build_poc.sh 的 `|| exit 1` 兜住 —— 宁可构建失败，也不产出「以为保护了
其实没保护」的产物。

用法
----
    python3 xtrace_kill.py <print_cmd.c> <y.tab.c> <make_cmd.c> <shell.c>
    python3 xtrace_kill.py <print_cmd.c> --check
"""
import os
import re
import sys

SENTINEL = "#ifndef V7_KEEP_XTRACE"
INSERT = [SENTINEL, "  return;", "#endif"]
SIG_RE = re.compile(r"^xtrace_print_\w+\s*\(")

# ---- 块替换表（按 basename 分发；\\n 在 Python 源里是文件中的字面 \n）----
BLOCK_PATCHES = {
    # verbose 主出口：parser 逐行回显解密后的脚本原文
    "y.tab.c": (
        '\t  if (echo_input_at_read && (shell_input_line[0] ||\n'
        '\t\t\t\t       shell_input_line_terminator != EOF) &&\n'
        '\t\t\t\t     shell_eof_token == 0)\n'
        '\t    fprintf (stderr, "%s\\n", shell_input_line);',
        '  /* r15：verbose 回显会倾倒解密后的脚本原文，见 xtrace_kill.py */\n',
        '\t    fprintf (stderr, "%s\\n", shell_input_line);',
    ),
    # verbose 副出口：read_secondary_line 的回显
    "make_cmd.c": (
        '      if (echo_input_at_read)\n'
        '\tfprintf (stderr, "%s", line);',
        '      /* r15：verbose 回显会倾倒解密后的脚本原文，见 xtrace_kill.py */\n',
        '\tfprintf (stderr, "%s", line);',
    ),
    # BASH_ENV：非交互 shell 启动时先 source 它再读脚本 —— 解密前唯一注入点
    "shell.c": (
        '      if (posixly_correct == 0 && act_like_sh == 0 && privileged_mode == 0 &&\n'
        '\t    sourced_env++ == 0)\n'
        '\texecute_env_file (get_string_value ("BASH_ENV"));',
        '      /* r15：BASH_ENV 是解密前唯一可控注入点，整段禁用（纵深：\n'
        '         zread 的 v7_env_guards 仍会拦 BASH_ENV 环境变量） */\n',
        '\texecute_env_file (get_string_value ("BASH_ENV"));',
    ),
}


def apply_block(path, old, pre_comment, body):
    """把 old 整块包进条件编译（幂等），块内代码原样保留（不加缩进）。

    注意宏方向与 print_cmd.c 相反，这是刻意的：
      - print_cmd.c 是「插入 return」→ #ifndef V7_KEEP_XTRACE
        （默认未定义宏 → return 生效 → 输出空化）
      - 本函数是「包裹原代码」→ #ifdef V7_KEEP_XTRACE
        （默认未定义宏 → 原代码被排除 → 调试输出/BASH_ENV 关闭；
         --keep-xtrace 定义宏 → 原代码恢复）
      r15 初版在这里用反了方向，导致 shell.c 的 BASH_ENV patch 实际
      未生效（实测 EVIL 脚本仍被 source）—— 已实测修正，勿改回。"""
    text = open(path, "r", encoding="utf-8", errors="surrogateescape").read()
    if SENTINEL in text and old not in text:
        return "skip", 0
    if old not in text:
        raise SystemExit("错误：%s 中未匹配到预期原文块（前 40 字节: %r）。\n"
                         "      bash 版本/缩进可能已变——请人工核对后更新"
                         " BLOCK_PATCHES，切勿静默放过。" % (path, old[:40]))
    new = ("#ifdef V7_KEEP_XTRACE\n" + pre_comment + old + "\n#endif")
    return text.replace(old, new, 1), 1


def find_bodies(lines):
    """print_cmd.c：返回 [(签名行 index, '{' 的 index), ...]。"""
    out = []
    for i, line in enumerate(lines):
        if not SIG_RE.match(line):
            continue
        j = i + 1
        while j < len(lines) and lines[j].rstrip() != "{":
            j += 1
        if j >= len(lines):
            raise SystemExit("错误：%s 之后找不到函数体起始的 '{'（源码结构已变？）"
                             % line.strip())
        out.append((i, j))
    return out


def already_done(lines, brace_idx):
    nxt = "\n".join(lines[brace_idx + 1:brace_idx + 6])
    return SENTINEL in nxt


def process_print_cmd(path):
    """xtrace 7 函数空化（原有逻辑）。"""
    text = open(path, "r", encoding="utf-8", errors="surrogateescape").read()
    lines = text.split("\n")
    bodies = find_bodies(lines)
    if not bodies:
        raise SystemExit("错误：%s 中未找到任何 xtrace_print_* 函数"
                         "（不是预期的 bash print_cmd.c？）" % path)
    todo = [b for b in bodies if not already_done(lines, b[1])]
    if not todo:
        return len(bodies), 0
    out = []
    prev = 0
    for _, brace_i in todo:
        out.extend(lines[prev:brace_i + 1])
        out.extend(INSERT)
        prev = brace_i + 1
    out.extend(lines[prev:])
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(out))
    return len(bodies), len(todo)


def main(argv):
    check_only = False
    args = []
    for a in argv:
        if a == "--check":
            check_only = True
        elif a in ("-h", "--help"):
            sys.stdout.write(__doc__ or "")
            return 0
        else:
            args.append(a)

    for path in args:
        if not os.path.isfile(path):
            raise SystemExit("错误：文件不存在 %s" % path)

    summary = []
    for path in args:
        base = os.path.basename(path)
        if base == "print_cmd.c":
            total, done = process_print_cmd(path)
            summary.append("%s: xtrace 函数 %d/%d 空化" % (base, done, total))
        elif base in BLOCK_PATCHES:
            old, pre, _body = BLOCK_PATCHES[base]
            if check_only:
                text = open(path, encoding="utf-8",
                            errors="surrogateescape").read()
                state = "已处理" if (SENTINEL in text and old not in text) \
                    else ("待处理" if old in text else "结构不符！")
                summary.append("%s: %s" % (base, state))
                if state == "结构不符！":
                    return 1
                continue
            res, n = apply_block(path, old, pre, None)
            if n:
                with open(path, "w", encoding="utf-8",
                          errors="surrogateescape") as f:
                    f.write(res)
            summary.append("%s: %s" % (
                base, "已包 #ifndef（幂等跳过）" if not n else "已包 #ifndef"))
        else:
            raise SystemExit("错误：不认识的文件 %s（应为 print_cmd.c / "
                             "y.tab.c / make_cmd.c / shell.c）" % path)

    for s in summary:
        print("  " + s)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
