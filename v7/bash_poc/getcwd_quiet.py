#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
# 分发内含魔改 bash 的产物时必须提供对应完整源码。
# -*- coding: utf-8 -*-
"""
getcwd_quiet.py —— 消除 bash 的 getcwd 报错刷屏（B 线 r15）

背景
----
安卓真机（尤其 /data/local/tmp，权限常为 drwxrwx--x「有 x 无 r」）跑产物时，
bash 每次取工作目录都会失败并往 stderr 刷：

    shell-init: error retrieving current directory: getcwd: cannot access parent directories: Permission denied
    job-working-directory: error retrieving current directory: ...

第二条**每执行一条命令刷一次**，把正常输出淹掉，用户第一反应是「产物坏了」。

排查结论（r14）：这不是致命错误。bash 打印后继续执行，退出码与业务逻辑
均正常。但噪音掩盖真实输出，且让使用者误判。

做法
----
全树唯一的报错出口在 builtins/common.c 的 get_working_directory()（全部
`shell-init` / `job-working-directory` / `eterm` 等前缀都由这一个 fprintf
产生，区别只是传入的 for_whom 不同）。给这个 fprintf 加一道运行时开关：

    if (getenv ("V7_GETCWD_WARN") != NULL)
      fprintf (...);

默认静默；需要排障时 `V7_GETCWD_WARN=1 ./app.bash` 即恢复打印，无需重编译
（真机上这点很重要——不能在用户机器上为了看一眼日志再跑一遍交叉编译）。

配套：common.c 原本既没包含 <stdlib.h> 也没用过 getenv，本脚本自动补上
include（幂等，已有则跳过）。

【明确边界】
    只抑制**报错输出**，不修 getcwd 失败本身，也不改动 PWD 语义。
    失败仍返回 NULL，bash 后续行为与上游完全一致。

用法
----
    python3 getcwd_quiet.py <bash源码树/builtins/common.c>      # 原地改写
    python3 getcwd_quiet.py <common.c> --check                  # 仅检查
"""
import sys

TARGET = 'error retrieving current directory'
MARK = "V7_GETCWD_WARN"

# 原文（tab 缩进，三行一段；\\n 在文件里是字面 \n 两字符）
OLD = (
    '\t  fprintf (stderr, _("%s: error retrieving current directory: %s: %s\\n"),\n'
    '\t\t   (for_whom && *for_whom) ? for_whom : get_name_for_error (),\n'
    '\t\t   _(bash_getcwd_errstr), strerror (errno));'
)

NEW = (
    '\t  /* r15：默认静默（安卓 drwxrwx--x 目录下 getcwd 必失败，刷屏淹没有用输出）。\n'
    '\t     需要排障时设 V7_GETCWD_WARN=1 即恢复打印。 */\n'
    '\t  if (getenv ("%s") != NULL)\n'
    '\t    fprintf (stderr, _("%%s: error retrieving current directory: %%s: %%s\\n"),\n'
    '\t\t     (for_whom && *for_whom) ? for_whom : get_name_for_error (),\n'
    '\t\t     _(bash_getcwd_errstr), strerror (errno));' % MARK
)


def ensure_stdlib(text):
    """common.c 未包含 stdlib.h（也没用过 getenv），补上。幂等。"""
    if "#include <stdlib.h>" in text:
        return text, False
    anchor = "#include <stdio.h>"
    if anchor not in text:
        raise SystemExit("错误：找不到 %s 作为 include 锚点（源码结构已变？）" % anchor)
    return text.replace(anchor, anchor + "\n#include <stdlib.h>", 1), True


def process(path):
    text = open(path, "r", encoding="utf-8", errors="surrogateescape").read()

    if TARGET not in text:
        raise SystemExit("错误：%s 中没有 '%s'（不是预期的 bash common.c？）"
                         % (path, TARGET))

    if MARK in text:
        return text, "skip"

    if OLD not in text:
        raise SystemExit(
            "错误：%s 中未匹配到预期的 fprintf 原文块。\n"
            "      可能是 bash 版本/缩进已变——请人工核对 get_working_directory()\n"
            "      后更新本脚本的 OLD 常量，切勿让它静默放过。" % path)

    text, added_inc = ensure_stdlib(text)
    text = text.replace(OLD, NEW, 1)
    return text, "ok" + ("+include" if added_inc else "")


def check(path):
    text = open(path, "r", encoding="utf-8", errors="surrogateescape").read()
    has_target = TARGET in text
    done = MARK in text
    has_stdlib = "#include <stdlib.h>" in text
    print("%s:" % path)
    print("  报错出口存在      : %s" % ("是" if has_target else "否"))
    print("  已静默（含开关）  : %s" % ("是" if done else "否"))
    print("  stdlib.h 已包含   : %s" % ("是" if has_stdlib else "否"))
    if not has_target or not done:
        return 1
    return 0


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
    if not args:
        sys.stderr.write(__doc__ or "")
        return 2
    path = args[0]

    if check_only:
        return check(path)

    new_text, how = process(path)
    if how != "skip":
        with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(new_text)
    print("getcwd 静默：%s → %s" % (
        "已处理（%s）" % how if how != "skip" else "此前已完成，跳过（幂等）", path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
