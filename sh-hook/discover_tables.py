#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# -*- coding: utf-8 -*-
"""
discover_tables.py —— sh-hook 之一：自动发现解释器的"保留字表"（规则 1）

动机
================================================================================
给解释器打 C 层插桩补丁，最难的一步是「往哪儿插」—— 每个 shell 的
保留字表叫什么名字、在哪个文件，事先不知道，只能逐个读源码。

但这件事**可以自动搜出来**：保留字表在数据形态上高度同构 ——
都是"一个数组，成员是一批 shell 保留字字符串"。本工具就是找这个形态。

用法
================================================================================
    python3 discover_tables.py <源码目录> [<源码目录> ...]
    python3 discover_tables.py <目录> --min-hit 6 --json

⚠️ **必须扫"构建过的"树，不能只扫 pristine 源码。**
   dash 的 parsekwd[] 由 mktokens 在构建时生成到 src/token_vars.h；
   只扫原始 tarball 会漏掉它。先 ./configure && make 一次再扫。

实测（2026-09，见 docs/DESIGN.md 同构证据一节）
================================================================================
    bash-5.2          → y.tab.c        word_token_alist  命中 22
    mksh-R59c         → syn.c          tokentab          命中 15
    dash-0.5.12/src   → token_vars.h   parsekwd          命中 16

三个 shell 全部自动命中。

实现要点（三条坑，改代码前先读）
================================================================================
1. **等长净化**：剥注释/字符串时必须**长度不变**，否则"用净化文本定位、
   回原文取内容"的偏移会全乱（第一版原型就栽在这，表现为"匹配上了却取不到"）。
2. **先剥字符串再配平花括号**：保留字表里含 `"{"`/`"}"`，朴素计数永不配平。
3. **扫构建后的树**：见上。

产出是**候选**，不是结论：发现 ≠ 可以插桩。确认语义等价（尤其"是否在
主执行路径"）之后，把位置写进下游插桩框架的锚点表（见 hook_engine.py）。

出身：从 ShellVMP（v7/bash_poc）的插桩工作中抽出，见 docs/DESIGN.md。
"""
import argparse
import glob
import json
import os
import re
import sys

# shell 保留字的超集（各 shell 的并集）。表命中 >=min_hit 个即视为候选。
RESERVED_WORDS = {
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "while",
    "until", "do", "done", "select", "function", "in", "time", "{", "}", "!",
    "[[", "]]", "coproc", "repeat", "foreach", "end",
}

# 需要净化的构造（顺序重要：先注释，后字面量）
_STRIP_PATTERNS = (
    r'/\*.*?\*/',                    # C 块注释
    r'//[^\n]*',                     # C++ 行注释
    r'"(?:\\.|[^"\\\n])*"',          # 字符串字面量
    r"'(?:\\.|[^'\\\n])*'",          # 字符字面量
)


def _blank(match):
    """等长替换：保留换行（维持行号），其余字符变空格。

    **关键**：长度必须与原串完全一致，否则任何基于偏移的二次定位都会错位。
    """
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def sanitize(text):
    """把注释与字面量替换成等长空白。返回串与入参**等长**。"""
    for pat in _STRIP_PATTERNS:
        text = re.sub(pat, _blank, text, flags=re.S)
    return text


def _brace_span(text, start):
    """从 start（指向 '{'）找到配对 '}' 之后的位置。

    要求 text 已经 sanitize 过 —— 否则字符串里的花括号会破坏计数。
    返回 (begin, end) 或 None。
    """
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    for k in range(start, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return start, k + 1
    return None                      # 不配平（可能被宏截断），放弃


def find_tables_in_file(path, min_hit=4):
    """在一个文件里找候选保留字表。返回 [(表名, 行号, 命中数, 命中列表)]。"""
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []

    clean = sanitize(raw)
    # 自检：净化必须等长，否则下面的偏移复用就是错的
    if len(clean) != len(raw):
        return []

    out = []
    for m in re.finditer(r"\b(\w+)\s*\[\s*\]\s*=\s*\{", clean):
        span = _brace_span(clean, m.end() - 1)
        if span is None:
            continue
        a, b = span
        body = raw[a:b]                                  # 同偏移取原文 ⇒ 字面量完好
        strs = set(re.findall(r'"((?:\\.|[^"\\])*)"', body))
        overlap = strs & RESERVED_WORDS
        if len(overlap) >= min_hit:
            line = raw.count("\n", 0, m.start()) + 1
            out.append((m.group(1), line, len(overlap), sorted(overlap)))
    return out


def discover(dirs, min_hit=4):
    """扫描若干目录下的 *.c / *.h，返回 {目录: [(文件, 表名, 行, 命中数, 命中)]}"""
    result = {}
    for d in dirs:
        files = (sorted(glob.glob(os.path.join(d, "*.c"))) +
                 sorted(glob.glob(os.path.join(d, "*.h"))))
        hits = []
        for f in files:
            for name, line, cnt, ov in find_tables_in_file(f, min_hit):
                hits.append((os.path.basename(f), name, line, cnt, ov))
        result[d] = hits
    return result


def main():
    ap = argparse.ArgumentParser(
        description="自动发现解释器的保留字表（规则 1 原型）")
    ap.add_argument("dirs", nargs="+", help="源码目录（须已构建过）")
    ap.add_argument("--min-hit", type=int, default=4,
                    help="最少命中几个保留字才认作候选表（默认 4）")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args()

    res = discover(args.dirs, args.min_hit)

    if args.json:
        print(json.dumps({
            d: [{"file": f, "table": n, "line": l, "hits": c, "words": ov}
                for f, n, l, c, ov in hs]
            for d, hs in res.items()}, ensure_ascii=False, indent=2))
        return 0

    bad = 0
    for d, hits in res.items():
        files = (sorted(glob.glob(os.path.join(d, "*.c"))) +
                 sorted(glob.glob(os.path.join(d, "*.h"))))
        print("--- %s (%d 个文件) ---" % (d, len(files)))
        if not hits:
            print("  （未发现候选表）")
            print("  提示：确认该目录已构建过（dash 的 parsekwd 在生成文件里）")
            bad += 1
            continue
        for f, n, l, c, ov in hits:
            print("  ✅ %-16s %-20s:%-5d 命中%2d: %s"
                  % (f, n, l, c, ",".join(ov[:8])))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
