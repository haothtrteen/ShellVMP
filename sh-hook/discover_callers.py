#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# -*- coding: utf-8 -*-
"""
discover_callers.py —— sh-hook 之三：查表函数与调用点发现（规则 2 / G2）

动机
================================================================================
G1（discover_tables.py）找到了"表"；但插桩真正要落的位置是**查表的函数**
和**调用查表函数的地方**——表只是数据，查询点才是执行路径。

本工具从一张表出发（可手动 --table，或 --from-g1 先跑 G1），自动产出：

    表 T 的引用点
      ├─ decl        函数体外（声明/初始化器）
      ├─ macro       宏体内（沿续行链回溯到 #define）
      ├─ func-ref    函数体内直接引用（附函数名）
      │     └─ caller    该函数 / 宏在全目录的调用点（插桩候选）
      └─ 容器链：函数体引用了 &X 形态的实参时，对容器 X 递归一轮
         （运行时哈希型 shell 的表只被"喂表"引用，真实查询在容器上，
          如 mksh: tokentab → initkeywords → &keywords → ktsearch 调用点）

三壳实测（2026-09，构建过的树）
================================================================================
    bash-5.2   word_token_alist → 宏 CHECK_FOR_RESERVED_WORD 体内(5310，
               展开点 read_token_word:7556/7573 = 解析主路径)
               + 旁路 find_reserved_word(7718，仅 print_cmd.c:1398 一处调用)
               + 传参 8431
    mksh-R59c  tokentab → initkeywords 喂表 → 容器 keywords →
               ktsearch(&keywords,...) 调用点 lex.c:1046 / tree.c:776 / funcs.c:653
    dash-0.5.12 parsekwd → findkwd(parser.c:1632) → 调用点 parser.c:725 + exec.c:788

产出是**候选**，不是结论：死代码孪生、初始化枚举、别名查询都会混进来。
活/死裁决交给探针（规则 3 / G3）。

用法
================================================================================
    python3 discover_callers.py <源码目录> --table <表名>
    python3 discover_callers.py <源码目录> --from-g1          # 先跑 G1 取首个命中
    python3 discover_callers.py <目录> --table T --json

出身：ShellVMP「通用 hook 点」G2 步骤，落在本子仓库实现。
"""
import argparse
import glob
import json
import os
import re
import sys

from discover_tables import sanitize            # 复用 G1 的等长净化

# 函数定义识别的排除词（控制流/操作符，防止 if(...) 被当函数头）
_NOT_FUNC = {"if", "for", "while", "switch", "return", "sizeof",
             "else", "do", "case", "defined"}
# 容器候选提取时排除的常见类型/修饰词（&int、&struct 这类）
_NOT_CONTAINER = {"int", "char", "void", "long", "short", "unsigned", "struct",
                  "union", "enum", "const", "static", "extern", "x", "y", "z",
                  "argv", "argc", "env", "t", "s", "p", "h", "i", "j", "n"}
_CALL_DEPTH = 2                                 # 容器链最大深度


def _sanitize_file(path):
    """读文件，返回 (raw, clean)。clean 与 raw 等长（G1 的契约）。"""
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None, None
    clean = sanitize(raw)
    if len(clean) != len(raw):                  # 净化契约自检（见 G1 三坑之一）
        return raw, None
    return raw, clean


def build_func_index(clean):
    """在净化文本上建函数索引：[(name, body_start, body_end)]。

    识别规则：行首是"若干个 标识符/星号 前缀 + 函数名 + ("——覆盖
    顶格式（返回类型独立一行，GNU 风格）与单行式（static int foo(...)）。
    ')' 之后判定（ANSI '{' / K&R 声明列表 '{' / 原型 ';'）后记录 body 区间。
    """
    # 行首：前缀 token 序列（类型/存储类/星号）+ 函数名 + '('
    head = re.compile(
        r"^((?:[A-Za-z_]\w*[\s\*]+)+)([A-Za-z_]\w*)\s*\(", re.M)
    funcs = []
    for m in head.finditer(clean):
        name = m.group(2)
        if name in _NOT_FUNC:
            continue
        # 找到与之配对的 ')'（简单计数，括号内不会出现字符串——已净化）
        depth = 0
        close = -1
        for k in range(m.end() - 1, min(len(clean), m.end() + 4096)):
            if clean[k] == "(":
                depth += 1
            elif clean[k] == ")":
                depth -= 1
                if depth == 0:
                    close = k
                    break
        if close < 0:
            continue
        # ')' 之后的判定：ANSI 定义 ')' → '{'；K&R 定义 ')' → 参数声明 → '{'；
        # 原型 ')' → ';'。窗口内找第一个 '{' 与第一个 ';'：
        #   无 '{' → 原型或杂项，拒；
        #   ';' 在 '{' 前，且 ')' 与 ';' 之间只有空白 → 原型，拒；
        #   ';' 在 '{' 前但有声明内容 → K&R 定义，接受（body 从 '{' 起）。
        win = clean[close + 1: close + 512]
        brace_off = win.find("{")
        if brace_off < 0:
            continue                            # 无函数体
        semi_off = win.find(";")
        if 0 <= semi_off < brace_off:
            if clean[close + 1: close + 1 + semi_off].strip() == "":
                continue                        # ANSI 原型
            # K&R：body 仍从 '{' 起
        brace = close + 1 + brace_off
        span = _match_brace(clean, brace)
        if span:
            funcs.append((name, span[0], span[1]))
    return funcs


def _match_brace(text, start):
    """净化文本上的花括号配平（字符串已剥掉，可直接计数）。"""
    depth = 0
    for k in range(start, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return start, k + 1
    return None


def _owner_of(pos, funcs):
    """引用点落在哪个函数体内。返回函数名或 None（函数体外）。"""
    best = None
    for name, a, b in funcs:
        if a <= pos < b:
            if best is None or (b - a) < (best[2] - best[1]):
                best = (name, a, b)             # 取最内层（嵌套时）
    return best[0] if best else None


def _macro_owner(raw, pos):
    """从引用位置向上沿续行链（行尾 \\）回溯；链头是 #define 则返回宏名。"""
    line_start = raw.rfind("\n", 0, pos) + 1
    start = line_start
    for _ in range(64):                          # 续行链上限
        prev_end = raw.rfind("\n", 0, start - 1)
        prev = raw[prev_end + 1: start - 1] if start > 1 else ""
        if prev.rstrip().endswith("\\"):
            start = prev_end + 1
        else:
            break
    head = raw[start:raw.find("\n", start)].strip()
    m = re.match(r"#\s*define\s+(\w+)", head)
    if m and start < pos <= raw.find("\n", pos):
        # 引用行必须确实在这条 define 的续行链内
        chain_end = line_start
        k = start
        while True:
            eol = raw.find("\n", k)
            if eol < 0 or not raw[start:eol].rstrip().endswith("\\"):
                chain_end = eol
                break
            k = eol + 1
        if start <= pos <= chain_end:
            return m.group(1)
    return None


def scan_table_refs(dirs, table, tag_prefix=""):
    """在目录里找引用 `table` 的位置。返回 [(file, line, role, owner, ctx)]"""
    refs = []
    for d in dirs:
        for f in (sorted(glob.glob(os.path.join(d, "*.c"))) +
                  sorted(glob.glob(os.path.join(d, "*.h")))):
            raw, clean = _sanitize_file(f)
            if clean is None:
                continue
            funcs = build_func_index(clean)
            for m in re.finditer(r"\b%s\b" % re.escape(table), clean):
                pos = m.start()
                line = raw.count("\n", 0, pos) + 1
                ctx = raw[raw.rfind("\n", 0, pos) + 1:
                          raw.find("\n", pos)].strip()[:100]
                owner = _macro_owner(raw, pos)
                if owner:
                    role, who = "macro", owner
                else:
                    fn = _owner_of(pos, funcs)
                    if fn:
                        role, who = "func-ref", fn
                    else:
                        role, who = "decl", "(file scope)"
                refs.append((os.path.basename(f), line,
                             tag_prefix + role, who, ctx))
    return refs


def _dedup(refs):
    seen, out = set(), []
    for r in refs:
        key = r[:4]
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _find_callers(dirs, owner_name, exclude_lines):
    """在全目录搜 owner_name 的调用点（`name(` 形态，净化文本上命中）。"""
    callers = []
    pat = re.compile(r"\b%s\s*\(" % re.escape(owner_name))
    for d in dirs:
        for f in (sorted(glob.glob(os.path.join(d, "*.c"))) +
                  sorted(glob.glob(os.path.join(d, "*.h")))):
            raw, clean = _sanitize_file(f)
            if clean is None:
                continue
            fname = os.path.basename(f)
            funcs = build_func_index(clean)
            for m in pat.finditer(clean):
                pos = m.start()
                line = raw.count("\n", 0, pos) + 1
                if (fname, line) in exclude_lines:
                    continue
                # 跳过预处理指令行（如 #define CHECK_FOR_RESERVED_WORD(tok) \）
                if raw[raw.rfind("\n", 0, pos) + 1:].lstrip().startswith("#"):
                    continue
                # 排除函数定义自身（顶格、后面配平出函数体）
                if re.match(r"^[A-Za-z_]", raw[raw.rfind("\n", 0, pos) + 1:]) \
                   and _owner_of(pos, funcs) is None:
                    continue
                fn = _owner_of(pos, funcs)
                ctx = raw[raw.rfind("\n", 0, pos) + 1:
                          raw.find("\n", pos)].strip()[:100]
                callers.append((fname, line, "caller",
                                "%s()@%s" % (owner_name, fn or "global"),
                                ctx))
    return _dedup(callers)


def _containers_in(refs, dirs, table, limit=4):
    """从"函数体内引用了 table"的函数提取**实参位置**的 &X 候选。

    依据：喂表函数的形态是"枚举表 + 把容器取地址传给写表函数"
    （如 mksh initkeywords: for (tt = tokentab; ...) ktenter(&keywords, ...)）。
    &X 必须出现在 `(&X` 或 `, &X` 的实参位置，且后面跟 `,` 或 `)`——
    这排除了 sizeof、打印枚举等引用形态。候选按出现频次取前 limit 个
    （原型不做语义裁决，频次是廉价的噪音闸门）。
    """
    pat_arg = re.compile(r"[(,]\s*&([A-Za-z_]\w*)\s*[,)]")
    want = re.compile(r"\b%s\b" % re.escape(table))
    freq = {}
    for d in dirs:
        for f in (sorted(glob.glob(os.path.join(d, "*.c")))):
            raw, clean = _sanitize_file(f)
            if clean is None:
                continue
            funcs = build_func_index(clean)
            for name, a, b in funcs:
                body = clean[a:b]
                if not want.search(body):
                    continue
                for am in pat_arg.finditer(body):
                    c = am.group(1)
                    if c != table and c not in _NOT_CONTAINER:
                        freq[c] = freq.get(c, 0) + 1
    ranked = sorted(freq.items(), key=lambda kv: -kv[1])
    return [c for c, n in ranked[:limit]]


def discover_callers(dirs, table):
    """规则 2 主流程。返回 (refs, callmap, containers_used)。

    refs: 表 T 的全部引用；callmap: {owner: [caller...]}；
    containers_used: 实际展开过的容器链（如 mksh 的 keywords）。
    """
    all_refs = []
    callmap = {}
    containers_used = []

    frontier = [(table, "", _CALL_DEPTH)]
    seen_tables = {table}
    while frontier:
        tab, prefix, depth = frontier.pop(0)
        refs = _dedup(scan_table_refs(dirs, tab, prefix))
        all_refs.extend(refs)

        # ① 调用者发现：宏名 / 函数体内的引用者 → 找它们的调用点
        owners = {who for f, l, role, who, c in refs
                  if role.endswith("macro") or role.endswith("func-ref")}
        for owner in sorted(owners):
            excl = {(f, l) for f, l, r, w, c in refs
                    if w == owner and r.endswith(("macro", "func-ref"))}
            callers = _find_callers(dirs, owner, excl)
            if callers:
                callmap[owner] = callers
                all_refs.extend(callers)

        # ② 容器链：表只被"喂表"引用时（运行时哈希型），真实查询在容器上；
        #    从枚举函数体内的 &X 实参扩展下一层（候选按频次限量，防爆炸）。
        #    "查询形态"= 表名后紧跟 , 或 )，即表被整体当实参/表达式消费
        #    （findstring(s, parsekwd, ...) / ktsearch(&keywords, ...)）——
        #    本层一旦出现，说明真实查询就在本层，不再向下扩展。
        query_form = re.compile(r"\b%s\s*[,)]" % re.escape(tab))
        has_query = any(query_form.search(c) for f, l, r, w, c in refs
                        if r == prefix + "func-ref")
        if depth > 0 and not has_query:
            for c in _containers_in(refs, dirs, tab):
                if c not in seen_tables:
                    seen_tables.add(c)
                    containers_used.append(c)
                    frontier.append((c, "%s→%s " % (prefix, c), depth - 1))
    return _dedup(all_refs), callmap, containers_used


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_g1_table(dirs):
    """跑 G1 取第一个命中的表名（--from-g1 模式）。"""
    from discover_tables import discover
    for d, hits in discover(dirs).items():
        if hits:
            return hits[0][1]                   # (file, name, line, cnt, ov)
    return None


def main():
    ap = argparse.ArgumentParser(
        description="查表函数与调用点发现（规则 2 / G2 原型）")
    ap.add_argument("dirs", nargs="+", help="源码目录（须已构建过）")
    ap.add_argument("--table", help="要追踪的表名")
    ap.add_argument("--from-g1", action="store_true",
                    help="先跑规则 1，用首个命中的表")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    table = args.table
    if args.from_g1:
        table = _load_g1_table(args.dirs)
        if table:
            print("G1 自动选定表：%s" % table)
    if not table:
        ap.error("需要 --table <表名> 或 --from-g1")

    refs, callmap, containers = discover_callers(args.dirs, table)

    if args.json:
        print(json.dumps({"table": table, "containers": containers,
                          "callers": {o: [{"file": f, "line": l,
                                           "owner": w, "ctx": c}
                                          for f, l, r, w, c in cs]
                                      for o, cs in callmap.items()},
                          "refs": [{"file": f, "line": l, "role": r,
                                    "owner": w, "ctx": c}
                                   for f, l, r, w, c in refs]},
                         ensure_ascii=False, indent=2))
        return 0

    print("--- 表 %s 的引用图谱 ---" % table)
    if containers:
        print("（容器链：%s）" % " → ".join([table] + containers))
    for f, l, r, w, c in refs:
        print("  %-6s %-22s %-14s %s:%d  %s" % (r, w, "", f, l, c[:60]))
    print("\n调用者：")
    for owner, cs in sorted(callmap.items()):
        print("  %s：" % owner)
        for f, l, r, w, c in cs:
            print("    %-28s %s:%d  %s" % (w, f, l, c[:60]))
    if not callmap:
        print("  （无 —— 若表只有 decl/feed 引用，见容器链提示；"
              "若函数引用无调用者，疑似死代码）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
