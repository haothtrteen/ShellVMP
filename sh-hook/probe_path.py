#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_path.py —— sh-hook 之四：主路径探针（规则 3 / G3）

解决什么
================================================================================
G1/G2 产出的是**候选**：候选里混着主路径、旁路、死代码。bash 的
`find_reserved_word` 教训表明——打到旁路上一切"成功"且什么也不发生。
裁决只能靠运行时证据：**插桩点后打可观测标记（探针），构建，跑一段
真实的脚本，命中的才是主执行路径。**

流程
================================================================================
    G2 引用图谱 -- 候选(file:line, 语句边界安全筛选)
      → 自动生成探针锚点表（prepend_before，write(2,...) 系统调用，
        零头文件依赖——mksh/dash 的相关文件没有 stdio.h）
      → hook_engine 打探针（同一引擎，铁律 1；幂等，重跑安全）
      → 增量构建 → 跑探针脚本 → 收集 stderr 的 [PROBE] 行
      → 命中 = 主路径候选；未命中 = 旁路/死代码/未触达

用法
================================================================================
    python3 probe_path.py --srcdir <构建过的树> --table <表名> \
        --build-cmd "make -j4" --shell ./bash \
        [--script "if true; then :; fi"] [--json]

    # 表名省略 --table 时自动跑 G1 取首个命中（--from-g1 行为）。
    # 脚本默认覆盖 if/for/while/case/函数定义/command 构造。

用法契约（改代码前先读）
================================================================================
- **候选行必须是语句边界**才可前插探针：首词是语句关键词（if/for/while/
  return/...）或行尾是 `;`/`{`/`}`。多行语句的中间行（如 dash findstring
  的续行）前插会产生语法错误——跳过并在报告里标注，由 caller 探针覆盖。
- **锚点必须唯一**：候选行文本在文件中不唯一时自动向上扩行拼接；
  扩到文件头仍不唯一则跳过并警告（绝不静默错位）。
- 探针用 `write(2, ...)` + 块内 extern 声明：任何 C 文件可编，无 include
  风险；LP64 下签名与 POSIX write 一致，无重声明冲突。

出身：ShellVMP「通用 hook 点」G3 步骤，落在本子仓库实现。
"""
import argparse
import contextlib
import json
import os
import re
import subprocess
import sys

import discover_callers as dc
import hook_engine

# 语句边界：行首词是语句关键词，或行尾是 ; { }
_STMT_START = {"if", "for", "while", "switch", "return", "do", "else",
               "case", "default", "{"}
# 函数定义头（与 discover_callers.build_func_index 同款）
_HEAD_RE = re.compile(r"^((?:[A-Za-z_]\w*[\s\*]+)+)([A-Za-z_]\w*)\s*\(")


def _probe_safe(line):
    """候选行是否可安全前插探针（语句边界判定）。

    三类禁止（后两个都是真实踩坑）：
    - 预处理行：# 的上下文不是语句；
    - else 段：`else if (...)` 前插语句会拆散 if-else 链
      （else without a previous if）；
    - 非语句边界：多行语句的中间行前插会产生语法错误。
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return False
    m = re.match(r"[A-Za-z_]\w*", s)
    if m and m.group(0) == "else":
        return False
    if m and m.group(0) in _STMT_START:
        return True
    return s[-1] in {";", "{", "}"}


def _dangling_head(prev_line):
    """前一行是否为**无块**控制结构头（for(...)/if(...)/else 单独成行）。

    是 ⇒ 候选行是该结构的 body，前插探针会让探针顶替 body、原语句被
    挤出循环/分支（真实踩坑：continue not within a loop）——候选必须跳过。
    """
    s = prev_line.strip()
    if not s:
        return False
    m = re.match(r"[A-Za-z_]\w*", s)
    return bool(m and m.group(0) in {"if", "for", "while", "switch",
                                     "else", "do"}
                and not s.endswith((";", "{", "}")))


def _load_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _unique_anchor(raw, lines, idx):
    """构造唯一锚点：候选行文本不唯一时向上扩行。

    扩展链上碰到**函数定义行**立即放弃（返回 None）——继续向上会把
    探针推到文件顶层，顶层复合语句非法（真实踩坑：两个函数体一模一样
    时，锚点扩展会一路吞过函数头）。宁可少打一个探针，绝不静默错位。
    """
    a = lines[idx]
    j = idx - 1
    while raw.count(a) > 1:
        # 跳过历史探针行（含 [PROBE]）：重跑时它们插在锚点上方，拼进
        # anchor 会让 new+anchor 不再匹配 → 幂等失效、重复插针
        while j >= 0 and "[PROBE]" in lines[j]:
            j -= 1
        if j < 0 or _HEAD_RE.match(lines[j]):
            return None
        a = lines[j] + "\n" + a
        j -= 1
    return a


def candidates(srcdir, table):
    """从 G2 引用图谱挑探针候选。

    返回 (cands, skipped)：
      cands   = [(file, line1based, owner, role)] —— caller（每 owner 前 8）
                + 语句边界安全的 func-ref；
      skipped = [(file, line, role, 原因)]
    """
    refs, callmap, _ = dc.discover_callers([srcdir], table)
    lines_cache = {}

    def lines_of(f):
        if f not in lines_cache:
            p = os.path.join(srcdir, f)
            lines_cache[f] = (_load_text(p).split("\n")
                              if os.path.isfile(p) else None)
        return lines_cache[f]

    cands, skipped = [], []

    # caller：离执行最近，每 owner 限量防爆炸
    per_owner = {}
    for f, line, role, owner, ctx in refs:
        if role != "caller":
            continue
        base = owner.split("()@")[0]
        per_owner[base] = per_owner.get(base, 0) + 1
        if per_owner[base] > 8:
            skipped.append((f, line, role, "caller 超 8 个/owner（限量）"))
            continue
        L = lines_of(f)
        if L is None:
            skipped.append((f, line, role, "文件不在 srcdir 下"))
            continue
        lt = L[line - 1]
        # 函数定义行上的调用（int main(void) {...} 一行式）：前插会落到
        # 文件顶层，顶层复合语句非法——跳过
        if _HEAD_RE.match(lt) and "{" in lt:
            skipped.append((f, line, role, "函数定义行（前插会落到顶层）"))
            continue
        if not _probe_safe(lt):
            skipped.append((f, line, role, "非语句边界（else 段/预处理/多行语句中）"))
            continue
        if line >= 2 and _dangling_head(L[line - 2]):
            skipped.append((f, line, role, "悬空控制头的 body 行（前插会吞循环体）"))
            continue
        cands.append((f, line, owner, role))

    # func-ref：语句边界安全的才打（宏体/decl 不打——caller 已覆盖执行）
    for f, line, role, owner, ctx in refs:
        if not role.endswith("func-ref"):
            continue
        L = lines_of(f)
        if L is None:
            skipped.append((f, line, role, "文件不在 srcdir 下"))
            continue
        lt = L[line - 1]
        if not _probe_safe(lt):
            skipped.append((f, line, role, "非语句边界（else 段/预处理/多行语句中，caller 已覆盖）"))
            continue
        if line >= 2 and _dangling_head(L[line - 2]):
            skipped.append((f, line, role, "悬空控制头的 body 行（前插会吞循环体）"))
            continue
        cands.append((f, line, owner, role))
    return cands, skipped


def make_probe_set(srcdir, table, cands):
    """把候选变成探针锚点集（ANCHOR_SET 格式，直接喂 hook_engine）。

    返回 (aset, dropped)：锚点无法唯一化的候选进 dropped（不静默混入
    未命中名单——那会误导裁决）。
    """
    files = {}
    ops = []
    dropped = []
    for f, line, owner, role in cands:
        path = os.path.join(srcdir, f)
        raw = _load_text(path)
        lines = raw.split("\n")
        anchor = _unique_anchor(raw, lines, line - 1)
        if anchor is None:
            dropped.append((f, line, role,
                            "锚点无法唯一化（%s，防顶层错位）" % owner))
            continue
        # tag 不含行号：重跑时 G2 扫描行号因探针行漂移，行号进 tag 会
        # 让 new+anchor 不再匹配 → 幂等失效、重复插针。命中粒度 = (file, owner)
        tag = "[PROBE] %s %s" % (f, owner)
        probe = ('{ extern long write(int, const void *, unsigned long); '
                 '(void)write(2, "%s\\n", %d); }\n'
                 % (tag, len(tag) + 1))
        slot = f
        files.setdefault(slot, f)
        ops.append({"file": slot, "tag": tag, "kind": "prepend_before",
                    "anchor": anchor, "new": probe})
    return ({"name": "probe:%s" % table, "files": files, "ops": ops},
            dropped)


def run_build(build_cmd, cwd):
    """增量构建。响亮失败：rc != 0 直接带日志退出。"""
    r = subprocess.run(build_cmd, shell=True, cwd=cwd,
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write("错误：构建失败（rc=%d）\n%s\n%s\n"
                         % (r.returncode, r.stdout[-2000:], r.stderr[-2000:]))
        sys.exit(1)


def run_probe(shell, script, cwd):
    """跑探针脚本，返回 stderr 文本。"""
    r = subprocess.run([shell, "-c", script], cwd=cwd,
                       capture_output=True, text=True, timeout=60)
    return r.stderr


def collect(stderr_text):
    """从 stderr 收集命中的 [PROBE] 标签，返回 {(file, owner)}。

    tag 无行号（见 make_probe_set），命中粒度 = (file, owner)。
    """
    hits = set()
    for m in re.finditer(r"\[PROBE\] (\S+) (.*)", stderr_text):
        hits.add((m.group(1), m.group(2).strip()))
    return hits


def main():
    ap = argparse.ArgumentParser(
        description="主路径探针（规则 3 / G3 原型）")
    ap.add_argument("--srcdir", required=True, help="构建过的源码树")
    ap.add_argument("--table", help="要裁决的表名（省略则自动跑 G1）")
    ap.add_argument("--build-cmd", required=True, help="增量构建命令")
    ap.add_argument("--shell", required=True, help="构建出的解释器路径")
    ap.add_argument("--script",
                    default='if true; then echo P1; fi\n'
                            'for x in 1 2; do :; done\n'
                            'n=0\n'
                            'while [ $n -lt 2 ]; do n=$((n+1)); done\n'
                            'case abc in a*) :;; esac\n'
                            'g() { :; }\n'
                            'if g; then command echo P2; fi\n',
                    help="探针脚本（默认覆盖主要保留字构造 + command）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    table = args.table
    if not table:
        table = dc._load_g1_table([args.srcdir])
        if not table:
            sys.stderr.write("错误：G1 未能发现候选表\n")
            sys.exit(1)

    cands, skipped = candidates(args.srcdir, table)
    if not cands:
        sys.stderr.write("错误：无可用探针候选\n")
        sys.exit(1)
    aset, dropped = make_probe_set(args.srcdir, table, cands)
    skipped = skipped + dropped

    # --json 模式：stdout 只输出 JSON（机器可解析），日志全部走 stderr
    def say(msg):
        print(msg, file=sys.stderr if args.json else sys.stdout)

    say(">> 打探针：%d 个候选（跳过 %d）" % (len(aset["ops"]), len(skipped)))
    if args.json:
        with contextlib.redirect_stdout(sys.stderr):
            hook_engine.apply_anchor_set(aset, args.srcdir)  # 幂等，重跑安全
    else:
        hook_engine.apply_anchor_set(aset, args.srcdir)

    say(">> 增量构建：%s" % args.build_cmd)
    run_build(args.build_cmd, args.srcdir)

    say(">> 跑探针脚本")
    err = run_probe(args.shell, args.script, args.srcdir)
    hits = collect(err)
    hit_keys = {(f, o) for f, o in hits}

    if args.json:
        print(json.dumps({
            "table": table,
            "hit": [{"file": f, "owner": o} for f, o in hits],
            "miss": [{"file": f, "line": l, "owner": o, "role": r}
                     for f, l, o, r in cands if (f, o) not in hit_keys],
            "skipped": [{"file": f, "line": l, "role": r, "why": w}
                        for f, l, r, w in skipped]},
            ensure_ascii=False, indent=2))
        return 0

    print("\n== 主路径裁决（表 %s）==" % table)
    print("命中（主执行路径候选）：")
    for f, o in sorted(hits):
        print("  ✅ %-22s %s" % (o, f))
    if not hits:
        print("  （无 —— 检查探针脚本是否触达相关构造）")
    print("未命中（旁路/死代码/未触达）：")
    for f, l, o, r in sorted(cands):
        if (f, o) not in hit_keys:
            print("  ❌ %-22s %s:%d  (%s)" % (o, f, l, r))
    if skipped:
        print("跳过：")
        for f, l, r, w in skipped:
            print("  ⚠️  %-22s %s:%d  %s" % (r, f, l, w))
    return 0


if __name__ == "__main__":
    sys.exit(main())
