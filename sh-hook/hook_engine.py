#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# -*- coding: utf-8 -*-
"""
hook_engine.py —— sh-hook 之二：表驱动 C 源码插桩引擎（与解释器无关）

是什么
================================================================================
把「往哪个文件的哪一行、插入/替换什么」声明成**锚点表**（ANCHOR_SET），
本引擎负责执行：定位 → 回滚历史形态 → 幂等检查 → 插入 → 写盘。

配套组件：
  discover_tables.py  —— 自动发现"往哪儿插"的候选位置（本引擎的输入之一）

锚点表格式（一个 ANCHOR_SET 描述一个解释器的整套插桩）
================================================================================
    ANCHOR_SETS = {
        "my-shell-1.0": {
            "name": "my-shell-1.0",
            "files": {"kw": "lex.c", "var": "var.c"},   # 槽位 → 文件名
            "ops": [
                # 在 anchor 之后追加 new
                {"file": "kw", "tag": "声明区", "kind": "append_after",
                 "anchor": "int kw_lookup(const char *);\n",
                 "new":    "extern const char *hook_translate_kw(const char *);\n"},
                # 在 anchor 之前插入 new
                {"file": "kw", "tag": "查表前", "kind": "prepend_before",
                 "anchor": "p = ktsearch(&keywords, ident, h);",
                 "new":    "translate_ident(ident);"},
                # 把 site_old 整段替换成 site_new
                {"file": "var", "tag": "变量入口", "kind": "replace",
                 "site_old": "...", "site_new": "...",
                 # 可选：历史形态回滚 [(旧形态, 还原成), ...]
                 "rollback": [(OLD_FORM, SITE_OLD)]},
            ],
        },
    }

用法
================================================================================
    python3 hook_engine.py <anchors.py> --interp my-shell-1.0 --srcdir <源码树>
    python3 hook_engine.py <anchors.py> --list
    python3 hook_engine.py <anchors.py> --interp ... --srcdir ... --dry-run

行为契约
================================================================================
- **幂等**：目标形态已在文中 → 跳过（重复构建安全）。
- **响亮失败**：锚点不匹配 → exit 1 并指名是哪个 tag（绝不静默错位）。
- **回滚带守卫**：历史形态存在且**新形态不在**文中才回滚 —— 若旧形态是
  新形态的前缀，没有这个守卫会把已升级的树降级回去（真实事故，见 README）。
- **dry-run**：只报告，不写盘。

三条铁律（改代码前先读，全部是真实事故）
================================================================================
1. **执行引擎只能有一份**。多入口（CLI/library）只应负责参数解析和文件
   读写，op 的执行必须全部走 run_ops()。两份循环必然漂移（日志丢失就是
   第一个症状）。
2. **回滚的旧形态与新形态绝不能互为子串**。设计锚点表时先自检
   `old in new`；引擎侧的"新形态不在文中"守卫是最后防线，不是借口。
3. **插桩点必须在主执行路径**。引擎无法替你验证语义等价 —— 用探针
   （patch 点后打可观测标记，跑一次真实脚本确认命中）验证后再上表。

出身：从 ShellVMP v7/bash_poc/isa_hook.py（B0 表驱动重构）抽出；
bash-5.2 全套锚点集留存在 ShellVMP 仓库，此处只含引擎与示例。
"""
import argparse
import importlib.util
import os
import sys


# ---------------------------------------------------------------------------
# 核心 op 执行
# ---------------------------------------------------------------------------

def _patch(text, old, new, tag, interp, site_old=None, site_new=None):
    """幂等地把 old 替换成 new；给了 site_old/site_new 时按 site 粒度替换。

    返回 (text, changed)。
    """
    already = (site_new is not None and site_new in text) or \
              (new is not None and new in text)
    if already:
        print("  %s：已 patch，跳过（幂等）" % tag)
        return text, False
    if old not in text:
        sys.stderr.write("错误：%s 锚点不匹配（%s 源码结构已变？）\n" % (tag, interp))
        sys.exit(1)
    if site_old is not None:
        if site_old not in text:
            sys.stderr.write("错误：%s 插桩点不匹配\n" % tag)
            sys.exit(1)
        return text.replace(site_old, site_new, 1), True
    return text.replace(old, new, 1), True


def _rollback(text, op, interp):
    """执行 op 的 rollback 列表：历史形态 → 还原目标。

    **守卫**：仅当"历史形态在文中 && 新形态不在文中"才回滚。
    返回 (text, changed)。
    """
    new_form = op.get("site_new") or op.get("new")
    for old_form, restore_to in op.get("rollback", []):
        if old_form in text and (new_form is None or new_form not in text):
            text = text.replace(old_form, restore_to, 1)
            print("  %s：检测到历史形态，已回滚待升级" % op["tag"])
            return text, True
    return text, False


def run_ops(aset, cache):
    """对 cache（槽位 → 文件文本）执行整套 ops。返回 (changed_slots, cache)。

    **唯一的 op 执行引擎** —— CLI 与库调用都必须经过这里（铁律 1）。
    """
    changed = set()
    for op in aset["ops"]:
        slot = op["file"]
        if slot not in cache:
            sys.stderr.write("错误：%s 引用了未加载的文件槽位 %r\n"
                             % (op.get("tag", "?"), slot))
            sys.exit(2)
        text = cache[slot]

        # ① 回滚历史形态（带"新形态不在文中"守卫）
        text, rolled = _rollback(text, op, aset["name"])
        if rolled:
            changed.add(slot)

        # ② 执行插桩
        kind = op["kind"]
        if kind == "append_after":
            anchor, new = op["anchor"], op["new"]
            if anchor + new in text:
                print("  %s：已 patch，跳过（幂等）" % op["tag"])
            elif anchor not in text:
                sys.stderr.write("错误：%s 锚点不匹配（%s 源码结构已变？）\n"
                                 % (op["tag"], aset["name"]))
                sys.exit(1)
            else:
                text = text.replace(anchor, anchor + new, 1)
                changed.add(slot)
                print("  %s：已追加" % op["tag"])
        elif kind == "prepend_before":
            anchor, new = op["anchor"], op["new"]
            if new + anchor in text:
                print("  %s：已 patch，跳过（幂等）" % op["tag"])
            elif anchor not in text:
                sys.stderr.write("错误：%s 锚点不匹配（%s 源码结构已变？）\n"
                                 % (op["tag"], aset["name"]))
                sys.exit(1)
            else:
                text = text.replace(anchor, new + anchor, 1)
                changed.add(slot)
                print("  %s：已前置插入" % op["tag"])
        elif kind == "replace":
            for field in ("site_old", "site_new"):
                if field not in op:
                    sys.stderr.write("错误：%s 的 replace op 缺少 %s\n"
                                     % (op.get("tag", "?"), field))
                    sys.exit(2)
            text, did = _patch(text, op["site_old"], None, op["tag"],
                               aset["name"],
                               site_old=op["site_old"],
                               site_new=op["site_new"])
            if did:
                changed.add(slot)
                print("  %s：已插桩" % op["tag"])
        else:
            sys.stderr.write("错误：未知 op.kind = %r（支持 append_after / "
                             "prepend_before / replace）\n" % kind)
            sys.exit(2)

        cache[slot] = text
    return changed, cache


# ---------------------------------------------------------------------------
# 文件级应用
# ---------------------------------------------------------------------------

def apply_anchor_set(aset, srcdir, dry_run=False):
    """对一棵源码树应用一套锚点集。返回改动文件数。"""
    print(">> 插桩目标：%s（%s）" % (aset["name"], srcdir))

    paths = {}
    for slot, fname in aset["files"].items():
        p = os.path.join(srcdir, fname)
        if not os.path.isfile(p):
            sys.stderr.write("错误：%s 缺少 %s（槽位 %s）\n"
                             % (aset["name"], fname, slot))
            sys.exit(1)
        paths[slot] = p

    cache = {}
    for slot in aset["files"]:
        with open(paths[slot], "r", encoding="utf-8") as f:
            cache[slot] = f.read()

    changed, cache = run_ops(aset, cache)

    if dry_run:
        names = [aset["files"][s] for s in aset["files"] if s in changed]
        print(">> dry-run：不写盘。会改动 %d 个文件：%s"
              % (len(changed), ", ".join(names) or "（无）"))
    else:
        for slot in changed:
            with open(paths[slot], "w", encoding="utf-8") as f:
                f.write(cache[slot])
        print(">> 已写盘 %d 个文件" % len(changed))

    print("ISA hook patch 全部应用（%s）" % aset["name"])
    return len(changed)


# ---------------------------------------------------------------------------
# 锚点表加载与 CLI
# ---------------------------------------------------------------------------

def load_anchors(path):
    """从 .py 文件加载 ANCHOR_SETS。"""
    spec = importlib.util.spec_from_file_location("sh_hook_anchors", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sets = getattr(mod, "ANCHOR_SETS", None)
    if not isinstance(sets, dict) or not sets:
        sys.stderr.write("错误：%s 未定义非空的 ANCHOR_SETS\n" % path)
        sys.exit(2)
    # 基本形态校验（响亮失败优于运行中途炸）
    for name, aset in sets.items():
        for field in ("name", "files", "ops"):
            if field not in aset:
                sys.stderr.write("错误：锚点集 %r 缺少字段 %r\n" % (name, field))
                sys.exit(2)
    return sets


def _usage(msg=None):
    if msg:
        sys.stderr.write("错误：%s\n" % msg)
    sys.stderr.write(
        "用法:\n"
        "  hook_engine.py <anchors.py> --interp <name> --srcdir <dir> [--dry-run]\n"
        "  hook_engine.py <anchors.py> --list\n")
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description="表驱动 C 源码插桩引擎")
    ap.add_argument("anchors", help="锚点表 .py 文件（须定义 ANCHOR_SETS）")
    ap.add_argument("--interp", help="锚点集名（只有一个时可省略）")
    ap.add_argument("--srcdir", help="解释器源码树根目录")
    ap.add_argument("--dry-run", action="store_true", help="只报告不写盘")
    ap.add_argument("--list", action="store_true", help="列出全部锚点集")
    args = ap.parse_args()

    sets = load_anchors(args.anchors)

    if args.list:
        for k, v in sorted(sets.items()):
            print("%-16s 文件：%s  操作数：%d"
                  % (k, ", ".join(v["files"].values()), len(v["ops"])))
        return 0

    if not args.srcdir:
        _usage("--srcdir 缺失")
    interp = args.interp
    if interp is None:
        if len(sets) == 1:
            interp = next(iter(sets))
        else:
            _usage("存在多个锚点集，须用 --interp 指定（可选：%s）"
                   % ", ".join(sorted(sets)))
    if interp not in sets:
        _usage("未知解释器 %r" % interp)

    apply_anchor_set(sets[interp], args.srcdir, args.dry_run)


if __name__ == "__main__":
    main()
