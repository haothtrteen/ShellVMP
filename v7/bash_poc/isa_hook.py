#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
# 分发内含魔改 bash 的产物时必须提供对应完整源码。
# -*- coding: utf-8 -*-
"""
isa_hook.py —— V7 ISA 四层随机化表 C 端插桩器（表驱动版，幂等）
================================================================================
用法（两种，等价）：

  # ① 旧式：按 bash-5.2 的文件顺序显式传 4 个路径（向后兼容，build_poc.sh 在用）
  python3 isa_hook.py <execute_cmd.c> <y.tab.c> <variables.c> <shell.c>

  # ② 新式：指定解释器 + 源码树根目录（锚点表自动决定要改哪些文件）
  python3 isa_hook.py --interp bash-5.2 --srcdir <bash源码树>

  可加 --dry-run 只报告会改什么、不写盘。

设计
================================================================================
本文件**不含任何 shell 知识**。所有「往哪个文件的哪一行插什么」都在
anchors.py 的锚点表里声明。本文件只做三件事：

  1. 读表 → 按 files 槽位解析出实际路径
  2. 逐 op 执行：回滚历史形态 → 幂等检查 → 锚点定位 → 替换/追加
  3. 任一锚点不匹配 → exit 1（防静默错位，与 xtrace_kill.py 同哲学）

这样加一个新解释器只需在 anchors.py 填一组 ANCHOR_SET，不用改本文件。

幂等与回滚
================================================================================
- 幂等：任一"已应用"形态（site_new / 追加后的 anchor+new）在文中出现即跳过。
- 回滚：部分 op 带 rollback 列表（历史形态 → 还原目标）。执行前若发现某
  历史形态存在且新形态缺席，先还原再重新应用 —— 否则幂等检查会误判
  "源码结构已变"（r16-5 升级时踩过）。
"""
import sys
import os

try:
    from anchors import ANCHOR_SETS, DEFAULT_INTERP
except ImportError:
    sys.stderr.write("错误：找不到 anchors.py（应与本脚本同目录）\n")
    sys.exit(2)


def _patch(text, old, new, tag, site_old=None, site_new=None):
    """幂等地把 old 替换成 new；给了 site_old/site_new 时按 site 粒度替换。

    - new 非 None：检查 new 是否已在文中（已 patch → 跳过）
    - site_new 非 None：检查 site_new 是否已在文中
    - old 不在文中 → 报错退出（响亮失败，不静默错位）
    """
    # 幂等：任一"已应用"形态在文中出现即跳过（new 为 None 时只看 site_new）
    already = (site_new is not None and site_new in text) or \
              (new is not None and new in text)
    if already:
        print("  %s：已 patch，跳过（幂等）" % tag)
        return text, False
    if old not in text:
        sys.stderr.write("错误：%s 锚点不匹配（%s 源码结构已变？）\n" % (tag, ADDED_CTX))
        sys.exit(1)
    if site_old is not None:
        if site_old not in text:
            sys.stderr.write("错误：%s 插桩点不匹配\n" % tag)
            sys.exit(1)
        return text.replace(site_old, site_new, 1), True
    return text.replace(old, new, 1), True


# 报错信息里带上当前解释器名（由 main 设置）
ADDED_CTX = DEFAULT_INTERP


def _rollback(text, op):
    """执行 op 的 rollback 列表：历史形态 → 还原目标。返回 (text, 是否改动)。"""
    for old_form, restore_to in op.get("rollback", []):
        # 只有当"历史形态在、新形态缺席"时才回滚
        new_form = op.get("site_new") or op.get("new")
        if old_form in text and (new_form is None or new_form not in text):
            text = text.replace(old_form, restore_to, 1)
            print("  %s：检测到历史形态，已回滚待升级" % op["tag"])
            return text, True
    return text, False


def _run_ops(aset, cache, dry_run=False):
    """对 cache（slot → 文本）执行整套 ops。返回 (changed_slots, cache)。

    这是唯一的 op 执行引擎 —— 新式/旧式入口都走这里，避免两份逻辑漂移。
    """
    changed = set()
    for op in aset["ops"]:
        slot = op["file"]
        text = cache[slot]

        # ① 回滚历史形态（若无守卫可能误降级已升级的树，见 anchors.py 注释）
        text, rolled = _rollback(text, op)
        if rolled:
            changed.add(slot)

        # ② 执行插桩
        if op["kind"] == "append_after":
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
        elif op["kind"] == "prepend_before":
            # 在 anchor **之前**插入 new。与 append_after 方向相反，
            # 用于"锚点是某条语句的开头、插入内容必须在它前面"的场合。
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
        elif op["kind"] == "replace":
            text, did = _patch(text, op["site_old"], None, op["tag"],
                               site_old=op["site_old"],
                               site_new=op["site_new"])
            if did:
                changed.add(slot)
                print("  %s：已插桩" % op["tag"])
        else:
            sys.stderr.write("错误：未知 op.kind = %r\n" % op["kind"])
            sys.exit(2)

        cache[slot] = text
    return changed, cache


def apply_anchor_set(aset, srcdir, dry_run=False):
    """对一棵源码树应用一套锚点集（--srcdir 新式入口）。返回改动文件数。"""
    global ADDED_CTX
    ADDED_CTX = aset["name"]
    print(">> 插桩目标：%s（%s）" % (aset["name"], srcdir))

    # 解析文件槽位 → 实际路径
    paths = {}
    for slot, fname in aset["files"].items():
        p = os.path.join(srcdir, fname)
        if not os.path.isfile(p):
            sys.stderr.write("错误：%s 缺少 %s（槽位 %s）\n"
                             % (aset["name"], fname, slot))
            sys.exit(1)
        paths[slot] = p

    # 读入（同一文件多个 op 只读写一次）
    cache = {}
    for slot in aset["files"]:
        with open(paths[slot], "r", encoding="utf-8") as f:
            cache[slot] = f.read()

    changed, cache = _run_ops(aset, cache, dry_run)

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


def _usage(msg=None):
    if msg:
        sys.stderr.write("错误：%s\n" % msg)
    sys.stderr.write(
        "用法:\n"
        "  isa_hook.py <execute_cmd.c> <y.tab.c> <variables.c> <shell.c>\n"
        "  isa_hook.py --interp <name> --srcdir <src-tree> [--dry-run]\n"
        "可用 --interp：%s\n"
        "可用 --list 查看全部锚点集\n"
        % ", ".join(sorted(ANCHOR_SETS))
    )
    sys.exit(2)


def main():
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]

    if "--list" in args:
        for k, v in sorted(ANCHOR_SETS.items()):
            print("%-12s 文件：%s  操作数：%d"
                  % (k, ", ".join(v["files"].values()), len(v["ops"])))
        return

    # ---- 新式：--interp / --srcdir ----
    if "--interp" in args or "--srcdir" in args:
        interp = DEFAULT_INTERP
        srcdir = None
        i = 0
        while i < len(args):
            if args[i] == "--interp":
                if i + 1 >= len(args):
                    _usage("--interp 缺少参数")
                interp = args[i + 1]
                i += 2
            elif args[i] == "--srcdir":
                if i + 1 >= len(args):
                    _usage("--srcdir 缺少参数")
                srcdir = args[i + 1]
                i += 2
            else:
                _usage("未知参数 %r" % args[i])
        if srcdir is None:
            _usage("--srcdir 缺失")
        if interp not in ANCHOR_SETS:
            _usage("未知解释器 %r" % interp)
        apply_anchor_set(ANCHOR_SETS[interp], srcdir, dry_run)
        return

    # ---- 旧式：4 个显式路径（向后兼容，build_poc.sh 在用） ----
    if len(args) != 4:
        _usage("参数个数应为 4，实际 %d" % len(args))

    aset = ANCHOR_SETS[DEFAULT_INTERP]
    slots = list(aset["files"].keys())
    explicit = dict(zip(slots, args))

    global ADDED_CTX
    ADDED_CTX = aset["name"]

    cache = {}
    for slot, path in explicit.items():
        if not os.path.isfile(path):
            sys.stderr.write("错误：找不到 %s\n" % path)
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            cache[slot] = f.read()

    changed, cache = _run_ops(aset, cache, dry_run)

    if dry_run:
        print(">> dry-run：不写盘")
    else:
        for slot in changed:
            with open(explicit[slot], "w", encoding="utf-8") as f:
                f.write(cache[slot])

    print("ISA hook patch 全部应用（%s）" % aset["name"])


if __name__ == "__main__":
    main()
