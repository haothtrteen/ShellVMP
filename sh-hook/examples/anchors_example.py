#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# -*- coding: utf-8 -*-
"""
anchors_example.py —— 示例锚点集：演示 ANCHOR_SET 格式与引擎行为

fixture-shell 是 tests/test_engine.sh 生成的假想解释器（fixture.c），
不是真实 shell —— 它存在的意义是让引擎测试**自包含**（不依赖任何
真实 shell 源码树），并覆盖三类 op 与回滚守卫。

真实解释器的锚点集请参考 ShellVMP 仓库的 v7/bash_poc/anchors.py
（bash-5.2 全套 + mksh-R59c 试验性 L3）。
"""

# ---- op 2 的形态族（演示 replace + 历史形态回滚）----
SITE_OLD = (
    "int feed(const char *tok) { CHECK_KW(tok); return lookup_word(tok); }\n"
)
# r1 旧形态：只接管了命令词，没有 hook_kw 定义（伪造的历史演进）
SITE_OLD_V1 = (
    "int feed(const char *tok) { CHECK_KW(tok); return lookup_word(tok) + 1; }\n"
)
SITE_NEW = (
    "int hook_kw(const char *t) { return t[0] == 'i' || t[0] == 'w'; }\n"
    "int feed(const char *tok) { CHECK_KW(tok); return hook_kw(tok) && lookup_word(tok); }\n"
)

# ---- op 1 的形态族（演示 append_after + 前缀包含陷阱）----
# 注意：DECL_OLD 是 DECL_NEW 的**前缀** —— 这正是引擎"新形态不在文中"
# 守卫要防的场景：已升级的树绝不能被回滚降级（见 README 三条铁律）。
DECL_NEW = (
    "/* sh-hook: hook_kw 前置声明（由锚点表注入） */\n"
    "int hook_kw(const char *t);\n"
)
DECL_OLD = (
    "/* sh-hook: hook_kw 前置声明（由锚点表注入） */\n"
)


ANCHOR_SETS = {
    "fixture-shell": {
        "name": "fixture-shell",
        "files": {"kw": "fixture.c"},
        "ops": [
            {
                "file": "kw",
                "tag": "fixture 声明区",
                "kind": "append_after",
                "anchor": "#define CHECK_KW(tok) do { scan_kw(tok); } while (0)\n",
                "new": DECL_NEW,
                "rollback": [
                    # 旧形态 = 只有注释行（新形态的前缀！）→ 还原成裸锚点
                    ("#define CHECK_KW(tok) do { scan_kw(tok); } while (0)\n"
                     + DECL_OLD,
                     "#define CHECK_KW(tok) do { scan_kw(tok); } while (0)\n"),
                ],
            },
            {
                "file": "kw",
                "tag": "fixture 查表点",
                "kind": "replace",
                "site_old": SITE_OLD,
                "site_new": SITE_NEW,
                "rollback": [
                    (SITE_OLD_V1, SITE_OLD),
                ],
            },
        ],
    },
}
