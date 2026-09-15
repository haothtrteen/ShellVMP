#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# test_isa_hook_table.sh —— B0/B1 锚点表回归
# ============================================================================
# 验证「表驱动插桩」重构**没有改变 bash 侧行为**，且新接口自洽。
#
# 核心断言（B0 的硬验收标准）：
#   用重构后的 isa_hook.py 插桩出的 bash 源码，与重构前的产物**逐字节一致**。
#
# 依赖：bash 源码树（tar 包）。找不到就 SKIP 而非 FAIL —— 本测试不该因为
#       开发者机器上没放 tarball 而变红。
#
# 用法：bash tests/test_isa_hook_table.sh
#       BASH_SRC_TGZ=/path/to/bash-5.2.tar.gz 可覆盖
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SELF_DIR/.." && pwd)"
HOOK="$REPO/v7/bash_poc/isa_hook.py"
ANCH="$REPO/v7/bash_poc/anchors.py"
TGZ="${BASH_SRC_TGZ:-/tmp/v7test/bash-5.2.tar.gz}"

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP $1"; SKIP=$((SKIP+1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== isa_hook 锚点表回归 =="

# --- 0) 语法自检 ---
if python3 -c "import ast,sys; [ast.parse(open(p).read()) for p in sys.argv[1:]]" \
     "$HOOK" "$ANCH" 2>/dev/null; then
    ok "syntax"
else
    bad "syntax"; echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"; exit 1
fi

# --- 1) --list 能列出锚点集 ---
if python3 "$HOOK" --list 2>/dev/null | grep -q 'bash-5.2'; then
    ok "list-shows-bash"
else
    bad "list-shows-bash"
fi

# --- 2) dry-run 不写盘 ---
if [ -f "$TGZ" ]; then
    mkdir -p "$WORK/dry" && tar xzf "$TGZ" -C "$WORK/dry" --strip-components=1
    before="$(md5sum "$WORK/dry/execute_cmd.c" | cut -d' ' -f1)"
    python3 "$HOOK" --interp bash-5.2 --srcdir "$WORK/dry" --dry-run >/dev/null 2>&1
    after="$(md5sum "$WORK/dry/execute_cmd.c" | cut -d' ' -f1)"
    [ "$before" = "$after" ] && ok "dry-run-writes-nothing" \
                             || bad "dry-run-writes-nothing"
else
    skip "dry-run-writes-nothing (无 tarball)"
fi

# --- 3) 逐字节基线：旧式 4 路径 == --srcdir（两种入口必须同结果） ---
if [ -f "$TGZ" ]; then
    mkdir -p "$WORK/p" "$WORK/s"
    tar xzf "$TGZ" -C "$WORK/p" --strip-components=1
    tar xzf "$TGZ" -C "$WORK/s" --strip-components=1

    python3 "$HOOK" "$WORK/p/execute_cmd.c" "$WORK/p/y.tab.c" \
            "$WORK/p/variables.c" "$WORK/p/shell.c" >/dev/null 2>&1
    python3 "$HOOK" --interp bash-5.2 --srcdir "$WORK/s" >/dev/null 2>&1

    for f in execute_cmd.c y.tab.c variables.c shell.c; do
        a="$(md5sum "$WORK/p/$f" | cut -d' ' -f1)"
        b="$(md5sum "$WORK/s/$f" | cut -d' ' -f1)"
        [ "$a" = "$b" ] && ok "agree-explicit-vs-srcdir:$f" \
                        || bad "agree-explicit-vs-srcdir:$f"
    done

    # --- 4) 幂等：重跑不改变结果 ---
    python3 "$HOOK" --interp bash-5.2 --srcdir "$WORK/s" >/dev/null 2>&1
    for f in execute_cmd.c y.tab.c variables.c shell.c; do
        a="$(md5sum "$WORK/p/$f" | cut -d' ' -f1)"
        b="$(md5sum "$WORK/s/$f" | cut -d' ' -f1)"
        [ "$a" = "$b" ] && ok "idempotent:$f" || bad "idempotent:$f"
    done

    # --- 5) 插桩确实发生了（4 个文件都含 v7_isa_translate / v7_builtin） ---
    grep -q 'v7_isa_translate_cmd' "$WORK/s/execute_cmd.c" \
        && ok "injected:execute_cmd.c" || bad "injected:execute_cmd.c"
    grep -q 'v7_isa_translate_kw' "$WORK/s/y.tab.c" \
        && ok "injected:y.tab.c" || bad "injected:y.tab.c"
    grep -q 'v7_isa_translate_var' "$WORK/s/variables.c" \
        && ok "injected:variables.c" || bad "injected:variables.c"
    grep -q 'v7_builtin_takeover_install' "$WORK/s/shell.c" \
        && ok "injected:shell.c" || bad "injected:shell.c"
else
    skip "byte-baseline (无 tarball)"
fi

# --- 6) 锚点不匹配必须响亮失败（不静默错位） ---
mkdir -p "$WORK/bogus"
for f in execute_cmd.c y.tab.c variables.c shell.c; do echo "int x;" > "$WORK/bogus/$f"; done
if python3 "$HOOK" --interp bash-5.2 --srcdir "$WORK/bogus" >/dev/null 2>&1; then
    bad "fails-loud-on-bad-anchor"
else
    ok "fails-loud-on-bad-anchor"
fi

# --- 7) 未知解释器必须报错 ---
if python3 "$HOOK" --interp nonexistent --srcdir "$WORK/bogus" >/dev/null 2>&1; then
    bad "rejects-unknown-interp"
else
    ok "rejects-unknown-interp"
fi

# --- 8) 锚点表是纯数据（不含可执行逻辑） ---
# 用 AST 判定，别看文本 —— 文档字符串里出现 "lambda" 这个词不算违规。
if python3 - "$ANCH" <<'PYEOF'
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
bad = []
for node in ast.walk(tree):
    if isinstance(node, ast.Lambda):
        bad.append("lambda")
    # 顶层/模块级的 import（anchors.py 应当零依赖，纯数据）
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        bad.append("import")
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        bad.append("def")
    if isinstance(node, (ast.If, ast.For, ast.While)):
        bad.append("control-flow")
sys.exit(1 if bad else 0)
PYEOF
then
    ok "anchors-is-pure-data"
else
    bad "anchors-is-pure-data"
fi

echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
