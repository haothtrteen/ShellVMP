#!/usr/bin/env bash
# test_hook_discover.sh —— 保留字表自动发现器回归
# ============================================================================
# 验证 discover_tables.py 能自动找到三个解释器的保留字表。
# 这是"通用 hook 点"方案（docs/GENERIC_HOOK_DESIGN.md 规则 1）的可执行证据。
#
# 发现器位于本仓库子项目 sh-hook/（「sh 通用 hook 点」，git subtree 并入），
# 本测试指向 $REPO/sh-hook/discover_tables.py；目录缺失时整体 SKIP 而非 FAIL。
#
# 找不到某个 shell 的源码树 → SKIP（不 FAIL）：本测试不该因为开发者机器上
# 没放源码而变红。可用环境变量指定：
#   BASH_SRC_DIR / MKSH_SRC_DIR / DASH_SRC_DIR
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SELF_DIR/.." && pwd)"
# 优先本仓库内 sh-hook/（v1.0 起）；兼容历史上曾作为兄弟仓库检出的布局
if [ -f "$REPO/sh-hook/discover_tables.py" ]; then
    TOOL="$REPO/sh-hook/discover_tables.py"
else
    TOOL="$REPO/../sh-hook/discover_tables.py"
fi

BASH_SRC_DIR="${BASH_SRC_DIR:-/tmp/v7test/bash-5.2}"
MKSH_SRC_DIR="${MKSH_SRC_DIR:-/tmp/v7test/mksh-mksh-R59c}"
DASH_SRC_DIR="${DASH_SRC_DIR:-/tmp/v7test/dash-0.5.12/src}"

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP $1"; SKIP=$((SKIP+1)); }

echo "== 保留字表发现器 =="

if [ ! -f "$TOOL" ]; then
    skip "discover_tables.py (子项目 sh-hook 未检出: $TOOL)"
    echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
    exit 0
fi
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$TOOL" \
    && ok "syntax" || bad "syntax"

# --- 期望值：<shell> <目录> <期望表名> <最少命中数> ---
check_shell() {
    local name="$1" dir="$2" want_table="$3" min_hit="$4"
    if [ ! -d "$dir" ]; then
        skip "$name (无源码树 $dir)"
        return
    fi
    local out
    out="$(python3 "$TOOL" "$dir" --min-hit "$min_hit" 2>/dev/null)"
    if printf '%s\n' "$out" | grep -q "\b$want_table\b"; then
        ok "$name 发现 $want_table"
    else
        bad "$name 未能发现 $want_table"
        printf '%s\n' "$out" | sed 's/^/       /'
    fi
}

check_shell "bash" "$BASH_SRC_DIR" "word_token_alist" 4
check_shell "mksh" "$MKSH_SRC_DIR" "tokentab" 4
check_shell "dash" "$DASH_SRC_DIR" "parsekwd" 4

# --- 可复现性：同一棵树跑两次，输出必须完全一致 ---
if [ -d "$MKSH_SRC_DIR" ]; then
    a="$(python3 "$TOOL" "$MKSH_SRC_DIR" 2>/dev/null)"
    b="$(python3 "$TOOL" "$MKSH_SRC_DIR" 2>/dev/null)"
    [ "$a" = "$b" ] && ok "reproducible" || bad "reproducible"
else
    skip "reproducible (无源码树)"
fi

# --- 净化等长自检：这是最容易错的实现点 ---
if python3 - "$TOOL" <<'PYEOF'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("dt", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
# 含字符串内花括号的样本：朴素配平会吃穿
sample = 'char *t[] = { "{", "if", "}", "while", "for", "do" };\nint next;\n'
assert len(m.sanitize(sample)) == len(sample), "sanitize 非等长"
sys.exit(0)
PYEOF
then
    ok "sanitize-length-preserving"
else
    bad "sanitize-length-preserving"
fi

# --- 抗干扰：字符串里的花括号不得让配平失控 ---
if python3 - "$TOOL" <<'PYEOF'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("dt", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
# 表里含 "{" "}"，后面还跟着另一个数组；正确的实现必须只吃到第一个表的 '}'
src = ('static const char *kw[] = {\n "{", "if", "}", "while", "for", "do", "done" };\n'
       'static const char *other[] = { "a", "b" };\n')
clean = m.sanitize(src)
import re
mm = re.search(r'\b(\w+)\s*\[\s*\]\s*=\s*\{', clean)
a, b = m._brace_span(clean, mm.end() - 1)
body = src[a:b]
sts = set(re.findall(r'"((?:\\.|[^"\\])*)"', body))
sys.exit(0 if ("other" not in body and len(sts & m.RESERVED_WORDS) >= 4) else 1)
PYEOF
then
    ok "brace-balance-ignores-string-braces"
else
    bad "brace-balance-ignores-string-braces"
fi

echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
