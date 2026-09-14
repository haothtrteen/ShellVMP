#!/usr/bin/env bash
# test_discover.sh —— discover_tables.py 回归
# ============================================================================
# 自包含部分（永远跑）：净化等长、花括号抗干扰、可复现。
# 真实源码树部分（可选）：bash/mksh/dash 三壳发现。
#   环境变量：BASH_SRC_DIR / MKSH_SRC_DIR / DASH_SRC_DIR（缺则 SKIP）
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF_DIR/.." && pwd)"
TOOL="$ROOT/discover_tables.py"

BASH_SRC_DIR="${BASH_SRC_DIR:-}"
MKSH_SRC_DIR="${MKSH_SRC_DIR:-}"
DASH_SRC_DIR="${DASH_SRC_DIR:-}"

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP $1"; SKIP=$((SKIP+1)); }

echo "== 保留字表发现器 =="

python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$TOOL" \
    && ok "syntax" || bad "syntax"

# --- 自包含：内置微型 fixture（合成 C 文件，含字符串内花括号） ---
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT
mkdir -p "$FIX/src"
cat > "$FIX/src/fake_lex.c" <<'EOF'
#include <stdio.h>
static const char *const parsekwd[] = {
	"if", "then", "else", "fi", "while", "for", "do", "done",
	0
};
static const char *other[] = { "a", "b" };
int main(void) { printf("{not a brace test}"); return 0; }
EOF
cat > "$FIX/src/fake_other.c" <<'EOF'
/* 这个数组不该被识别：保留字命中不足 */
static const char *noise[] = { "alpha", "beta", "gamma" };
EOF

out="$(python3 "$TOOL" "$FIX/src" 2>/dev/null)"
printf '%s\n' "$out" | grep -q 'parsekwd' && ok "finds-synthetic-table" \
                                            || bad "finds-synthetic-table"
printf '%s\n' "$out" | grep -q 'noise'    && bad "rejects-low-overlap" \
                                          || ok "rejects-low-overlap"

# --- 可复现 ---
a="$(python3 "$TOOL" "$FIX/src" 2>/dev/null)"
b="$(python3 "$TOOL" "$FIX/src" 2>/dev/null)"
[ "$a" = "$b" ] && ok "reproducible" || bad "reproducible"

# --- 净化等长（最易错的实现点，见 README 三条坑） ---
if python3 - "$TOOL" <<'PYEOF'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("dt", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
sample = 'char *t[] = { "{", "if", "}", "while", "for", "do" };\nint next;\n'
assert len(m.sanitize(sample)) == len(sample), "sanitize 非等长"
sys.exit(0)
PYEOF
then ok "sanitize-length-preserving"
else bad "sanitize-length-preserving"
fi

# --- 花括号配平不受字符串内花括号干扰（表里含 "{" 时朴素计数会吃穿） ---
if python3 - "$TOOL" <<'PYEOF'
import sys, importlib.util, re
spec = importlib.util.spec_from_file_location("dt", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
src = ('static const char *kw[] = {\n "{", "if", "}", "while", "for", "do", "done" };\n'
       'static const char *other[] = { "a", "b" };\n')
clean = m.sanitize(src)
mm = re.search(r'\b(\w+)\s*\[\s*\]\s*=\s*\{', clean)
a, b = m._brace_span(clean, mm.end() - 1)
body = src[a:b]
sts = set(re.findall(r'"((?:\\.|[^"\\])*)"', body))
sys.exit(0 if ("other" not in body and len(sts & m.RESERVED_WORDS) >= 4) else 1)
PYEOF
then ok "brace-balance-ignores-string-braces"
else bad "brace-balance-ignores-string-braces"
fi

# --- 真实源码树（可选） ---
check_shell() {  # $1=name $2=dir $3=want_table
    if [ -z "$2" ] || [ ! -d "$2" ]; then
        skip "$1 (未设 $2 或目录不存在)"
        return
    fi
    local out
    out="$(python3 "$TOOL" "$2" 2>/dev/null)"
    if printf '%s\n' "$out" | grep -q "\b$3\b"; then
        ok "$1 发现 $3"
    else
        bad "$1 未能发现 $3"
        printf '%s\n' "$out" | sed 's/^/       /'
    fi
}
check_shell "bash" "$BASH_SRC_DIR" "word_token_alist"
check_shell "mksh" "$MKSH_SRC_DIR" "tokentab"
check_shell "dash" "$DASH_SRC_DIR" "parsekwd"

echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
