#!/usr/bin/env bash
# test_probe.sh —— probe_path.py（规则 3 / G3）回归
# ============================================================================
# 自包含部分（永远跑）：假解释器 fixture——打探针→编译→运行→收集命中，
# 验证"活路径命中 / 死代码不命中"的核心裁决。
# 真实源码树部分（可选）：bash / mksh / dash 三壳探针（⚠️ 会在树上留下
# [PROBE] 行并在结束时清理重建）。缺树则 SKIP。
#   环境变量：BASH_SRC_DIR / MKSH_SRC_DIR / DASH_SRC_DIR
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF_DIR/.." && pwd)"
TOOL="$ROOT/probe_path.py"

BASH_SRC_DIR="${BASH_SRC_DIR:-}"
MKSH_SRC_DIR="${MKSH_SRC_DIR:-}"
DASH_SRC_DIR="${DASH_SRC_DIR:-}"

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP $1"; SKIP=$((SKIP+1)); }

echo "== 主路径探针（规则 3）=="

python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$TOOL" \
    && ok "syntax" || bad "syntax"

FIX="$(mktemp -d)"
cleanup_all() { rm -rf "$FIX"; }
trap cleanup_all EXIT
mkdir -p "$FIX/src"

cat > "$FIX/src/fake_interp.c" <<'EOF'
static const char *const kw[] = { "if", "while", 0 };
static int dead_fn(const char *s)
{
    int i;
    for (i = 0; kw[i]; i++)
        if (s[0] != kw[i][0]) continue;
    return -2;
}
static int lookup(const char *s)
{
    int i;
    for (i = 0; kw[i]; i++)
        if (s[0] == kw[i][0]) return i;
    return -1;
}
int main(void)
{
    return lookup("if") >= 0 ? 0 : 1;
}
EOF

# ---- T1：活路径命中 / 死代码不命中 ----
if python3 "$TOOL" --srcdir "$FIX/src" --table kw \
       --build-cmd "gcc -o fake fake_interp.c" --shell "$FIX/src/fake" \
       --script "" --json > "$FIX/probe.json" 2> "$FIX/probe.log"; then
    python3 - "$FIX/probe.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
hit = {(h["file"], h["owner"]) for h in d["hit"]}
miss = {(m["file"], m["owner"]) for m in d["miss"]}
live = any(f == "fake_interp.c" and o.startswith("lookup()@main") for f, o in hit)
dead_hit = any(o == "dead_fn" for f, o in miss)
sys.exit(0 if (live and dead_hit) else 1)
PYEOF
    [ $? -eq 0 ] && ok "live-path-hit-dead-miss" || bad "live-path-hit-dead-miss"
else
    bad "live-path-hit-dead-miss（探针流程退出非零）"
fi

# ---- T2：探针幂等（重跑：裁决语义一致 + 不重复插针）----
N_BEFORE=$(grep -c '\[PROBE\]' "$FIX/src/fake_interp.c")
python3 "$TOOL" --srcdir "$FIX/src" --table kw \
    --build-cmd "gcc -o fake fake_interp.c" --shell "$FIX/src/fake" \
    --script "" --json > "$FIX/probe2.json" 2>/dev/null
N_AFTER=$(grep -c '\[PROBE\]' "$FIX/src/fake_interp.c")
if python3 - "$FIX/probe.json" "$FIX/probe2.json" <<'PYEOF'
import json, sys
d1 = json.load(open(sys.argv[1]))
d2 = json.load(open(sys.argv[2]))
key = lambda d: (sorted((h["file"], h["owner"]) for h in d["hit"]),
                 sorted((m["file"], m["owner"]) for m in d["miss"]))
sys.exit(0 if key(d1) == key(d2) else 1)
PYEOF
   [ "$N_BEFORE" -eq "$N_AFTER" ]; then
    ok "probe-idempotent"
else
    bad "probe-idempotent"
fi

# ---- 真实源码树（可选；测试后清理 [PROBE] 行并重建）----
cleanup_tree() {  # $1=树根 $2=build-cmd
    (cd "$1" && grep -rl '\[PROBE\]' --include='*.c' --include='*.h' . 2>/dev/null \
        | while read -r f; do sed -i '/\[PROBE\]/d' "$f"; done
     eval "$2" >/dev/null 2>&1) &
}

if [ -d "$BASH_SRC_DIR" ]; then
    if python3 "$TOOL" --srcdir "$BASH_SRC_DIR" --table word_token_alist \
           --build-cmd "make -j4" --shell "$BASH_SRC_DIR/bash" --json \
           > "$FIX/bash.json" 2>/dev/null; then
        python3 - "$FIX/bash.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
hit = {(h["file"], h["owner"]) for h in d["hit"]}
main_hit = any(f.endswith("y.tab.c") and "CHECK_FOR_RESERVED_WORD()@read_token_word" in o
               for f, o in hit)
bypass = [x for x in d["miss"] if "find_reserved_word" in x["owner"]]
sys.exit(0 if (main_hit and bypass) else 1)
PYEOF
        [ $? -eq 0 ] && ok "bash: 主路径命中 + find_reserved_word 自动拒绝" \
            || bad "bash: 主路径/旁路裁决"
    else
        bad "bash: 探针流程失败"
    fi
    cleanup_tree "$BASH_SRC_DIR" "make"
else
    skip "bash (未设 BASH_SRC_DIR)"
fi

if [ -d "$MKSH_SRC_DIR" ]; then
    if python3 "$TOOL" --srcdir "$MKSH_SRC_DIR" --table tokentab \
           --build-cmd "sh Build.sh -r" --shell "$MKSH_SRC_DIR/mksh" --json \
           > "$FIX/mksh.json" 2>/dev/null; then
        python3 - "$FIX/mksh.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
hit = any(h["file"] == "lex.c" and h["owner"] == "yylex" for h in d["hit"])
sys.exit(0 if hit else 1)
PYEOF
        [ $? -eq 0 ] && ok "mksh: yylex 查询点命中" || bad "mksh: yylex 命中"
    else
        bad "mksh: 探针流程失败"
    fi
    cleanup_tree "$MKSH_SRC_DIR" "sh Build.sh -r"
else
    skip "mksh (未设 MKSH_SRC_DIR)"
fi

if [ -d "$DASH_SRC_DIR" ]; then
    if python3 "$TOOL" --srcdir "$DASH_SRC_DIR" --table parsekwd \
           --build-cmd "make" --shell "$DASH_SRC_DIR/dash" --json \
           > "$FIX/dash.json" 2>/dev/null; then
        python3 - "$FIX/dash.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
hit = any(h["file"] == "parser.c" and h["owner"].startswith("findkwd()@readtoken")
          for h in d["hit"])
sys.exit(0 if hit else 1)
PYEOF
        [ $? -eq 0 ] && ok "dash: findkwd@readtoken 命中" || bad "dash: findkwd 命中"
    else
        bad "dash: 探针流程失败"
    fi
    cleanup_tree "$DASH_SRC_DIR" "make"
else
    skip "dash (未设 DASH_SRC_DIR)"
fi

echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
