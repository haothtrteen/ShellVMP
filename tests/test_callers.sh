#!/usr/bin/env bash
# test_callers.sh —— discover_callers.py（规则 2 / G2）回归
# ============================================================================
# 自包含部分（永远跑）：合成 C fixture 覆盖三种引用形态 ——
#   direct（表→查表函数→调用者）、macro（宏体内引用→展开点）、
#   hash 链（表→喂表函数→&容器→查询函数）、死代码（引用但无调用者）。
# 真实源码树部分（可选）：bash / mksh / dash 三壳发现，缺树则 SKIP。
#   环境变量：BASH_SRC_DIR / MKSH_SRC_DIR / DASH_SRC_DIR
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF_DIR/.." && pwd)"
TOOL="$ROOT/discover_callers.py"

BASH_SRC_DIR="${BASH_SRC_DIR:-}"
MKSH_SRC_DIR="${MKSH_SRC_DIR:-}"
DASH_SRC_DIR="${DASH_SRC_DIR:-}"

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP $1"; SKIP=$((SKIP+1)); }

json() {  # 跑工具并输出 JSON；$1=目录 $2=表名
    python3 "$TOOL" "$1" --table "$2" --json 2>/dev/null
}

echo "== 查表函数/调用点发现器（规则 2）=="

python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$TOOL" \
    && ok "syntax" || bad "syntax"

FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT
mkdir -p "$FIX/src"

# ---- fixture 1：direct 型 + 死代码 ----
cat > "$FIX/src/fake_direct.c" <<'EOF'
static const char *const parsekwd[] = { "if", "then", "else", 0 };
static int dead_lookup(const char *s)
{
    int i;
    for (i = 0; parsekwd[i]; i++)
        if (s[0] == parsekwd[i][0]) return i;
    return -1;
}
static const char *const *findstr(const char *s, const char *const *t)
{
    return t;
}
int findkw(const char *s)
{
    const char *const *p = findstr(s, parsekwd);
    return p ? (int)(p - parsekwd) : -1;
}
int readcmd(const char *w)
{
    if (findkw(w) >= 0) return 1;
    return 0;
}
EOF

# ---- fixture 2：宏体内引用 + 展开点 ----
cat > "$FIX/src/fake_macro.c" <<'EOF'
static const char *const kwtab[] = { "if", "else", 0 };
#define CHECK_KW(t) do { \
    int i; \
    for (i = 0; kwtab[i].w; i++) \
        if (t[0] == kwtab[i].w[0]) return 1; \
} while (0)
int parse_one(const char *tok)
{
    CHECK_KW(tok);
    return 0;
}
EOF

# ---- fixture 3：hash 容器链（表→喂表→&容器→查询函数）----
cat > "$FIX/src/fake_hash.c" <<'EOF'
static const char *const tokentab[] = { "if", "while", 0 };
struct tbl { int flag; };
static struct tbl kwtab;
static struct tbl *tbl_enter(struct tbl *t, const char *n)
{
    return t;
}
static struct tbl *ktsearch(struct tbl *t, const char *s)
{
    return t;
}
static void initkw(void)
{
    int i;
    for (i = 0; tokentab[i]; i++)
        tbl_enter(&kwtab, tokentab[i]);
}
int yylex(const char *ident)
{
    if (ktsearch(&kwtab, ident)) return 1;
    return 0;
}
EOF

# ---- T1 direct：查表函数与调用者 ----
J="$(json "$FIX/src" parsekwd)"
echo "$J" | python3 -c '
import json,sys
d=json.load(sys.stdin)
refs=d["refs"]
fr=[r for r in refs if r["role"]=="func-ref" and r["owner"]=="findkw"]
call=d["callers"].get("findkw",[])
files=[c["file"] for c in call]
sys.exit(0 if (fr and any(c["owner"].startswith("findkw()@readcmd") for c in call)) else 1)' \
    && ok "direct-func-ref-and-caller" || bad "direct-func-ref-and-caller"

# ---- T2 死代码：有引用、无调用者（G3 自动排除的素材）----
echo "$J" | python3 -c '
import json,sys
d=json.load(sys.stdin)
has_ref=any(r["owner"]=="dead_lookup" and r["role"]=="func-ref" for r in d["refs"])
no_call="dead_lookup" not in d["callers"]
sys.exit(0 if (has_ref and no_call) else 1)' \
    && ok "dead-code-no-caller" || bad "dead-code-no-caller"

# ---- T3 宏：宏体内引用 + 展开点发现 ----
J2="$(json "$FIX/src" kwtab)"
echo "$J2" | python3 -c '
import json,sys
d=json.load(sys.stdin)
mac=any(r["role"]=="macro" and r["owner"]=="CHECK_KW" for r in d["refs"])
call=d["callers"].get("CHECK_KW",[])
exp=any(c["file"]=="fake_macro.c" and c["owner"].startswith("CHECK_KW()@parse_one") for c in call)
sys.exit(0 if (mac and exp) else 1)' \
    && ok "macro-ref-and-expansion-site" || bad "macro-ref-and-expansion-site"

# ---- T4 hash 链：容器扩展 → 查询函数 ----
J3="$(json "$FIX/src" tokentab)"
echo "$J3" | python3 -c '
import json,sys
d=json.load(sys.stdin)
chain_ok = d["containers"] == ["kwtab"]
q=[r for r in d["refs"] if "kwtab" in r["role"] and r["owner"]=="yylex"]
feed=[r for r in d["refs"] if "kwtab" in r["role"] and r["owner"]=="initkw"]
sys.exit(0 if (chain_ok and q and feed) else 1)' \
    && ok "hash-chain-container-expansion" || bad "hash-chain-container-expansion"

# ---- T5 可复现 ----
a="$(json "$FIX/src" parsekwd)"; b="$(json "$FIX/src" parsekwd)"
[ "$a" = "$b" ] && ok "reproducible" || bad "reproducible"

# ---- 真实源码树（可选）----
if [ -d "$DASH_SRC_DIR" ]; then
    J="$(json "$DASH_SRC_DIR" parsekwd)"
    echo "$J" | python3 -c '
import json,sys
d=json.load(sys.stdin)
call=d["callers"].get("findkwd",[])
loc={(c["file"],c["line"]) for c in call}
sys.exit(0 if ("parser.c",725) in loc and ("exec.c",788) in loc else 1)' \
        && ok "dash: findkwd 调用点 parser.c:725 + exec.c:788" \
        || bad "dash: findkwd 调用点"
else
    skip "dash (未设 DASH_SRC_DIR)"
fi

if [ -d "$MKSH_SRC_DIR" ]; then
    J="$(json "$MKSH_SRC_DIR" tokentab)"
    echo "$J" | python3 -c '
import json,sys
d=json.load(sys.stdin)
chain="keywords" in d["containers"]
q=[r for r in d["refs"] if "keywords" in r["role"] and r["owner"]=="yylex" and r["file"]=="lex.c" and r["line"]==1046]
sys.exit(0 if (chain and q) else 1)' \
        && ok "mksh: 容器链 keywords → yylex(lex.c:1046)" \
        || bad "mksh: 容器链"
else
    skip "mksh (未设 MKSH_SRC_DIR)"
fi

if [ -d "$BASH_SRC_DIR" ]; then
    J="$(json "$BASH_SRC_DIR" word_token_alist)"
    echo "$J" | python3 -c '
import json,sys
d=json.load(sys.stdin)
mac=any(r["role"]=="macro" and r["owner"]=="CHECK_FOR_RESERVED_WORD" for r in d["refs"])
exp=any(c["owner"].startswith("CHECK_FOR_RESERVED_WORD()@read_token_word")
        for c in d["callers"].get("CHECK_FOR_RESERVED_WORD",[]))
# find_reserved_word 是解析主路径的旁路（仅 print_cmd.c:1398 一处调用）：
# G2 把两条路径都摆出来，主路径裁决交给规则 3（探针）
side=[c for c in d["callers"].get("find_reserved_word",[])
      if c["file"]=="print_cmd.c" and c["line"]==1398]
sys.exit(0 if (mac and exp and side) else 1)' \
        && ok "bash: 宏主路径 read_token_word + 旁路 find_reserved_word(print_cmd.c:1398)" \
        || bad "bash: 宏/旁路"
else
    skip "bash (未设 BASH_SRC_DIR)"
fi

echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
