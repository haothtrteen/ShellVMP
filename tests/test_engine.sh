#!/usr/bin/env bash
# test_engine.sh —— hook_engine.py 引擎回归（自包含，不依赖任何真实 shell 源码）
# ============================================================================
# 用生成的 fixture 解释器覆盖：插桩/幂等/dry-run/响亮失败/历史回滚/
# 前缀包含陷阱（README 三条铁律的 1、2）/ 编译可过。
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF_DIR/.." && pwd)"
ENGINE="$ROOT/hook_engine.py"
ANCHORS="$ROOT/examples/anchors_example.py"

PASS=0; FAIL=0
ok()  { echo "  PASS $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL+1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== hook_engine 引擎回归 =="

# ---- fixture：假想解释器源码 ----
make_fixture() {  # $1 = 目录  [$2 = 用 SITE_OLD_V1 造"历史形态"树]
    mkdir -p "$1"
    cat > "$1/fixture.c" <<'EOF'
/* fixture: 假想解释器（仅用于引擎测试） */
static const char *kw_table[] = { "if", "while", 0 };
#define CHECK_KW(tok) do { scan_kw(tok); } while (0)
static void scan_kw(const char *t) { (void)t; }
int lookup_word(const char *w) { return kw_table[0] ? 0 : -1; }
int feed(const char *tok) { CHECK_KW(tok); return lookup_word(tok); }
int main(void) { return feed("if"); }
EOF
    if [ "${2:-}" = "v1" ]; then
        # 伪造 r1 历史形态：feed 是旧版（+1）
        sed -i 's/return lookup_word(tok); }/return lookup_word(tok) + 1; }/' "$1/fixture.c"
    fi
}

# ---- T1 正常插桩 ----
make_fixture "$WORK/t1"
if python3 "$ENGINE" "$ANCHORS" --srcdir "$WORK/t1" > "$WORK/t1.log" 2>&1; then
    if grep -q 'hook_kw' "$WORK/t1/fixture.c" \
       && grep -q 'int hook_kw(const char \*t);' "$WORK/t1/fixture.c"; then
        ok "apply-inserts-hook"
    else
        bad "apply-inserts-hook（日志：$(tail -2 "$WORK/t1.log" | tr '\n' ' ')）"
    fi
else
    bad "apply-inserts-hook（引擎退出非零）"
fi

# ---- T2 插桩后可编译、可运行 ----
if command -v gcc >/dev/null 2>&1; then
    if gcc -o "$WORK/t1/fixture.bin" "$WORK/t1/fixture.c" 2>"$WORK/cc.log" \
       && "$WORK/t1/fixture.bin"; then
        ok "compiles-and-runs"
    else
        bad "compiles-and-runs"
        sed 's/^/       /' "$WORK/cc.log" | head -5
    fi
else
    echo "  SKIP compiles-and-runs (无 gcc)"
fi

# ---- T3 幂等 ----
before="$(md5sum "$WORK/t1/fixture.c" | cut -d' ' -f1)"
python3 "$ENGINE" "$ANCHORS" --srcdir "$WORK/t1" >/dev/null 2>&1
after="$(md5sum "$WORK/t1/fixture.c" | cut -d' ' -f1)"
[ "$before" = "$after" ] && ok "idempotent" || bad "idempotent"

# ---- T4 dry-run 不写盘 ----
make_fixture "$WORK/t4"
b="$(md5sum "$WORK/t4/fixture.c" | cut -d' ' -f1)"
python3 "$ENGINE" "$ANCHORS" --srcdir "$WORK/t4" --dry-run >/dev/null 2>&1
a="$(md5sum "$WORK/t4/fixture.c" | cut -d' ' -f1)"
[ "$b" = "$a" ] && ok "dry-run-writes-nothing" || bad "dry-run-writes-nothing"

# ---- T5 历史形态回滚（v1 树 → 引擎自动升级）----
make_fixture "$WORK/t5" v1
grep -q 'lookup_word(tok) + 1' "$WORK/t5/fixture.c" \
    && ok "v1-fixture-prepared" || bad "v1-fixture-prepared"
if python3 "$ENGINE" "$ANCHORS" --srcdir "$WORK/t5" > "$WORK/t5.log" 2>&1; then
    grep -q 'hook_kw(tok) && lookup_word(tok)' "$WORK/t5/fixture.c" \
        && ! grep -q 'lookup_word(tok) + 1' "$WORK/t5/fixture.c" \
        && ok "rollback-upgrades-v1" || bad "rollback-upgrades-v1"
else
    bad "rollback-upgrades-v1（引擎退出非零）"
fi

# ---- T6 前缀包含陷阱：已升级的树绝不能被降级（铁律 2）----
# t1 已是新形态（anchor + DECL_NEW）。DECL_OLD 是 DECL_NEW 的前缀，
# 错误实现会把 anchor+DECL_OLD 命中在 anchor+DECL_NEW 上并降级。
before="$(md5sum "$WORK/t1/fixture.c" | cut -d' ' -f1)"
python3 "$ENGINE" "$ANCHORS" --srcdir "$WORK/t1" >/dev/null 2>&1
after="$(md5sum "$WORK/t1/fixture.c" | cut -d' ' -f1)"
if [ "$before" = "$after" ] \
   && grep -q 'int hook_kw(const char \*t);' "$WORK/t1/fixture.c"; then
    ok "prefix-trap-no-downgrade"
else
    bad "prefix-trap-no-downgrade"
fi

# ---- T7 锚点不匹配必须响亮失败 ----
make_fixture "$WORK/t7"
sed -i 's/CHECK_KW(tok) do { scan_kw(tok); } while (0)/CHECK_KW(t) do { scan_kw(t); } while (0)/' \
    "$WORK/t7/fixture.c"
if python3 "$ENGINE" "$ANCHORS" --srcdir "$WORK/t7" >/dev/null 2>&1; then
    bad "fails-loud-on-anchor-mismatch"
else
    ok "fails-loud-on-anchor-mismatch"
fi

# ---- T8 未知解释器拒绝 / --list ----
if python3 "$ENGINE" "$ANCHORS" --interp nonexistent --srcdir "$WORK/t1" >/dev/null 2>&1; then
    bad "rejects-unknown-interp"
else
    ok "rejects-unknown-interp"
fi
python3 "$ENGINE" "$ANCHORS" --list 2>/dev/null | grep -q 'fixture-shell' \
    && ok "list-works" || bad "list-works"

# ---- T9 库方式调用走同一引擎（铁律 1：无第二份循环）----
if python3 - "$ENGINE" "$WORK/t1" <<'PYEOF'
import sys, importlib.util, os
spec = importlib.util.spec_from_file_location("he", sys.argv[1])
he = importlib.util.module_from_spec(spec); spec.loader.exec_module(he)
sets = he.load_anchors(os.path.join(os.path.dirname(sys.argv[1]),
                                    "examples", "anchors_example.py"))
d = sys.argv[2]
src = open(os.path.join(d, "fixture.c")).read()
cache = {"kw": src}
changed, cache = he.run_ops(sets["fixture-shell"], cache)
sys.exit(0 if "hook_kw" in cache["kw"] and not changed else 1)
PYEOF
then
    ok "library-path-uses-same-engine"
else
    bad "library-path-uses-same-engine"
fi

echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
