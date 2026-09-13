#!/usr/bin/env bash
# ============================================================================
# _rn() PRNG 单独验证 —— 不经生成器、不解产物，直接测函数本身
#
# 为什么需要这个测试：
#   _rn() 是 V6 密钥链的头号风险点（见 docs/PITFALLS.md §8.1）。
#   它一旦算错，产物表现为「跑完第一个块就 exit 1，零报错」——
#   症状与 MAC 篡改、环境指纹不符、ISA 表破损**完全无法区分**，
#   实测曾为此烧掉数小时。而这个测试能在 1 秒内定位到函数级。
#
# 三个必须成立的断言：
#   1. 序列必须与 bash 5.1+ 的 $RANDOM 逐位一致（编译期模拟器复刻的是它）
#   2. 连续取值必须**递增推进**（防 $( ) 子 shell 陷阱：状态回不来）
#   3. 不得出现连续重复值（(rv==last) 重摇逻辑）
#
# 退出码：0 全过；非 0 = 失败项数
# ============================================================================
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)" || exit 1

PASS=0; FAIL=0

# --- 从生成器里抽出 _rn() 定义（保证测的是真源码，不是副本）-------------
OB="${OB:-}"
if [ -z "$OB" ]; then
    for _c in "$SELF_DIR/../v6/shell_script_obfuscator_v6.sh" \
              "$SELF_DIR/shell_script_obfuscator_v6.sh"; do
        [ -f "$_c" ] && OB="$_c" && break
    done
fi
if [ -z "$OB" ] || [ ! -f "$OB" ]; then
    echo "错误：找不到 V6 混淆器（可用 OB 环境变量指定）" >&2
    exit 1
fi

# 抽取第一个 `_rn() {` 到其配对 `}` 的整段
RN_DEF=$(awk '
    /^_rn\(\) \{/ { inb = 1; depth = 0 }
    inb {
        print
        n = gsub(/\{/, "{"); m = gsub(/\}/, "}")
        depth += n - m
        if (depth == 0 && NR > 0 && /\}/) { exit }
    }
' "$OB" 2>/dev/null)

if [ -z "$RN_DEF" ]; then
    echo "FAIL 未能在生成器中抽到 _rn() 定义（函数被删了？）" >&2
    exit 1
fi

# --- 断言 1：与 bash 原生 $RANDOM 逐位一致 ---------------------------------
# 取 3 组不同种子，避免单点巧合
for seed in 42 1 123456789; do
    sim=$(bash -c "$RN_DEF
_rs=$seed; _rr=\$(( _rs & 0xFFFFFFFF )); _rl=0
_rn; a=\$_ro; _rn; b=\$_ro; _rn; c=\$_ro
printf '%s %s %s' \"\$a\" \"\$b\" \"\$c\"" 2>/dev/null)
    ref=$(bash -c "RANDOM=$seed; printf '%s %s %s' \"\$RANDOM\" \"\$RANDOM\" \"\$RANDOM\"" 2>/dev/null)
    if [ "$sim" = "$ref" ]; then
        echo "PASS rng-seq seed=$seed  ($sim)"
        PASS=$((PASS + 1))
    else
        echo "FAIL rng-seq seed=$seed"
        echo "       期望(bash \$RANDOM): $ref"
        echo "       实际(_rn)         : $sim"
        echo "       若「实际」三个值全相同 → \$( ) 子 shell 陷阱（见 PITFALLS §8.1.1）"
        FAIL=$((FAIL + 1))
    fi
done

# --- 断言 2：状态必须推进（独立于 bash 的防回归）---------------------------
prog=$(bash -c "$RN_DEF
_rs=7; _rr=\$(( _rs & 0xFFFFFFFF )); _rl=0
out=''
i=0; while [ \$i -lt 12 ]; do _rn; out=\"\$out \$_ro\"; i=\$((i+1)); done
printf '%s' \"\$out\"" 2>/dev/null)
uniq_n=$(printf '%s\n' $prog | sort -u | wc -l)
if [ "$uniq_n" -ge 10 ]; then
    echo "PASS rng-advance (12 次取值中 $uniq_n 个不同)"
    PASS=$((PASS + 1))
else
    echo "FAIL rng-advance —— 12 次取值只有 $uniq_n 个不同值，PRNG 状态没推进"
    echo "       序列：$prog"
    echo "       典型原因：调用点写成 _ra=\$(_rn) 而非 _rn; _ra=\$_ro"
    FAIL=$((FAIL + 1))
fi

# --- 断言 3：无连续重复 ----------------------------------------------------
dup=$(printf '%s\n' $prog | awk 'p==$0 && NR>1 {print NR": "$0} {p=$0}' | head -3)
if [ -z "$dup" ]; then
    echo "PASS rng-no-dup"
    PASS=$((PASS + 1))
else
    echo "FAIL rng-no-dup —— 出现连续重复值（(rv==last) 重摇失效）"
    echo "$dup"
    FAIL=$((FAIL + 1))
fi

# --- 断言 4：定义位置必须在 _am() 之后（builtin 模式 awk 会删掉前面的段）--
RN_LINE=$(grep -n '^_rn() {' "$OB" | head -1 | cut -d: -f1)
AM_LINE=$(grep -n '^_am() {' "$OB" | head -1 | cut -d: -f1)
if [ -n "$RN_LINE" ] && [ -n "$AM_LINE" ] && [ "$RN_LINE" -gt "$AM_LINE" ]; then
    echo "PASS def-order (_am@$AM_LINE < _rn@$RN_LINE)"
    PASS=$((PASS + 1))
else
    echo "FAIL def-order —— _rn 定义必须在 _am 定义之后（_am@${AM_LINE:-?} _rn@${RN_LINE:-?}）"
    echo "       builtin 模式下生成器用 awk 替换 ^_f(){ 到 ^_am(){ 的整段，"
    echo "       定义落在此区间内会被整段删除 → 产物里没有 _rn（见 PITFALLS §8.1.1 约束②）"
    FAIL=$((FAIL + 1))
fi

# --- 断言 5：内部临时变量不得占用契约名 _rt --------------------------------
if printf '%s' "$RN_DEF" | grep -q '_rt\b'; then
    echo "FAIL rng-contract-name —— _rn 内部用了 _rt，会冲掉块间契约值"
    echo "       改用 _rq/_ro 等私有名（见 PITFALLS §8.1.1 约束③）"
    FAIL=$((FAIL + 1))
else
    echo "PASS rng-contract-name"
    PASS=$((PASS + 1))
fi

# --- 断言 6：调用点不得用 $(_rn) 捕获 --------------------------------------
# 只扫真正会执行的代码，跳过注释（文档里会引用这个反例写法）
call_bad=$(grep -n '\$(_rn)' "$OB" 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#' | head -3)
if [ -z "$call_bad" ]; then
    echo "PASS call-form (无 \$( ) 捕获)"
    PASS=$((PASS + 1))
else
    echo "FAIL call-form —— 存在 \$( ) 捕获调用，子 shell 会吃掉 PRNG 状态更新"
    echo "$call_bad"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "======================================"
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "ALL GREEN" || echo "HAS FAILURES"
exit "$FAIL"
