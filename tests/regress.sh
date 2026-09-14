#!/usr/bin/env bash
# V6 终版三件套加固 —— 端到端回归驱动
# 覆盖：aes/builtin × junk/decoy 矩阵（输出逐字节比对）、数据块/指令批/
#       骨架三类篡改拒绝（MAC/完整性/一层壳三道门各司其职）、passkey+AI_GUARD
# 解析脚本自身目录为绝对路径（必须在 cd 之前完成，否则相对 $0 会基于新 cwd 二次求值）
SELF_DIR="$(cd "$(dirname "$0")" && pwd)" || exit 1
cd "$SELF_DIR" || exit 1
# 定位 V6 混淆器：OB 环境变量 → 包内 ../v6/（zip 布局）→ 同目录 → 开发沙箱
OB="${OB:-}"
if [ -z "$OB" ]; then
    for _c in "$SELF_DIR/../v6/shell_script_obfuscator_v6.sh" \
              "$SELF_DIR/shell_script_obfuscator_v6.sh" \
              /workspace/tshell_r10/v6/shell_script_obfuscator_v6.sh \
              /workspace/shell_script_obfuscator_v6.sh; do
        [ -f "$_c" ] && OB="$_c" && break
    done
fi
[ -n "$OB" ] && [ -f "$OB" ] || {
    echo "错误：找不到 V6 混淆器（查找：OB 环境变量、../v6/、脚本目录）" >&2
    exit 1
}
PASS=0; FAIL=0

# 自清理：退出时删除本套件产生的中间产物（编译日志/产物脚本/运行输出/基线），
# 保证反复运行后测试目录保持干净。设 REGRESS_KEEP=1 可保留以便排障。
_cleanup() {
    [ "${REGRESS_KEEP:-0}" = "1" ] && return 0
    rm -f compile_*.log prod_*.sh run_*.out run_*.err tam_*.out tam__.sh \
          test_big_ref.out test_small_ref.out test_isa_hook_table.log 2>/dev/null
}
trap _cleanup EXIT

bash test_big.sh > test_big_ref.out 2>/dev/null
bash test_small.sh > test_small_ref.out 2>/dev/null

run_case() {  # $1=name $2=mode $3=junk $4=decoy $5=src
    local name="$1" mode="$2" junk="$3" decoy="$4" src="$5"
    local out="prod_${name}.sh"
    if ! ANDROID_GATE=0 CRYPTO_MODE="$mode" JUNK_LEVEL="$junk" DECOY_LEVEL="$decoy" \
         bash "$OB" "$src" "$out" > "compile_${name}.log" 2>&1; then
        echo "FAIL $name [compile]"; tail -5 "compile_${name}.log"; FAIL=$((FAIL+1)); return 1
    fi
    bash "$out" > "run_${name}.out" 2> "run_${name}.err"
    local rc=$?
    if [ "$rc" -eq 0 ] && diff -q "${src%.sh}_ref.out" "run_${name}.out" >/dev/null; then
        echo "PASS $name ($(wc -c < "$out") bytes)"; PASS=$((PASS+1)); return 0
    fi
    echo "FAIL $name [run rc=$rc]"
    diff "${src%.sh}_ref.out" "run_${name}.out" | head -10
    head -5 "run_${name}.err"
    FAIL=$((FAIL+1)); return 1
}

# 翻转第 idx 个数组项密文值的第 pos 个字符（首个匹配 = 指令表在前、数据表在后）
tamper_idx() {  # $1=file $2=idx $3=pos
    awk -v pat="[$2]=\"" -v pos="$3" '
        {
            if (!done) {
                i = index($0, pat)
                if (i > 0) {
                    vs = i + length(pat)
                    vl = index(substr($0, vs), "\"") - 1
                    if (vl > pos) {
                        v = substr($0, vs, vl)
                        c = substr(v, pos, 1)
                        r = (c == "A") ? "B" : "A"
                        v = substr(v, 1, pos-1) r substr(v, pos+1)
                        $0 = substr($0, 1, vs-1) v substr($0, vs+vl)
                        done = 1
                    }
                }
            }
            print
        }
        END { exit done ? 0 : 1 }
    ' "$1" > "$1.tp" && mv "$1.tp" "$1"
}

tamper_test() {  # $1=name $2=product $3=kind
    local name="$1" prod="$2" kind="$3" cp="tam_${name}_${kind}.sh"
    cp "$prod" "$cp"
    case "$kind" in
        data) tamper_idx "$cp" 40 20 ;;
        inst) tamper_idx "$cp" 0 20 ;;
        skel) printf '# skeleton byte\n' >> "$cp" ;;
    esac
    bash "$cp" > "tam_${name}_${kind}.out" 2>/dev/null
    local rc=$?
    local full
    full=$(wc -c < "tam_${name}_${kind}.out")
    if [ "$rc" -ne 0 ]; then
        # 数据块篡改：前置块已执行 → 输出应为参考输出的严格前缀（证明是
        # 确定性 MAC 拒绝点退出，而非乱码 eval）
        if [ "$kind" = data ] && [ "$full" -gt 0 ]; then
            head -c "$full" test_big_ref.out > "tam_${name}_pre.out"
            if cmp -s "tam_${name}_${kind}.out" "tam_${name}_pre.out"; then
                echo "PASS tamper-$name-$kind (rc=$rc, prefix ${full}B)"; PASS=$((PASS+1)); return
            fi
            echo "FAIL tamper-$name-$kind (rc=$rc 但输出非参考前缀 —— 乱码被执行!)"; FAIL=$((FAIL+1)); return
        fi
        echo "PASS tamper-$name-$kind (rc=$rc, out=${full}B)"; PASS=$((PASS+1))
    else
        echo "FAIL tamper-$name-$kind (rc=0 —— 篡改未被拒绝!)"; FAIL=$((FAIL+1))
    fi
}

echo "=== 功能矩阵：输出逐字节比对 ==="
run_case aes_j0d0_big    aes     0 0 test_big.sh
run_case aes_j0d1_big    aes     0 1 test_big.sh
run_case aes_j1d0_big    aes     1 0 test_big.sh
run_case aes_j1d1_big    aes     1 1 test_big.sh
run_case aes_small       aes     0 0 test_small.sh
run_case builtin_j0d0_big builtin 0 0 test_big.sh
run_case builtin_j0d1_big builtin 0 1 test_big.sh
run_case builtin_j1d0_big builtin 1 0 test_big.sh
run_case builtin_j1d1_big builtin 1 1 test_big.sh
run_case builtin_small   builtin 0 0 test_small.sh

echo "=== 篡改拒绝（MAC / 完整性 / 一层壳）==="
tamper_test aes_j1d1     prod_aes_j1d1_big.sh     data
tamper_test aes_j1d1     prod_aes_j1d1_big.sh     inst
tamper_test aes_j1d1     prod_aes_j1d1_big.sh     skel
tamper_test builtin_j1d1 prod_builtin_j1d1_big.sh data
tamper_test builtin_j1d1 prod_builtin_j1d1_big.sh inst
tamper_test builtin_j1d1 prod_builtin_j1d1_big.sh skel

echo "=== 密钥分离 + AI_GUARD 组合 ==="
for mode in aes builtin; do
    if ANDROID_GATE=0 CRYPTO_MODE="$mode" PASSKEY_MODE=1 PASSKEY_CUSTOM='testkey123' AI_GUARD=1 \
       bash "$OB" test_small.sh "prod_pk_${mode}.sh" > "compile_pk_${mode}.log" 2>&1; then
        printf 'testkey123\n' | bash "prod_pk_${mode}.sh" > "run_pk_${mode}.out" 2>/dev/null
        if diff -q test_small_ref.out "run_pk_${mode}.out" >/dev/null; then
            echo "PASS pk-$mode (正确密钥)"; PASS=$((PASS+1))
        else
            echo "FAIL pk-$mode (正确密钥下输出不符)"; FAIL=$((FAIL+1))
        fi
        printf 'wrongkey\nwrongkey\nwrongkey\n' | bash "prod_pk_${mode}.sh" > "run_pk_${mode}_bad.out" 2>/dev/null
        if [ $? -ne 0 ] && [ ! -s "run_pk_${mode}_bad.out" ]; then
            echo "PASS pk-$mode (错误密钥拒绝)"; PASS=$((PASS+1))
        else
            echo "FAIL pk-$mode (错误密钥未拒绝)"; FAIL=$((FAIL+1))
        fi
    else
        echo "FAIL pk-$mode [compile]"; tail -3 "compile_pk_${mode}.log"; FAIL=$((FAIL+1))
    fi
done

echo ""
echo "=== C 层插桩器锚点表（B0/B1）==="
# 这个子测试有自己的 PASS/FAIL 汇总；此处只当作一个门（gate）计入总数，
# 避免把它的十几条断言全灌进本套件的计数里。
if bash "$SELF_DIR/test_isa_hook_table.sh" > test_isa_hook_table.log 2>&1; then
    echo "PASS isa_hook-table（锚点表：逐字节/幂等/响亮失败）"; PASS=$((PASS+1))
else
    echo "FAIL isa_hook-table"; tail -5 test_isa_hook_table.log; FAIL=$((FAIL+1))
fi

echo ""
echo "======================================"
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "ALL GREEN" || echo "HAS FAILURES"
exit $FAIL
