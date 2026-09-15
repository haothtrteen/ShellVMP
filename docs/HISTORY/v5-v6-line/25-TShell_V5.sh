#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md

# shell_script_obfuscator_v5.sh - AES-256-CTR 全链加密版
#
# 相对上一版的改进（对抗已实锤的两类静态攻击：循环 XOR + base64 已知明文
# 逐位反推、密钥原料枚举穷举）：
#   1. 指令/数据块全部改用 openssl AES-256-CTR（raw K/iv，逐项独立密钥流）
#      → 已知明文只能推出密钥流片段，对 256bit 密钥零信息
#   2. 一层壳（解释器）改为 gzip + PBKDF2-AES-256-CTR（sha512，高迭代）
#   3. 骨架自哈希 H_skel 掺入一层口令 P1 —— 改骨架任何一字节都必须完整
#      重放 PBKDF2 才能重加密，插桩成本叠加一个量级
#   4. 工具（openssl/gzip/sha512sum/sha256sum/uname）编译期绑定绝对路径，
#      运行期不再走 PATH → 免疫 PATH 劫持型的密钥/明文窃听
#   5. 指令批量化（INST_BATCH 条/批）：运行期 openssl 进程数降到 1/16
#   6. 环境熵（KEY_ENTROPY）掺入一层口令：枚举空间从 ~1664 拉到数万级，
#      且每次验证都要付一次 PBKDF2 全迭代
#   7. 反调试/反插桩检测内嵌加密数据块；平台指纹/设备熵/解释器哈希 IH
#      全部掺入密钥链 —— 环境不符时一步都解不开，且静默乱码无提示

# 真执行垃圾块等级：0 关闭，N≥1 时在每个真实块后注入 N 个垃圾块。
# 垃圾块与真实块结构完全相同（det/beacon/rt/s/ck 链），会真正 eval 执行，
# 但对原始代码零影响；它们参与密钥链 → AI 重放 VM 时一个都跳不过去，
# 只能逐块解密求值，上下文/压缩次数成倍增长
JUNK_LEVEL=${JUNK_LEVEL:-0}
# 诱饵数据块等级：0 关闭，N≥1 时注入 N×真实块数的诱饵（恒假谓词，零执行）
DECOY_LEVEL=${DECOY_LEVEL:-0}
# 一层 PBKDF2 迭代次数（越大启动越慢、攻击者枚举越贵；默认 600000）
L1_ITER=${L1_ITER:-600000}
# 密钥掺入的环境熵等级：0 无 / 1 cpu.abi / 2 abi+Android 大版本
# 注意 2 意味着产物绑定同一 Android 大版本；分发给版本混杂设备请用 0/1
KEY_ENTROPY=${KEY_ENTROPY:-2}
# 每批打包的指令条数（运行期一次 openssl 调用解密整批）
INST_BATCH=16
# 目标 bash 主版本（默认取编译机 BASH_VERSINFO[0]）
TARGET_BASH_MAJOR=${TARGET_BASH_MAJOR:-}
# 安卓门控：默认开启，ANDROID_GATE=0 关闭（用于在非安卓环境测试）
ANDROID_GATE=${ANDROID_GATE:-1}
# 设备绑定：HOST_BIND=1 时密钥掺本机 serialno/android_id（产物仅本机可跑）
HOST_BIND=${HOST_BIND:-0}
# 密钥分离模式：PASSKEY_MODE=1 时一层口令掺入用户密钥（信封加密）。
# 随机主密钥 M 绝不写入产物；每个 passkey 独立包裹 M，运行期 read -s
# 向用户要密钥，解开任意包裹得到 M 才能推得一层口令 —— 密钥材料不在
# 文件里，纯静态分析在信息论上无法还原（见 prepare_passkeys 注记）
PASSKEY_MODE=${PASSKEY_MODE:-0}
# 生成的密钥个数（1-16，默认 1）；多个密钥均可解密
PASSKEY_COUNT=${PASSKEY_COUNT:-1}
# 自定义密钥（| 分隔，如 'k1|k2|k3'；设置后忽略 PASSKEY_COUNT，密钥不得含 |）
PASSKEY_CUSTOM=${PASSKEY_CUSTOM:-}
# 解包裹 PBKDF2 迭代次数（防离线爆破）。随机强密钥下 10000 足够且启动快；
# 自定义弱口令请调高（如 300000）。每次错误尝试的代价 ≈ 密钥数 × 此值
UNWRAP_ITER=${UNWRAP_ITER:-10000}
# 可选：密钥另存到文件（权限 600）；不设则仅在编译输出中打印
PASSKEY_FILE=${PASSKEY_FILE:-}
# 加密架构：aes（默认，openssl AES-256-CTR + PBKDF2）| builtin（纯 shell/awk
# 4 原语多态，零 openssl 依赖，兼容极简环境；密码学强度弱于 aes，见各注记）
CRYPTO_MODE=${CRYPTO_MODE:-aes}
# builtin 模式一层壳链式 sha512 轮数（每轮一次 sha512sum 子进程 ≈2-4ms，
# 300 ≈ 1s 启动。注：非密钥分离时一层壳的秘密本就全部在文件内，该层作用
# 是 H_skel 防篡改绑定，轮数只为拉高攻击者改壳后重封装的成本）
BUILTIN_L1_ITER=${BUILTIN_L1_ITER:-300}
# builtin 模式 passkey 解包裹链式 sha512 轮数。警告：攻击者用原生语言重实现
# 该 KDF 每轮仅 ~1µs，防弱口令爆破强度远低于 PBKDF2 —— builtin 模式务必用
# 随机长密钥（默认生成即随机），自定义弱口令请调高此值并知晓局限
BUILTIN_KDF_ITER=${BUILTIN_KDF_ITER:-600}
WORK_DIR=$(mktemp -d)

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT INT TERM

#==============================================================================
# 工具函数
#==============================================================================

gen_rand() {
    local len="${1:-16}" charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local result="" i
    for ((i = 0; i < len; i++)); do
        result+="${charset:RANDOM % ${#charset}:1}"
    done
    printf '%s' "$result"
}

split_into_blocks() {
    local content="$1"
    local current="" line err rc
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -n "$current" ]; then
            current+=$'\n'"$line"
        else
            current="$line"
        fi
        [[ "$line" =~ \\$ ]] && continue
        err=$(bash -n <<< "$current" 2>&1)
        rc=$?
        [ $rc -ne 0 ] && continue
        [[ "$err" == *"here-document"* ]] && continue
        printf '%s\0' "$current"
        current=""
    done <<< "$content"
    [ -n "$current" ] && printf '%s\0' "$current"
}

#==============================================================================
# 块压缩器：将可安全合并的多行块压缩为单行（用 ; 分隔）
# 策略：
#   1. 跳过含 heredoc 的块（<< 标记）
#   2. 跳过含续行符 \ 的块
#   3. 将换行替换为 ; ，用 bash -n 验证语法正确性
#   4. 验证不通过则保留原块
#==============================================================================

compact_block() {
    local block="$1"
    local compacted err rc

    # 含 heredoc 或续行符的块不压缩
    [[ "$block" == *"<<"* ]] && { printf '%s' "$block"; return; }
    [[ "$block" == *'\\'* ]] && { printf '%s' "$block"; return; }

    # 换行替换为 ; （先去掉行首空白）
    compacted=$(printf '%s' "$block" | sed ':a;N;$!ba;s/\n[[:space:]]*/; /g')

    # 语法验证
    err=$(bash -n <<< "$compacted" 2>&1)
    rc=$?
    [ $rc -ne 0 ] && { printf '%s' "$block"; return; }
    [[ "$err" == *"here-document"* ]] && { printf '%s' "$block"; return; }

    printf '%s' "$compacted"
}

#==============================================================================
# 执行模拟器：在子shell中按顺序执行用户代码块，捕获每块的执行结果
#
# 原理：
#   1. 把所有用户代码块按顺序写入临时脚本
#   2. 每块执行后，输出一个唯一标记 + $_ 的值（上一条命令的最后参数）
#   3. $_ 的值取决于用户代码实际执行了什么，无法静态推导
#
# 例如：
#   echo "Hello"  → $_ = "Hello"
#   name="test"   → $_ = "test"
#   for i in 1 2 3; do echo $i; done → $_ = "3"
#
# 攻击者必须真正模拟 bash 执行环境，包括变量赋值、命令输出等
#==============================================================================

simulate_execution() {
    local sim_script="$WORK_DIR/sim.sh"
    local marker="__RT_MARK_$(gen_rand 8)__"
    local i

    # 构建模拟脚本：按顺序执行所有块，每块后捕获 $_
    # 关键：每块前的信标必须与运行时 wrapped 块里的 beacon 完全一致。
    # 对于"不修改 $_ 的块"（如纯函数定义），rt 捕获的就是信标值本身，
    # 信标不一致 → 编译期嵌入的 _s 初值与运行时分叉 → 密钥链断（已踩坑）
    {
        echo '#!/usr/bin/env bash'
        for ((i = 0; i < ${#REAL_BLOCKS[@]}; i++)); do
            printf 'true "%s"\n' "${VM_BEACONS[$i]:-__rr__}"
            printf '%s\n' "${REAL_BLOCKS[$i]}"
            printf 'printf "%s%%s%s\\n" "$_"\n' "$marker" "$marker"
        done
    } > "$sim_script"

    # 执行并捕获结果
    local sim_output
    sim_output=$(bash "$sim_script" 2>/dev/null) || true

    # 提取每块的 $_ 值
    RT_VALUES=()
    local line rt_val
    while IFS= read -r line; do
        if [[ "$line" == ${marker}*${marker} ]]; then
            rt_val="${line#${marker}}"
            rt_val="${rt_val%${marker}}"
            RT_VALUES+=("$rt_val")
        fi
    done <<< "$sim_output"

    # 如果某些块没有产生标记（比如 exit 提前），用空字符串填充
    while [ "${#RT_VALUES[@]}" -lt "${#REAL_BLOCKS[@]}" ]; do
        RT_VALUES+=("")
    done

    echo "信息：执行模拟完成，捕获 ${#RT_VALUES[@]} 个执行结果" >&2
}

#==============================================================================
# _s 执行状态计算器：随机生成唯一表达式 + 依赖前一个块的执行结果 (_rt)
#
# 核心思路：
#   1. 随机拼装多项式表达式（变量数、运算、常量、顺序都随机）
#   2. 表达式中混入 _rt（前一个块执行后的 $_ 值）
#   3. AI 必须真正模拟 bash 执行才能知道 _rt，进而才能推导 _s
#==============================================================================

gen_s_computation() {
    # 多态化：rt_name/s_in/s_out 由调用方逐块生成随机名，内部临时变量也随机命名
    # 契约名 _S2/_di 已整体随机化（N_S2/N_DI，compile_v5 生成）：用户脚本
    # 再怎么给 _S2/_di 赋值也砸不到 VM 内部（names 回归测试的根因修复）
    local current_s="$1" di="$2" rt="$3" rt_name="$4" s_in="$5" s_out="$6"
    local nvars=$((RANDOM % 2 + 2))
    local var_decls=""
    local all_items=()
    local i vname

    all_items+=("$s_in|%s|$current_s")
    all_items+=("${N_DI}|%d|$di")
    all_items+=("$rt_name|%s|$rt")

    for ((i = 0; i < nvars; i++)); do
        vname="$(gen_rand_var)"
        local vsrc=$((RANDOM % 2))
        case $vsrc in
            0)
                local vval=$((RANDOM % 200 + 1))
                var_decls+="$vname=$vval; "
                all_items+=("$vname|%d|$vval")
                ;;
            1)
                local factor=$((RANDOM % 9 + 2))
                local offset=$((RANDOM % 50))
                local vval=$((di * factor + offset))
                var_decls+="$vname=\$((\$${N_DI} * $factor + $offset)); "
                all_items+=("$vname|%d|$vval")
                ;;
        esac
    done

    local npick=$((RANDOM % 2 + 3))
    local fmt="" args="" idx
    local nitems=${#all_items[@]}

    for ((i = 0; i < npick; i++)); do
        idx=$((RANDOM % nitems))
        IFS='|' read -r vname vfmt vval <<< "${all_items[$idx]}"
        fmt+="$vfmt"
        args+="\"\$$vname\" "
    done

    local double=$((RANDOM % 3))
    local code
    if [ "$double" -eq 0 ]; then
        code="${var_decls}${s_out}=\$(printf \"$fmt\" $args | \"\$${N_S2}\"); ${s_out}=\${${s_out}:0:8}; ${s_out}=\$(printf \"%s\" \"\${${s_out}}\" | \"\$${N_S2}\"); ${s_out}=\${${s_out}:0:8}"
    else
        code="${var_decls}${s_out}=\$(printf \"$fmt\" $args | \"\$${N_S2}\"); ${s_out}=\${${s_out}:0:8}"
    fi

    # 模拟求值：N_S2 用编译机 sha256sum 绝对路径（运行时由骨架提供同款绑定路径）
    local new_s
    new_s=$(eval "${N_S2}='$SHA256_BIN'; ${s_in}='$current_s'; ${N_DI}=$di; ${rt_name}='$rt'; $code; printf '%s' \"\${${s_out}}\"")

    printf '%s\x01%s' "$code" "$new_s"
}

#==============================================================================
# _ck 密钥派生：同样随机生成唯一表达式
#==============================================================================

gen_ck_derivation_with_s() {
    # 多态化：s_name 由调用方传入（= 该块 s_out 名），内部临时变量随机命名
    # 契约名 _ck/_S2/_di 已整体随机化（N_CK/N_S2/N_DI，compile_v5 生成），
    # 与解释器 sed 重命名后的名字逐字一致
    local current_ck="$1" new_s="$2" di="$3" s_name="$4"
    local nvars=$((RANDOM % 2 + 1))
    local var_decls=""
    local all_items=()
    local i vname

    all_items+=("${N_CK}|%s|$current_ck")
    all_items+=("$s_name|%s|$new_s")
    all_items+=("${N_DI}|%d|$di")

    for ((i = 0; i < nvars; i++)); do
        vname="$(gen_rand_var)"
        local vsrc=$((RANDOM % 2))
        case $vsrc in
            0)
                local vval=$((RANDOM % 10000 + 1))
                var_decls+="$vname=$vval; "
                all_items+=("$vname|%d|$vval")
                ;;
            1)
                local factor=$((RANDOM % 7 + 2))
                local vval=$((di * factor))
                var_decls+="$vname=\$((\$${N_DI} * $factor)); "
                all_items+=("$vname|%d|$vval")
                ;;
        esac
    done

    local npick=$((RANDOM % 2 + 3))
    local fmt="" args="" idx
    local nitems=${#all_items[@]}

    for ((i = 0; i < npick; i++)); do
        idx=$((RANDOM % nitems))
        IFS='|' read -r vname vfmt vval <<< "${all_items[$idx]}"
        fmt+="$vfmt"
        args+="\"\$$vname\" "
    done

    local double=$((RANDOM % 3))
    local code
    if [ "$double" -eq 0 ]; then
        code="${var_decls}${N_CK}=\$(printf \"$fmt\" $args | \"\$${N_S2}\"); ${N_CK}=\${${N_CK}:0:16}; ${N_CK}=\$(printf \"%s\" \"\${${N_CK}}\" | \"\$${N_S2}\"); ${N_CK}=\${${N_CK}:0:16}"
    else
        code="${var_decls}${N_CK}=\$(printf \"$fmt\" $args | \"\$${N_S2}\"); ${N_CK}=\${${N_CK}:0:16}"
    fi

    local new_ck
    new_ck=$(eval "${N_S2}='$SHA256_BIN'; ${N_CK}='$current_ck'; ${s_name}='$new_s'; ${N_DI}=$di; $code; printf '%s' \"\${${N_CK}}\"")

    printf '%s\x01%s' "$code" "$new_ck"
}

#==============================================================================
# 诱饵数据块生成器
#
# 原理：生成与真实数据块结构完全一致的假块，塞进 _d 末尾，但没有任何
#       EXEC 指令引用它们（死代码），运行时一次都不会被解密 → 零开销。
#       AI 却必须逐个解密+追踪才能确认是死块，上下文被迅速耗尽。
#
# DECOY_LEVEL 决定诱饵数量（DECOY_LEVEL × 真实块数），0 关闭。
#==============================================================================

gen_decoy_code() {
    local n=$((RANDOM % 4 + 2))
    local fname="dk_$(gen_rand 4)"
    local vname="dv_$(gen_rand 4)"
    local code
    code="${fname}(){ local j acc; acc=0; for j in \$(seq 1 ${n}); do acc=\$((acc+j)); done; printf '%s' \"\$acc\"; }"
    code+=$'\n'"${vname}=\$(${fname})"
    code+=$'\n'"[ \"\${${vname}}\" -ge 0 ] && echo \"inline:$(gen_rand 4)\""
    printf '%s' "$code"
}

gen_decoy_wrapped() {
    local key="$1" det="$2" di="$3"
    local fake s_r s_code new_s ck_r ck_code
    local beacon rt_name s_in s_out
    fake="$(gen_decoy_code)"
    beacon="__$(gen_rand 6)__"
    rt_name="$(gen_rand_var)"
    s_in="$(gen_rand_var)"
    s_out="$(gen_rand_var)"
    s_r=$(gen_s_computation "dk_$(gen_rand 8)" "$di" "decoy" "$rt_name" "$s_in" "$s_out")
    s_code="${s_r%%$'\x01'*}"
    new_s="${s_r#*$'\x01'}"
    ck_r=$(gen_ck_derivation_with_s "$key" "$new_s" "$di" "$s_out")
    ck_code="${ck_r%%$'\x01'*}"
    printf '%s\n%s\n%s\n%s\n%s\n%s' \
        "$det" "true \"$beacon\"" "$fake" "$rt_name=\$_" "$s_code" "$ck_code"
}

#==============================================================================
# 真执行垃圾块生成器（JUNK_LEVEL 核心）
#
# 与 DECOY_LEVEL 诱饵块的本质区别：
#   诱饵块：CEXEC(恒假谓词)，运行时零执行；AI 只要判定谓词为假即可整块跳过
#   垃圾块：作为普通数据块进入执行流，真实 eval 执行，参与 _s/_ck 密钥链
#           → AI 重放 VM 时跳过任何一块，后续密钥链立即断裂，必须逐块解密
#
# 垃圾体硬约束（保证"真执行但零影响"）：
#   1. 只用 bash 内建（赋值/算术/参数展开/if/case/for 字面量）→ 零 fork、零输出
#   2. 语句永不返回非零（不用裸 [ ]&&、分支带默认）→ 用户脚本 set -e 也不会被误杀
#   3. 变量名 __j + 10 位随机串，且与用户脚本全文比对，杜绝撞名污染用户状态
#   4. 纯确定性（不用 $RANDOM/$$/date/外部命令）→ 编译期模拟与运行时 $_ 一致
#   5. bash -n 逐块验证，失败自动回退平凡赋值
#==============================================================================

# 用户脚本全文（obfuscate_script 里赋值），用于垃圾变量名撞名检查
declare -g USER_SCRIPT_CONTENT=""

gen_junk_var() {
    local name
    while :; do
        name="__j$(gen_rand 10)"
        # 与用户脚本任何子串都不重合才使用（连 __j 前缀习惯都避开）
        if [[ "$USER_SCRIPT_CONTENT" != *"$name"* ]]; then
            printf '%s' "$name"
            return
        fi
    done
}

gen_junk_code() {
    local v1 v2 v3 t n i s1 s2 n1 n2 n3 code
    v1="$(gen_junk_var)"
    v2="$(gen_junk_var)"
    v3="$(gen_junk_var)"
    t=$((RANDOM % 6))
    case $t in
        0)
            # 算术累加链
            code="$v1=$((RANDOM % 89 + 11))"
            n=$((RANDOM % 4 + 2))
            for ((i = 0; i < n; i++)); do
                code+=$'\n'"$v1=\$(($v1 * 3 + $i + $((RANDOM % 17 + 1))))"
            done
            code+=$'\n'"$v2=\$(($v1 % 251))"
            ;;
        1)
            # 字符串切片 + 后缀剥离 + 长度
            s1="$(gen_rand $((RANDOM % 5 + 6)))"
            s2="$(gen_rand $((RANDOM % 5 + 4)))"
            code="$v1=\"$s1$s2\""
            code+=$'\n'"$v2=\"\${$v1:$((RANDOM % 3)):3}\${$v1%%$s2}\""
            code+=$'\n'"$v3=\${#$v2}"
            code+=$'\n'"if [ \"\${#$v2}\" -ge 0 ]; then $v3=\$(($v3 + ${#s1})); fi"
            ;;
        2)
            # 恒真条件嵌套
            n=$((RANDOM % 50 + 10))
            code="$v1=$n"
            code+=$'\n'"if [ \"\${$v1}\" -gt 5 ]; then $v2=\$(($v1 + 3)); else $v2=\$((0 - $v1)); fi"
            code+=$'\n'"if [ \"\${$v2:-0}\" -ne 0 ]; then $v3=\$(($v2 * 2 + 1)); else $v3=7; fi"
            ;;
        3)
            # case 分支算术
            code="$v1=$((RANDOM % 7 + 2))"
            code+=$'\n'"case \$(($v1 % 3)) in"
            code+=$'\n'"    0) $v2=\$(($v1 + 1)) ;;"
            code+=$'\n'"    1) $v2=\$(($v1 * 2)) ;;"
            code+=$'\n'"    *) $v2=$v1 ;;"
            code+=$'\n'"esac"
            code+=$'\n'"$v3=\${#$v2}"
            ;;
        4)
            # 数组遍历求和
            n1=$((RANDOM % 99 + 1)); n2=$((RANDOM % 99 + 1)); n3=$((RANDOM % 99 + 1))
            code="$v1=($n1 $n2 $n3)"
            code+=$'\n'"$v2=0"
            code+=$'\n'"for $v3 in \"\${$v1[@]}\"; do $v2=\$(($v2 + $v3)); done"
            ;;
        5)
            # 字符统计循环
            s1="$(gen_rand 8)"
            code="$v1=\"$s1\""
            code+=$'\n'"$v2=0"
            code+=$'\n'"for $v3 in a b c d e f; do"
            code+=$'\n'"    case \"\${$v1}\" in *\"\${$v3}\"*) $v2=\$(($v2 + 1)) ;; esac"
            code+=$'\n'"done"
            ;;
    esac

    # 语法验证：任何模板异常都回退到最保守的平凡赋值
    if ! bash -n <<< "$code" 2>/dev/null; then
        code="$v1=$((RANDOM % 1000 + 1))"$'\n'"$v2=\$(($v1 * 3 + 7))"
    fi
    printf '%s' "$code"
}

#==============================================================================
# 不透明谓词生成器
#
# 原理：生成"看似需要推理、实则恒为某值"的布尔表达式，编码为类型编号。
#       解释器 CEXEC 指令按类型求值。AI 无法静态判定真值，必须代入 _di/_s
#       逐个模拟；运行时只是一次 $((...)) 算术（纳秒级）。
#
# 类型 0-3 恒真（真实块用），4-7 恒假（诱饵块用）：
#   0/4: _di+1 恒正 / 0-_di-1 恒负
#   1/5: _di*_di+1 恒正 / 0-_di*_di-1 恒负
#   2/6: _di+_di+2 恒正 / -1 恒负
#   3/7: _di*2+1 恒正 / 0-_di*2-1 恒负
# 只用 + - * 基础算术，避免 ==/!=/>=/<=/% 及字符串比较，兼容所有 bash 版本。
#==============================================================================

gen_opaque_pred() {
    local target="$1"   # "true" 或 "false"
    if [ "$target" = "true" ]; then
        printf '%d' $((RANDOM % 4))
    else
        printf '%d' $((RANDOM % 4 + 4))
    fi
}

#==============================================================================
# bash $RANDOM 状态机模拟器（编译时使用，功能1 核心）
#
# 完整复现 bash 5.1+ lib/sh/random.c 的语义（AI 想在 Python 里模拟密钥链
# 必须同样复现，错一处全盘皆错）：
#   1. intrand32: Park-Miller 最小标准生成器（Schrage 法避免溢出）
#      rseed = 16807 * rseed mod (2^31-1)，rseed==0 时换 123459876
#   2. brand: ret = ((rseed>>16) ^ (rseed&65535)) & 32767   [compat>50, 即 bash≥5.1]
#   3. get_random_number: do { rv=brand() } while (rv==last)  ← 隐蔽去重循环
#   4. RANDOM=n 赋值: rseed=n (u32), last=0
#
# 运行时解释器 _am() 用真实 $RANDOM（每条指令前重播种），与此模拟一致。
#==============================================================================

SR_SEED=0
SR_LAST=0
SR_OUT=0
NEW_MK=""

# 注意：所有函数用全局变量传递状态/结果，绝不能放进 $(...) 子shell调用，
# 否则状态推进丢失（首次测试已踩坑：子shell里 SR_SEED 不回传，序列全部重复）
sim_random_reset() {   # 等价于运行时 RANDOM=$1
    SR_SEED=$(( $1 & 0xFFFFFFFF ))
    SR_LAST=0
}

sim_random_next() {    # 等价于运行时引用一次 $RANDOM（含 do-while 去重），结果写入 SR_OUT
    local h l t
    while :; do
        [ "$SR_SEED" -eq 0 ] && SR_SEED=123459876
        h=$(( SR_SEED / 127773 ))
        l=$(( SR_SEED - 127773 * h ))
        t=$(( 16807 * l - 2836 * h ))
        [ "$t" -lt 0 ] && t=$(( t + 2147483647 ))
        SR_SEED=$t
        t=$(( (SR_SEED >> 16) ^ (SR_SEED & 65535) ))
        t=$(( t & 32767 ))
        [ "$t" -ne "$SR_LAST" ] && break
    done
    SR_LAST=$t
    SR_OUT=$t
}

# 模拟解释器 _am() 的密钥推进：RS 状态机推进 → 重播种 → 消费2次 → sha512 掺入
# 与运行时 _am() 逐比特一致（毒化分支在正常环境不触发，无需模拟）。
# !! 必须用 sha512sum（_S5）：运行时 _am 用 "$_S5"，此处用 sha256sum 会密钥链分叉
# 结果写入 NEW_MK；调用方式: sim_advance_mk "$key" "$pos"; key=$NEW_MK
sim_advance_mk() {
    local ra rb
    VM_RS=$(( (VM_RS * 1103515245 + 12345) & 0x7fffffff ))
    sim_random_reset "$VM_RS"
    sim_random_next; ra=$SR_OUT
    sim_random_next; rb=$SR_OUT
    NEW_MK=$(printf '%s%d%d%d' "$1" "$2" "$ra" "$rb" | "$SHA512_BIN" | cut -c1-16)
}

#==============================================================================
# 生成不与契约变量冲突的随机变量名（_XX 形式）
# 契约变量（数据块与解释器共享，不可被重命名覆盖）：_mk _ck _c _d _s _di
# _rt _f _e _p _n _sa _sb _sc _sd _zz _zy _zv。若随机名撞上则重新生成。
#==============================================================================

# 变量名注册表：确保同一次生成的所有随机变量名互不相同。
# 不去重时 25 个变量从 62² 空间抽取，撞名概率约 8%（撞名 = 解释器逻辑错乱）
#
# !! 必须用文件而不是 bash 数组：所有调用点都是 rt_name="$(gen_rand_var)" 这种
#    $(...) 形式，gen_rand_var 在子 shell 里执行，数组 += 的注册无法传回父进程
#    → 注册表永远是空的 → 撞名未被阻止。已实锤的故障形态（随机复现 ~8%）：
#      某块 rt_name 撞上解释器改名后的循环计数变量 → 运行时 rt_name=$_ 把
#    循环计数覆盖成信标串 "__xxxxxx__" → [ p -lt n ] 报错 → VM 静默提前退出
#    （rc=0、输出截断、无任何报错）；撞上链变量则密钥链分叉 → base64 垃圾。
#    文件注册表对子 shell 持久，注册不会丢。
VAR_NAME_REGISTRY="$WORK_DIR/.var_registry"
: > "$VAR_NAME_REGISTRY" 2>/dev/null || VAR_NAME_REGISTRY="$(mktemp)"

gen_rand_var() {
    local name
    while :; do
        name="_$(gen_rand 2)"
        case "$name" in
            _mk|_ck|_c|_d|_s|_di|_rt|_f|_e|_p|_n|_sa|_sb|_sc|_sd|_zz|_zy|_zv) continue ;;
            _am|_ra|_rb|_pm|_nw|_t0|_t|_pp|_md|_rs|_B64|_SH256|_PRF|_I) continue ;;
            _da|_ke|_kb|_r|_i|_j|_b|_encoded|_hexdata|_bytes|_inst|_code|_ok|_pt) continue ;;
            _fp|_iH|_f1|_f2|_f3|_f4|_f5) continue ;;
            _a|_k|_m|_v|_bi|_bb|_bj|_bk) continue ;;
            _dv|_hb|_kf|_bt|_bs|_ia|_line) continue ;;
            # AES 版骨架契约名 + 解释器重命名源 token（防 sed 二次替换误伤）
            # _sl=数据层盐 _b=批明文 _ial=批内指令数组（解释器模板内联变量）
            _OS|_GZ|_UN|_S5|_S2|_SEED|_SLT|_ITR|_ek|_ent|_e1|_e2|_hs|_p1|_ins|_rj|_nb|_ni|_ii|_zw) continue ;;
            _sl|_b|_ial|_kf|_D) continue ;;
        esac
        # 跨子 shell 持久查重：命中已注册名则重生成
        if grep -qxF "$name" "$VAR_NAME_REGISTRY"; then
            continue
        fi
        # 避开用户脚本已有的标识符/子串（用户代码写同名变量会打断密钥链）
        if [ -n "$USER_SCRIPT_CONTENT" ] && grep -qF "$name" <<< "$USER_SCRIPT_CONTENT"; then
            continue
        fi
        printf '%s\n' "$name" >> "$VAR_NAME_REGISTRY"
        printf '%s' "$name"
        return
    done
}

#==============================================================================
# VM 解释器随机化生成器
#
# 原理：每次生成解释器时随机重命名内部变量（解密/加密函数、循环计数、
#       指令/数据局部变量），并在 while+case 与 while+if 两种控制流变体间
#       随机选择。→ 密文 _I 每次不同，AI 无法用固定模式字符串定位解释器。
#
# 注意：与数据块共享的契约变量（_mk/_ck/_c/_d/_di/_sl/_rs/_OS/_S5）在
#       gen_randomized_interpreter 末尾统一 sed 重命名为 compile_v5 生成的
#       N_* 随机名（骨架/数据块/解释器三端一致），仅此而已。
#==============================================================================

gen_builtin_fe_body() {
    # builtin 模式的解释器解/加密函数体。注意：
    #   - heredoc 引号包裹 → 内容原样输出，$ 不展开
    #   - awk 内 sprintf("\\x%02x") 双反斜杠原样保留 → 运行期 awk 输出 \xNN 文本
    #   - md % 4 归约：指令批传批索引 _p（>3），数据块传 0-3 原语号
    cat <<'FE_EOF'
_f() {
    local _da="$1" _ke="$2" _md="$3"
    local _kb _r
    _kb=$(printf '%s' "$_ke" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    _r=$(awk -v hex="$_da" -v kb="$_kb" -v md="$_md" '
    function x8(a, b,   r, p) {
        r = 0; p = 1
        while (a > 0 || b > 0) {
            r += ((a % 2 + b % 2) % 2) * p
            a = int(a / 2); b = int(b / 2); p *= 2
        }
        return r
    }
    BEGIN {
        md = md % 4
        n = split(kb, k, " ")
        hlen = length(hex)
        r = ""
        hx = "0123456789abcdef"
        for (i = 1; i <= hlen; i += 2) {
            hi = index(hx, tolower(substr(hex, i, 1))) - 1
            lo = index(hx, tolower(substr(hex, i+1, 1))) - 1
            b = hi * 16 + lo
            cnt = (i - 1) / 2
            kk = k[cnt % n + 1]
            if (md == 0) v = (b - kk + 256) % 256
            else if (md == 1) v = x8(b, kk)
            else if (md == 2) v = ((b - kk - cnt) % 256 + 256) % 256
            else v = (b + kk) % 256
            r = r sprintf("\\x%02x", v)
        }
        printf "%s", r
    }')
    printf "$_r" | base64 -d
}
_e() {
    local _da="$1" _ke="$2" _md="$3"
    local _encoded _kb _bytes
    _encoded=$(printf '%s' "$_da" | base64 -w0 2>/dev/null || printf '%s' "$_da" | base64 | tr -d '\n')
    _kb=$(printf '%s' "$_ke" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    _bytes=$(printf '%s' "$_encoded" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    awk -v data="$_bytes" -v kb="$_kb" -v md="$_md" '
    function x8(a, b,   r, p) {
        r = 0; p = 1
        while (a > 0 || b > 0) {
            r += ((a % 2 + b % 2) % 2) * p
            a = int(a / 2); b = int(b / 2); p *= 2
        }
        return r
    }
    BEGIN {
        md = md % 4
        n = split(kb, k, " ")
        nd = split(data, d, " ")
        for (i = 1; i <= nd; i++) {
            cnt = i - 1
            kk = k[(i-1) % n + 1]
            if (md == 0) printf "%02x", (d[i] + kk) % 256
            else if (md == 1) printf "%02x", x8(d[i], kk)
            else if (md == 2) printf "%02x", (d[i] + kk + cnt) % 256
            else printf "%02x", (d[i] - kk + 256) % 256
        }
    }'
}
FE_EOF
}

gen_randomized_interpreter() {
    local tlimit="${1:-120000000}"
    local I_DEC I_ENC V_DA V_KE V_KF
    local V_PC V_INST V_CODE V_OK V_PT V_B V_NB V_NI V_II V_IAL V_RJ
    local V_AM V_RA V_RB V_PM V_NW V_T0 V_PP V_T V_MD
    I_DEC="$(gen_rand_var)"; I_ENC="$(gen_rand_var)"
    V_DA="$(gen_rand_var)"; V_KE="$(gen_rand_var)"; V_KF="$(gen_rand_var)"
    V_B="$(gen_rand_var)"; V_NB="$(gen_rand_var)"; V_NI="$(gen_rand_var)"; V_II="$(gen_rand_var)"
    V_IAL="$(gen_rand_var)"; V_RJ="$(gen_rand_var)"
    V_PC="$(gen_rand_var)"; V_INST="$(gen_rand_var)"; V_CODE="$(gen_rand_var)"
    V_OK="$(gen_rand_var)"; V_PT="$(gen_rand_var)"
    V_AM="$(gen_rand_var)"; V_RA="$(gen_rand_var)"; V_RB="$(gen_rand_var)"; V_PM="$(gen_rand_var)"
    V_NW="$(gen_rand_var)"; V_T0="$(gen_rand_var)"; V_PP="$(gen_rand_var)"; V_T="$(gen_rand_var)"
    V_MD="$(gen_rand_var)"

    # builtin 模式：生成 _f/_e 的 awk 版函数体（x8 纯算术 + 4 原语，
    # 与编译期 builtin_enc_item/builtin_dec_item 逐字节互逆）
    local fe_body_file=""
    if [ "$CRYPTO_MODE" = "builtin" ]; then
        fe_body_file="$WORK_DIR/fe_body.txt"
        gen_builtin_fe_body > "$fe_body_file"
    fi

    local ctrl=$((RANDOM % 2))
    local interp
    if [ "$ctrl" -eq 0 ]; then
        interp=$(cat <<'I_EOF'
_f() {
    local _da="$1" _ke="$2" _md="$3"
    local _kf
    _kf=$(printf '%s%s%d%s' "$_ke" "$_sl" "$_md" "$_ke" | "$_S5")
    _kf=${_kf:0:96}
    printf '%s' "$_da" | "$_OS" enc -d -aes-256-ctr -a -A -K "${_kf:0:64}" -iv "${_kf:64:32}" 2>/dev/null
}
_e() {
    local _da="$1" _ke="$2" _md="$3"
    local _kf
    _kf=$(printf '%s%s%d%s' "$_ke" "$_sl" "$_md" "$_ke" | "$_S5")
    _kf=${_kf:0:96}
    printf '%s' "$_da" | "$_OS" enc -aes-256-ctr -a -A -K "${_kf:0:64}" -iv "${_kf:64:32}" 2>/dev/null
}
_am() {
    _rs=$(( (_rs * 1103515245 + 12345) & 0x7fffffff ))
    RANDOM=$_rs
    _ra=$RANDOM
    _rb=$RANDOM
    _pm=1
    [ $(( _p % 4 )) -eq 1 ] && {
        [ "$(builtin type -t eval)" != builtin ] && _pm=0
        case $- in *x*) _pm=0 ;; esac
        [ -n "${BASH_XTRACEFD:-}" ] && _pm=0
        [ "${PS4:-+ }" != "+ " ] && _pm=0
    }
    [ -n "${EPOCHREALTIME:-}" ] && { _nw=${EPOCHREALTIME//.}; [ $(( _nw - _t0 )) -gt __TL__ ] && _pm=0; }
    [ "$_pm" = 1 ] || _mk="${_mk}q"
    _mk=$(printf '%s%d%d%d' "$_mk" "$_p" "$_ra" "$_rb" | "$_S5")
    _mk=${_mk:0:16}
    return 0
}
_t0=${EPOCHREALTIME:-0}
_t0=${_t0//.}
_p=0
_n=${#_c[@]}
while [ "$_p" -lt "$_n" ]; do
    { _b=$(_f "${_c[$_p]}" "$_mk" "$_p"); } 2>/dev/null
    IFS=$'\x01' read -r -a _ial <<< "$_b"
    for _ii in "${_ial[@]}"; do
        _inst="$_ii"
        case "$_inst" in
            EXEC:*)
                _t="${_inst#EXEC:}"
                _md="${_t##*:}"
                _t="${_t%:*}"
                _pp="${_t##*:}"
                _di="${_t%:*}"
                { _code=$(_f "${_d[$_di]}" "$_ck" "$_md"); } 2>/dev/null
                case "$_pp" in
                    0) builtin eval "$_code" ;;
                    1) builtin source /dev/fd/9 9<<< "$_code" ;;
                    *) builtin source <(printf '%s' "$_code") ;;
                esac
                unset _code
                ;;
            CEXEC:*)
                _t="${_inst#CEXEC:}"
                _pt="${_t##*:}"
                _t="${_t%:*}"
                _md="${_t##*:}"
                _t="${_t%:*}"
                _pp="${_t##*:}"
                _di="${_t%:*}"
                case "$_pt" in
                    0) _ok=$(( _di + 1 )) ;;
                    1) _ok=$(( _di * _di + 1 )) ;;
                    2) _ok=$(( _di + _di + 2 )) ;;
                    3) _ok=$(( _di * 2 + 1 )) ;;
                    4) _ok=$(( 0 - _di - 1 )) ;;
                    5) _ok=$(( 0 - _di * _di - 1 )) ;;
                    6) _ok=$(( -1 )) ;;
                    7) _ok=$(( 0 - _di * 2 - 1 )) ;;
                    *) _ok=0 ;;
                esac
                if [ "$_ok" -gt 0 ]; then
                    { _code=$(_f "${_d[$_di]}" "$_ck" "$_md"); } 2>/dev/null
                    case "$_pp" in
                        0) builtin eval "$_code" ;;
                        1) builtin source /dev/fd/9 9<<< "$_code" ;;
                        *) builtin source <(printf '%s' "$_code") ;;
                    esac
                    unset _code
                fi
                ;;
            HALT)
                break 2
                ;;
            NOP|*)
                ;;
        esac
        unset _inst
    done
    _am
    _c[$_p]=$(_e "$_b" "$_mk" "$_p")
    # 赋值形式恒返回 0：((_p++)) 在 _p=0 时算术值为 0 → 返回码 1，
    # 会被用户脚本的 set -e 误杀（首块即 set -e 时必死，rc=1 无输出）
    _p=$((_p + 1))
done
unset _mk _ck _p _n _s _di _rt _sa _sb _sc _sd _zz _zy _zv _rs _ra _rb _pm _nw _t0 _ok _pt _pp _t _md _b _ial _ii _inst 2>/dev/null
I_EOF
)
    else
        interp=$(cat <<'I2_EOF'
_f() {
    local _da="$1" _ke="$2" _md="$3"
    local _kf
    _kf=$(printf '%s%s%d%s' "$_ke" "$_sl" "$_md" "$_ke" | "$_S5")
    _kf=${_kf:0:96}
    printf '%s' "$_da" | "$_OS" enc -d -aes-256-ctr -a -A -K "${_kf:0:64}" -iv "${_kf:64:32}" 2>/dev/null
}
_e() {
    local _da="$1" _ke="$2" _md="$3"
    local _kf
    _kf=$(printf '%s%s%d%s' "$_ke" "$_sl" "$_md" "$_ke" | "$_S5")
    _kf=${_kf:0:96}
    printf '%s' "$_da" | "$_OS" enc -aes-256-ctr -a -A -K "${_kf:0:64}" -iv "${_kf:64:32}" 2>/dev/null
}
_am() {
    _rs=$(( (_rs * 1103515245 + 12345) & 0x7fffffff ))
    RANDOM=$_rs
    _ra=$RANDOM
    _rb=$RANDOM
    _pm=1
    [ $(( _p % 4 )) -eq 1 ] && {
        [ "$(builtin type -t eval)" != builtin ] && _pm=0
        case $- in *x*) _pm=0 ;; esac
        [ -n "${BASH_XTRACEFD:-}" ] && _pm=0
        [ "${PS4:-+ }" != "+ " ] && _pm=0
    }
    [ -n "${EPOCHREALTIME:-}" ] && { _nw=${EPOCHREALTIME//.}; [ $(( _nw - _t0 )) -gt __TL__ ] && _pm=0; }
    [ "$_pm" = 1 ] || _mk="${_mk}q"
    _mk=$(printf '%s%d%d%d' "$_mk" "$_p" "$_ra" "$_rb" | "$_S5")
    _mk=${_mk:0:16}
    return 0
}
_t0=${EPOCHREALTIME:-0}
_t0=${_t0//.}
_p=0
_n=${#_c[@]}
while [ "$_p" -lt "$_n" ]; do
    { _b=$(_f "${_c[$_p]}" "$_mk" "$_p"); } 2>/dev/null
    IFS=$'\x01' read -r -a _ial <<< "$_b"
    for _ii in "${_ial[@]}"; do
        _inst="$_ii"
        if [ "${_inst#EXEC:}" != "$_inst" ]; then
            _t="${_inst#EXEC:}"
            _md="${_t##*:}"
            _t="${_t%:*}"
            _pp="${_t##*:}"
            _di="${_t%:*}"
            { _code=$(_f "${_d[$_di]}" "$_ck" "$_md"); } 2>/dev/null
            case "$_pp" in
                0) builtin eval "$_code" ;;
                1) builtin source /dev/fd/9 9<<< "$_code" ;;
                *) builtin source <(printf '%s' "$_code") ;;
            esac
            unset _code
        elif [ "${_inst#CEXEC:}" != "$_inst" ]; then
            _t="${_inst#CEXEC:}"
            _pt="${_t##*:}"
            _t="${_t%:*}"
            _md="${_t##*:}"
            _t="${_t%:*}"
            _pp="${_t##*:}"
            _di="${_t%:*}"
            case "$_pt" in
                0) _ok=$(( _di + 1 )) ;;
                1) _ok=$(( _di * _di + 1 )) ;;
                2) _ok=$(( _di + _di + 2 )) ;;
                3) _ok=$(( _di * 2 + 1 )) ;;
                4) _ok=$(( 0 - _di - 1 )) ;;
                5) _ok=$(( 0 - _di * _di - 1 )) ;;
                6) _ok=$(( -1 )) ;;
                7) _ok=$(( 0 - _di * 2 - 1 )) ;;
                *) _ok=0 ;;
            esac
            if [ "$_ok" -gt 0 ]; then
                { _code=$(_f "${_d[$_di]}" "$_ck" "$_md"); } 2>/dev/null
                case "$_pp" in
                    0) builtin eval "$_code" ;;
                    1) builtin source /dev/fd/9 9<<< "$_code" ;;
                    *) builtin source <(printf '%s' "$_code") ;;
                esac
                unset _code
            fi
        elif [ "$_inst" = "HALT" ]; then
            break 2
        fi
        unset _inst
    done
    _am
    _c[$_p]=$(_e "$_b" "$_mk" "$_p")
    _p=$((_p + 1))
done
unset _mk _ck _p _n _s _di _rt _sa _sb _sc _sd _zz _zy _zv _rs _ra _rb _pm _nw _t0 _ok _pt _pp _t _md _b _ial _ii _inst 2>/dev/null
I2_EOF
)
    fi

    # builtin 模式：把 AES 版 _f/_e 函数体（从 "_f() {" 行到 "_am() {" 行前）
    # 整段替换为 awk 版。替换正文经临时文件 + getline 读取 —— 不走 -v
    # （awk 对 -v 值做转义处理，正文中 \\x 会被吞，gawk/mawk 行为还不一致）
    if [ -n "$fe_body_file" ]; then
        interp=$(printf '%s\n' "$interp" | awk -v bf="$fe_body_file" '
            { lines[NR] = $0 }
            END {
                s = 0; e = 0
                for (i = 1; i <= NR; i++) {
                    if (lines[i] ~ /^_f\(\) \{/) s = i
                    if (lines[i] ~ /^_am\(\) \{/) { e = i; break }
                }
                if (s == 0 || e == 0 || e <= s) {
                    print "INTERNAL_ERROR_FE_SPAN" > "/dev/stderr"
                    exit 1
                }
                body = ""
                while ((getline l < bf) > 0) body = body l "\n"
                for (i = 1; i < s; i++) print lines[i]
                printf "%s", body
                for (i = e; i <= NR; i++) print lines[i]
            }')
        if [ $? -ne 0 ] || [[ "$interp" != *'printf "$_r" | base64 -d'* ]]; then
            echo "错误：解释器 builtin 函数体替换失败" >&2
            return 1
        fi
    fi

    # 随机重命名解释器私有变量（\b 防止部分匹配，awk 内部无下划线 token 不受影响）
    # 契约变量同样在此重命名为 N_*（_rs 现也随 N_RS 改名；私有名先替换，
    # 契约名后替换 —— 前者插入的新名不可能被后者模式命中：均为 \b 词边界匹配，
    # 且替换产物是完整 token，不会拼接出新匹配）
    interp=$(printf '%s' "$interp" | sed \
        -e "s/_f\b/${I_DEC}/g" \
        -e "s/_e\b/${I_ENC}/g" \
        -e "s/_da\b/${V_DA}/g" \
        -e "s/_ke\b/${V_KE}/g" \
        -e "s/_am\b/${V_AM}/g" \
        -e "s/_t0\b/${V_T0}/g" \
        -e "s/_t\b/${V_T}/g" \
        -e "s/_ra\b/${V_RA}/g" \
        -e "s/_rb\b/${V_RB}/g" \
        -e "s/_pm\b/${V_PM}/g" \
        -e "s/_nw\b/${V_NW}/g" \
        -e "s/_pp\b/${V_PP}/g" \
        -e "s/_md\b/${V_MD}/g" \
        -e "s/_p\b/${V_PC}/g" \
        -e "s/_n\b/${V_NB}/g" \
        -e "s/_inst\b/${V_INST}/g" \
        -e "s/_code\b/${V_CODE}/g" \
        -e "s/_ok\b/${V_OK}/g" \
        -e "s/_pt\b/${V_PT}/g" \
        -e "s/_ial\b/${V_IAL}/g" \
        -e "s/_ii\b/${V_II}/g" \
        -e "s/_kf\b/${V_KF}/g" \
        -e "s/_b\b/${V_B}/g" \
        -e "s/_OS\b/${N_OS}/g" \
        -e "s/_S5\b/${N_S5}/g" \
        -e "s/_sl\b/${N_SL}/g" \
        -e "s/_c\b/${N_C}/g" \
        -e "s/_d\b/${N_D}/g" \
        -e "s/_rs\b/${N_RS}/g" \
        -e "s/_mk\b/${N_MK}/g" \
        -e "s/_ck\b/${N_CK}/g" \
        -e "s/_di\b/${N_DI}/g" \
        -e "s/__TL__/${tlimit}/g" \
    )
    printf '%s' "$interp"
}

#==============================================================================
# 安卓/Termux 环境检测生成器
#
# 原理：真实脚本在 Termux（安卓）上运行，AI 一般在服务器 Linux 上运行
#       检出非安卓环境 → 拒绝执行（exit 1），直接废掉 AI 的动态抓取
#
# 多种检测信号随机选取，且混入加密块，grep 无法发现。
# 采用"宽松 OR"组合：命中任一安卓信号即通过，全部缺失才判定非安卓 → exit。
# 这样兼容多种安卓 shell 环境，避免误杀：
#   - 标准 Termux app：/system/build.prop、/data/data/com.termux、PREFIX、TERMUX_VERSION 都在
#   - ADB shell / Root 终端：ANDROID_ROOT、getprop、/system/build.prop 在，但无 Termux 信号
#   - 服务器 Linux：以上全部缺失 → exit 1
#
# 通过 ANDROID_GATE=0 可关闭（用于在非安卓环境测试）
#==============================================================================

gen_android_detection() {
    local t=$((RANDOM % 4))
    case $t in
        0)
            printf '%s' '[ -f /system/build.prop ] || [ -n "${ANDROID_ROOT:-}" ] || [ -d /data/data/com.termux ] || exit 1'
            ;;
        1)
            printf '%s' '[ -n "${PREFIX:-}" ] || [ -n "${TERMUX_VERSION:-}" ] || [ -n "${ANDROID_ROOT:-}" ] || exit 1'
            ;;
        2)
            printf '%s' '[ -n "${ANDROID_ROOT:-}" ] || command -v getprop >/dev/null 2>&1 || [ -f /system/build.prop ] || exit 1'
            ;;
        3)
            printf '%s' '[ -f /system/build.prop ] || [ -n "${PREFIX:-}" ] || [ -n "${ANDROID_ROOT:-}" ] || exit 1'
            ;;
    esac
}

#==============================================================================
# 平台指纹采集器（编译期与运行时 bootstrap 共用同一公式，两端逐比特一致）
#
# 信号选择原则：只选"所有安卓 Termux 必真 & 所有服务器 Linux 必假"的
# 稳定信号做 AND 组合，绝不绑定具体设备/型号/系统版本 → 换安卓设备零误判：
#   s1: uname -m ∈ {aarch64,armv7l,armv8l,armv6l}  ← x86/arm 服务器必假
#   s2: /system/build.prop 存在                     ← 非安卓系统必假
#   s3: /system/bin/getprop 可执行（绝对路径，防 PATH 劫持/伪造 PATH）
#   s4: /data/data/com.termux 存在                  ← 非 Termux 必假
#   s5: getprop ro.build.version.release 输出数字开头 ← 假 getprop/非安卓必假
#
# 与 gen_android_detection（可见门）的本质区别：指纹掺进 interp_key 和 _mk
# 初值 → 环境不符时第一步就解出乱码静默失败，伪造环境变量（export PREFIX/
# TERMUX_VERSION/...）对指纹完全无效 —— 门变成密钥原料，绕过动作本身失效
#==============================================================================

collect_platform_entropy() {
    local m v s1 s2 s3 s4 s5
    m=$(uname -m 2>/dev/null || echo x)
    case "$m" in
        aarch64|armv7l|armv8l|armv6l) s1=1 ;;
        *) s1=0 ;;
    esac
    [ -f /system/build.prop ] && s2=1 || s2=0
    [ -x /system/bin/getprop ] && s3=1 || s3=0
    [ -d /data/data/com.termux ] && s4=1 || s4=0
    s5=0
    if [ "$s3" = 1 ]; then
        v=$(/system/bin/getprop ro.build.version.release 2>/dev/null)
        case "$v" in [0-9]*) s5=1 ;; esac
    fi
    printf '%s%s%s%s%s' "$s1" "$s2" "$s3" "$s4" "$s5"
}

#==============================================================================
# 设备熵采集器（HOST_BIND=1 时启用；编译期与运行时共用同一公式）
#
# 与平台指纹的区别：平台指纹是"类"级（所有安卓=11111，仅 5 bit，可枚举），
# 设备熵是"台"级（serialno/android_id，数十~上百 bit，不可枚举）。
# 掺入密钥链后：攻击者拿到密文+骨架也推不出密钥 —— 唯一真墙。
#
# 取值优先级（稳定性排序，全部只读、无需 root）：
#   1. getprop ro.serialno / ro.boot.serialno（绝大多数真机非空）
#   2. settings get secure android_id（无串号设备兜底，加 A: 前缀防混同）
# 两者都取不到（模拟器/特殊 ROM）→ 返回空 → 绑定退化为平台指纹并告警
#
# 注意：HOST_BIND=1 意味着产物只在这台设备上运行（换机/重刷系统后失效），
# 这是 DRM 式绑定的固有属性，不是误判；默认关闭，用户显式开启
#==============================================================================

collect_device_entropy() {
    local dv=""
    if [ -x /system/bin/getprop ]; then
        dv="$(/system/bin/getprop ro.serialno 2>/dev/null)"
        [ -z "$dv" ] && dv="$(/system/bin/getprop ro.boot.serialno 2>/dev/null)"
    fi
    if [ -z "$dv" ] && [ -x /system/bin/settings ]; then
        dv="A:$(/system/bin/settings get secure android_id 2>/dev/null)"
    fi
    printf '%s' "$dv"
}

#==============================================================================
# 通用环境熵采集器（编译期与运行时共用同一公式，两端逐比特一致）
#
# 与平台指纹（5 bit 类级）的区别：环境熵掺入的是"值"（版本号/abi），
# 把攻击者的枚举空间从 ~1664 拉到数万级（配合 PBKDF2 单次验证成本）。
#
# KEY_ENTROPY 等级（值越大枚举空间越大，但可运行设备范围越窄）：
#   0：不掺任何环境熵（所有安卓类内设备可跑，枚举空间回到基线）
#   1：掺 ro.product.cpu.abi（现代机几乎都是 arm64-v8a，兼容性损失极小）
#   2：掺 abi + ro.build.version.release（默认；收件人需同 Android 大版本）
#
# 注意 KEY_ENTROPY=2 时 Android 13 编译的产物在 14 上解不开（静默乱码）。
# 分发给版本混杂的设备请用 KEY_ENTROPY=0 或 1。
#==============================================================================

collect_env_entropy() {
    local lvl="${1:-${KEY_ENTROPY:-2}}" e1="" e2=""
    if [ "$lvl" -ge 1 ] && [ -x /system/bin/getprop ]; then
        e2="$(/system/bin/getprop ro.product.cpu.abi 2>/dev/null)"
    fi
    if [ "$lvl" -ge 2 ] && [ -x /system/bin/getprop ]; then
        e1="$(/system/bin/getprop ro.build.version.release 2>/dev/null)"
    fi
    printf '%s|%s' "$e1" "$e2"
}

#==============================================================================
# AES-CTR 原语（openssl 实现，编译期侧）
#
# 为什么替换自制的 4 模式 awk 密码 + 循环 XOR（对抗已实锤的两种静态攻击）：
#   1. 循环 XOR + base64 已知明文 → 16 组各 421 样本逐位反推，零歧义（战报1）
#   2. 密钥原料可枚举 → 32 指纹 × 13 $- × 4 版本 ≈ 1664 次穷举（战报1）
# AES-CTR 后：已知明文只能推出密钥流片段，对 256 位密钥零信息；
# 枚举仍在但每次验证要付 PBKDF2 数万轮（GPU 也需小时级）。
#
# 块/指令层密钥派生（编译↔运行逐比特一致，_sl 为每次生成随机盐）：
#   kf = sha512( chainkey + _sl + index + chainkey )[0:96]
#   key = kf[0:64]（32 字节 AES-256），iv = kf[64:96]（16 字节 CTR 计数块）
# 每项 index 不同 → 密钥流永不重复，逐位独立性彻底消失
#==============================================================================

# 能力自检：按 CRYPTO_MODE 分支
#   aes：需 openssl（-aes-256-ctr -pbkdf2）+ gzip + sha512sum/sha256sum
#   builtin：零 openssl，需 sha512sum/sha256sum/base64/od/awk/gzip + /dev/urandom
check_crypto_capability() {
    GZIP_BIN=$(command -v gzip 2>/dev/null)
    SHA512_BIN=$(command -v sha512sum 2>/dev/null)
    SHA256_BIN=$(command -v sha256sum 2>/dev/null)

    if [ "$CRYPTO_MODE" = "builtin" ]; then
        local t
        for t in base64 od awk; do
            command -v "$t" >/dev/null 2>&1 || {
                echo "错误：builtin 模式缺少 $t（还需 gzip/sha512sum/sha256sum）。" >&2
                return 1
            }
        done
        if [ -z "$SHA512_BIN" ] || [ -z "$SHA256_BIN" ] || [ -z "$GZIP_BIN" ]; then
            echo "错误：本机缺少 gzip/sha512sum/sha256sum，无法生成 builtin 版本。" >&2
            return 1
        fi
        [ -r /dev/urandom ] || {
            echo "错误：/dev/urandom 不可读（密钥生成需要）。" >&2
            return 1
        }
        # 4 原语逐模式回环（含 >512 字节样本验证 mode 2 双取模修复）
        local pt="builtin_probe_$(date +%s)_$$_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad_pad"
        local m ct rt
        for m in 0 1 2 3; do
            ct=$(builtin_enc_item "$pt" "probekey$m" "$m")
            rt=$(builtin_dec_item "$ct" "probekey$m" "$m")
            if [ "$rt" != "$pt" ]; then
                echo "错误：builtin 原语 mode $m 回环失败（awk 兼容性问题）。" >&2
                return 1
            fi
        done
        return 0
    fi

    OPENSSL_BIN=$(command -v openssl 2>/dev/null)
    if [ -z "$OPENSSL_BIN" ] || [ -z "$SHA512_BIN" ] || [ -z "$SHA256_BIN" ] || [ -z "$GZIP_BIN" ]; then
        echo "错误：本机缺少 openssl/gzip/sha512sum/sha256sum，无法生成 AES 版本。（极简环境可用 CRYPTO_MODE=builtin）" >&2
        return 1
    fi
    local pt="cap_probe_$(date +%s)_$$" rt
    if [ -n "$GZIP_BIN" ]; then
        rt=$(printf '%s' "$pt" | "$GZIP_BIN" -c | "$OPENSSL_BIN" enc -aes-256-ctr -a -A -pbkdf2 -iter 1000 -pass pass:cap 2>/dev/null \
             | "$OPENSSL_BIN" enc -d -aes-256-ctr -a -A -pbkdf2 -iter 1000 -pass pass:cap 2>/dev/null | "$GZIP_BIN" -dc 2>/dev/null)
    else
        rt=$(printf '%s' "$pt" | "$OPENSSL_BIN" enc -aes-256-ctr -a -A -pbkdf2 -iter 1000 -pass pass:cap 2>/dev/null \
             | "$OPENSSL_BIN" enc -d -aes-256-ctr -a -A -pbkdf2 -iter 1000 -pass pass:cap 2>/dev/null)
    fi
    if [ "$rt" != "$pt" ]; then
        echo "错误：openssl 能力不足（需 ≥1.1.0 支持 -aes-256-ctr -pbkdf2）。" >&2
        return 1
    fi
    return 0
}

# 单项加密：$1=明文 $2=链密钥 $3=项索引 → base64(AES-CTR(明文))
aes_enc_item() {
    local kf
    kf=$(printf '%s%s%d%s' "$2" "$VM_AES_SALT" "$3" "$2" | "$SHA512_BIN" | cut -c1-96)
    printf '%s' "$1" | "$OPENSSL_BIN" enc -aes-256-ctr -a -A -K "${kf:0:64}" -iv "${kf:64:32}" 2>/dev/null
}

#==============================================================================
# builtin 原语（无 openssl 环境的回退架构，移植自 TShell_V2）
#
# 4 种原语，段级多态化核心（密钥按字节循环，k[i%n]）：
#   mode 0: Vigenère 加法  enc=(b+k)%256      ↔ 运行时 (b-k+256)%256
#   mode 1: XOR            enc=b^k            ↔ 运行时 b^k（x8 纯算术实现）
#   mode 2: 加法+位置      enc=(b+k+cnt)%256  ↔ 运行时 ((b-k-cnt)%256+256)%256
#           （mode 2 必须双取模：块长可超 512，单靠 +512 在 cnt>512 时
#             出现负数，mawk 的 % 保留符号 → %02x 输出垃圾 → 解密流损坏）
#   mode 3: Vigenère 减法  enc=(b-k+256)%256  ↔ 运行时 (b+k)%256
# 明文先 base64 再加密 → 密文为 hex 文本（全程文本安全）。
#
# x8() 为纯算术 XOR：awk 的 ^ 是幂运算（POSIX），mawk/busybox awk 无位运算
# 且无 gawk 的 xor()，直接 ^ 会算出天文数字（已踩坑）
#==============================================================================
builtin_enc_item() {
    local block="$1" key="$2" mode="${3:-0}"
    local encoded keybytes databytes
    encoded=$(printf '%s' "$block" | base64 -w0 2>/dev/null || printf '%s' "$block" | base64 | tr -d '\n')
    keybytes=$(printf '%s' "$key" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    databytes=$(printf '%s' "$encoded" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    awk -v data="$databytes" -v kb="$keybytes" -v md="$mode" '
    function x8(a, b,   r, p) {
        r = 0; p = 1
        while (a > 0 || b > 0) {
            r += ((a % 2 + b % 2) % 2) * p
            a = int(a / 2); b = int(b / 2); p *= 2
        }
        return r
    }
    BEGIN {
        md = md % 4
        n = split(kb, k, " ")
        nd = split(data, d, " ")
        for (i = 1; i <= nd; i++) {
            cnt = i - 1
            kk = k[(i-1) % n + 1]
            if (md == 0)      printf "%02x", (d[i] + kk) % 256
            else if (md == 1) printf "%02x", x8(d[i], kk)
            else if (md == 2) printf "%02x", (d[i] + kk + cnt) % 256
            else              printf "%02x", (d[i] - kk + 256) % 256
        }
    }'
}

# 编译期解密（自检/回环验证用；与运行期解释器 _f 的 awk 逐字节一致）
builtin_dec_item() {
    local hex="$1" key="$2" mode="${3:-0}"
    local keybytes r
    keybytes=$(printf '%s' "$key" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    r=$(awk -v hex="$hex" -v kb="$keybytes" -v md="$mode" '
    function x8(a, b,   r, p) {
        r = 0; p = 1
        while (a > 0 || b > 0) {
            r += ((a % 2 + b % 2) % 2) * p
            a = int(a / 2); b = int(b / 2); p *= 2
        }
        return r
    }
    BEGIN {
        md = md % 4
        n = split(kb, k, " ")
        hlen = length(hex)
        r = ""
        hx = "0123456789abcdef"
        for (i = 1; i <= hlen; i += 2) {
            hi = index(hx, tolower(substr(hex, i, 1))) - 1
            lo = index(hx, tolower(substr(hex, i+1, 1))) - 1
            b = hi * 16 + lo
            cnt = (i - 1) / 2
            kk = k[cnt % n + 1]
            if (md == 0) v = (b - kk + 256) % 256
            else if (md == 1) v = x8(b, kk)
            else if (md == 2) v = ((b - kk - cnt) % 256 + 256) % 256
            else v = (b + kk) % 256
            r = r sprintf("\\x%02x", v)
        }
        printf "%s", r
    }')
    printf "$r" | base64 -d
}

# 链式 sha512 慢哈希（builtin 模式的 PBKDF2 替代；每轮一个子进程，
# 编译期与运行期 bootstrap 用同一公式逐字节一致）
kdf_builtin() {
    local v="$1" i
    for ((i = 0; i < "$2"; i++)); do
        v=$(printf '%s' "$v" | "$SHA512_BIN" | cut -c1-64)
    done
    printf '%s' "$v"
}

# /dev/urandom 十六进制（builtin 模式的 openssl rand 替代）
urandom_hex() {
    od -An -tx1 -N"$1" /dev/urandom 2>/dev/null | tr -d ' \n'
}

# 加密调度器：按 CRYPTO_MODE 路由。$3 项索引在 aes 模式仅作密钥派生
# 掺杂；builtin 模式映射为 4 原语选择（运行期 _f 同样 md%4 归约）
enc_item() {
    if [ "$CRYPTO_MODE" = "builtin" ]; then
        builtin_enc_item "$1" "$2" "$(( ${3:-0} % 4 ))"
    else
        aes_enc_item "$1" "$2" "$3"
    fi
}

#==============================================================================
# V5 编译器：执行依赖密钥 + 安卓环境门控
#
# 核心机制：
#   1. _ck 密钥链依赖 _s（执行状态变量），必须真正执行代码才能得到下一个密钥
#   2. _s 有 8 种计算模式，每个块随机不同，攻击者必须逐块解密阅读才能推导
#   3. _ck 有 4 种派生模式，依赖 _s，进一步增加推导复杂度
#   4. 没有噪音块 — 每个块都是真实代码，不浪费执行时间
#==============================================================================

compile_v5() {
    local count=${#REAL_BLOCKS[@]}
    local i key encrypted state pattern

    # 平台指纹：编译机环境采集（运行时 bootstrap 用同一公式再算一遍）。
    # VM_FP_OVERRIDE 仅供测试注入假指纹，模拟"跨平台产物在错误环境运行"
    VM_PLATFORM_FP="${VM_FP_OVERRIDE:-$(collect_platform_entropy)}"

    # 设备熵（HOST_BIND=1 时启用）：编译机真实串号/android_id 掺入密钥链。
    # 产物只在编译这台设备上可解；VM_DV_OVERRIDE 仅供测试注入假设备熵
    VM_DEVICE_ID=""
    if [ "${HOST_BIND:-0}" = "1" ]; then
        VM_DEVICE_ID="${VM_DV_OVERRIDE:-$(collect_device_entropy)}"
        [ -z "$VM_DEVICE_ID" ] && \
            echo "警告: HOST_BIND=1 但未取到设备熵（无 serialno/android_id），绑定退化为平台指纹" >&2
    fi

    # 契约名整体随机化：骨架/解释器/数据块共享的全部全局名一次性抽取。
    # 用户脚本再怎么给 _mk/_ck/_c/_d/_di/_OS/_S2... 赋值也砸不到 VM 内部
    # （t_names 回归的根因修复）。gen_rand_var 注册表保证互不撞名且避开
    # 用户脚本全文子串。必须在 gen_randomized_interpreter 之前生成：
    # 解释器模板的 sed 按这些名字重命名。
    # 注意：_GZ/_hb/_ITR/_SEED/_I 仅 bootstrap 使用（先于任何用户代码执行），
    # 不可能被用户脚本砸，保持字面名不动。
    N_OS="$(gen_rand_var)"; N_S5="$(gen_rand_var)"; N_S2="$(gen_rand_var)"
    N_SL="$(gen_rand_var)"; N_C="$(gen_rand_var)";  N_D="$(gen_rand_var)"
    N_RS="$(gen_rand_var)"; N_MK="$(gen_rand_var)"; N_CK="$(gen_rand_var)"
    N_DI="$(gen_rand_var)"

    # 解释器提前到此处生成：指令流初值密钥要掺解释器明文哈希（IH）。
    # 运行时 bootstrap 在 eval 前对解密出的解释器文本算同一哈希掺入 _mk：
    #   攻击者往解密后的解释器里插 tee 日志 → IH 变 → 全链静默报废；
    #   且 IH 期望值深埋在指令密文里 —— 他环境不符时连解释器明文都拿不到，
    #   想硬编码 IH 必须先伪造全部 5 项指纹解开解释器，成本叠加一个量级
    # tlimit 按块数估算（指令数 ≤ 2×块数，原公式按指令数，此处略放宽无害）
    local tlimit=$(( count * 8000000 + 30000000 ))
    VM_INTERP_TEXT="$(gen_randomized_interpreter "$tlimit")"
    # 剥所有尾换行：与运行期 _D=$(... 命令替换的剥尾行为精确对齐（否则哈希分叉）。
    # 剥净后的文本同时是一层壳明文（finalize_layer1 加密它），存全局避免二次剥
    local it="$VM_INTERP_TEXT"
    while [[ "$it" == *$'\n' ]]; do it="${it%$'\n'}"; done
    VM_INTERP_STRIPPED="$it"
    # _iH 掺入 _mk 初值公式：sha512(_D)[0:16]，运行期 bootstrap 用 "$_S5" 同款
    VM_INTERP_HASH=$(printf '%s' "$VM_INTERP_STRIPPED" | "$SHA512_BIN" | cut -c1-16)

    # 功能3：密钥掺入 bash 运行时变量（$- / BASH_VERSINFO）
    # 运行时公式（输出脚本内）: sha512(SEED + FP + DV + IH + "$-" + VERSINFO[0] + 6)
    # 非真 bash（zsh/python 模拟器假设错）、环境指纹不符或非绑定设备
    # → 密钥直接错误，一步都解不开，且无任何报错提示错在哪
    local key_seed
    key_seed=$(gen_rand 16)
    VM_KEY_SEED="$key_seed"
    # 数据层 AES 盐（骨架契约变量 _sl；编译期 aes_enc_item 与运行期 _f/_e 共用）
    VM_AES_SALT="$(gen_rand 48)"
    # 运行期 $- 恒为 hB（#!/usr/bin/env bash 非交互执行）；目标 bash 主版本默认取本机
    TARGET_BASH_MAJOR="${TARGET_BASH_MAJOR:-${BASH_VERSINFO[0]}}"
    key=$(printf '%s%s%s%s%s%d%d' "$key_seed" "$VM_PLATFORM_FP" "$VM_DEVICE_ID" "$VM_INTERP_HASH" "hB" "$TARGET_BASH_MAJOR" 6 | "$SHA512_BIN" | cut -c1-16)

    # 功能1：$RANDOM 状态机初始种子（解释器 _am 每条指令前用它重播种）
    VM_RS=$(( (RANDOM * 32768 + RANDOM) & 0x7fffffff ))
    VM_INITIAL_RS="$VM_RS"

    VM_INITIAL_KEY="$key"
    VM_INSTRUCTIONS=()
    VM_DATA=()

    # 工具路径断言检测：builtin 模式骨架不绑定 N_OS（无 openssl 依赖），
    # 只断言哈希工具；aes 模式三件全断言
    local os_det="[ -x \"\$${N_S5}\" ] || exit 1; [ -x \"\$${N_S2}\" ] || exit 1"
    [ "$CRYPTO_MODE" != "builtin" ] && os_det="[ -x \"\$${N_OS}\" ] || exit 1; ${os_det}"
    local -a DETS=(
        '[[ $- == *x* ]] && exit 1; [ -n "${LD_PRELOAD:-}" ] && exit 1; [ -z "$(declare -f eval 2>/dev/null)" ] || exit 1'
        'if [ -r /proc/self/status ]; then _zv=$(grep "^TracerPid:" /proc/self/status 2>/dev/null | tr -dc "0-9"); [ "${_zv:-0}" != "0" ] && exit 1; fi'
        'if [ -r /proc/$PPID/cmdline ] 2>/dev/null; then _zv=$(tr "\0" " " < /proc/$PPID/cmdline 2>/dev/null); case "$_zv" in *strace*|*ltrace*|*gdb*|*ptrace*|*dbserver*) exit 1 ;; esac; fi'
        "$os_det"
        '[[ $- == *x* ]] && exit 1; [ -n "${LD_PRELOAD:-}" ] && exit 1'
        'if [ -r /proc/self/status ]; then _zv=$(grep "^TracerPid:" /proc/self/status 2>/dev/null | tr -dc "0-9"); [ "${_zv:-0}" != "0" ] && exit 1; fi; if [ -r /proc/$PPID/cmdline ] 2>/dev/null; then _zv=$(tr "\0" " " < /proc/$PPID/cmdline 2>/dev/null); case "$_zv" in *strace*|*ltrace*|*gdb*) exit 1 ;; esac; fi'
    )

    # 初始化 _s
    local s
    s=$(gen_rand 8)
    VM_INITIAL_S="$s"

    # 完整性校验（d0 内）：归一化 N_D[0]（自容器）与 _I（finalize 在 hash 之后才替换
    # 占位符为密文，不归一化则运行期必失配）。哈希走绑定路径 N_S2 = sha256sum。
    # sed 模式里的 N_D 为编译期随机名 —— 与 inject_integrity_hash 的归一化逐字一致
    local integ_code="[ -f \"\$0\" ] && { _zv=\$(sed 's/${N_D}\\[0\\]=\"[^\"]*\"/${N_D}[0]=\"X\"/; s/_I=\"[^\"]*\"/_I=\"\"/' \"\$0\" | \"\$${N_S2}\" | cut -c1-16); [ \"\$_zv\" = \"@@INTEGRITY_HASH@@\" ] || exit 1; }"

    # 预生成每块信标：模拟器与运行时 wrapped 块共用（见 simulate_execution 注释）
    VM_BEACONS=()
    for ((i = 0; i < count; i++)); do
        VM_BEACONS[$i]="__$(gen_rand 6)__"
    done

    # 执行模拟：获取每个块执行后的 $_ 值
    simulate_execution

    # 加密数据块：每个块注入检测 + 原始代码 + _rt捕获 + _s 计算 + _ck 派生
    local data_key="$key"
    local det_idx=0

    # 安卓门控：默认开启，ANDROID_GATE=0 关闭
    local android_gate
    if [ "${ANDROID_GATE:-1}" != "0" ]; then
        android_gate="$(gen_android_detection)"
    else
        android_gate=""
    fi

    # 段级多态化：每块随机 beacon 内容、rt/s 链变量名、加密原语 mode
    # s 链：块 i 读 s_cur 写 s_next，块 i+1 的 s_cur = 块 i 的 s_next
    VM_S0_NAME="$(gen_rand_var)"
    local s_cur="$VM_S0_NAME" s_next rt_name beacon dmode
    VM_DMODES=()
    for ((i = 0; i < count; i++)); do
        local wrapped det s_code new_s ck_code new_ck s_result ck_result
        local rt_val="${RT_VALUES[$i]:-}"

        det_idx=$((RANDOM % ${#DETS[@]}))
        det="${DETS[$det_idx]}"

        beacon="${VM_BEACONS[$i]}"
        rt_name="$(gen_rand_var)"
        s_next="$(gen_rand_var)"
        dmode=$((RANDOM % 4))

        s_result=$(gen_s_computation "$s" "$i" "$rt_val" "$rt_name" "$s_cur" "$s_next")
        s_code="${s_result%%$'\x01'*}"
        new_s="${s_result#*$'\x01'}"

        ck_result=$(gen_ck_derivation_with_s "$data_key" "$new_s" "$i" "$s_next")
        ck_code="${ck_result%%$'\x01'*}"
        new_ck="${ck_result#*$'\x01'}"

        # 块结构（多态）：第一块含 完整性校验 + 安卓门控
        if [ "$i" -eq 0 ]; then
            wrapped="${integ_code}"$'\n'"${android_gate}"$'\n'"${det}"$'\ntrue "'"${beacon}"'"'$'\n'"${REAL_BLOCKS[$i]}"$'\n'"${rt_name}=\$_"$'\n'"${s_code}"$'\n'"${ck_code}"
            VM_D0_PLAINTEXT="$wrapped"
        else
            wrapped="${det}"$'\ntrue "'"${beacon}"'"'$'\n'"${REAL_BLOCKS[$i]}"$'\n'"${rt_name}=\$_"$'\n'"${s_code}"$'\n'"${ck_code}"
        fi

        VM_DMODES[$i]="$dmode"
        VM_DATA[$i]=$(enc_item "$wrapped" "$data_key" "$dmode")

        s="$new_s"
        s_cur="$s_next"
        data_key="$new_ck"
    done

    # 诱饵块：染大文件体积与 AI 分析上下文，运行时零开销
    local decoy_level="${DECOY_LEVEL:-0}"
    VM_DECOY_MODES=()
    if [ "$decoy_level" -ge 1 ]; then
        local dc dc_total dc_det dc_wrapped dc_enc
        dc_total=$(( ${#VM_DATA[@]} * decoy_level ))
        for ((dc = 0; dc < dc_total; dc++)); do
            dc_det="${DETS[$((RANDOM % ${#DETS[@]}))]}"
            dc_wrapped=$(gen_decoy_wrapped "$data_key" "$dc_det" "$((1000 + dc))")
            # 诱饵指令携带同一 dmode（恒假谓词保证永不解密，此处仅为结构一致）
            VM_DECOY_MODES[$dc]=$((RANDOM % 4))
            dc_enc=$(enc_item "$dc_wrapped" "$data_key" "${VM_DECOY_MODES[$dc]}")
            VM_DATA+=("$dc_enc")
            # 链式推进密钥（仅外观，诱饵永不执行，不影响真实 _ck 链）
            data_key=$(printf '%s%d' "$data_key" "$dc" | sha256sum | cut -c1-16)
        done
        echo "信息：注入 $dc_total 个诱饵数据块（DECOY_LEVEL=$decoy_level）" >&2
    fi

    # 编译指令（明文列表）→ 批量化 AES 加密
    # 真实块随机 EXEC/CEXEC(恒真)，诱饵块 CEXEC(恒假)，随机 NOP 散布；
    # EXEC/CEXEC 带 path 字段（0=eval 1=fd here-string 2=process-sub），拆散单点
    # 指令格式：EXEC:块:路径:原语 / CEXEC:块:路径:原语:谓词
    local -a inst_list=()
    local inst_target
    for ((i = 0; i < count; i++)); do
        if [ $((RANDOM % 2)) -eq 1 ]; then
            inst_target="CEXEC:$i:$((RANDOM % 3)):${VM_DMODES[$i]}:$(gen_opaque_pred true)"
        else
            inst_target="EXEC:$i:$((RANDOM % 3)):${VM_DMODES[$i]}"
        fi
        case $((RANDOM % 3)) in
            0) inst_list+=("$inst_target") ;;
            1) inst_list+=("NOP" "$inst_target") ;;
            2) inst_list+=("$inst_target" "NOP") ;;
        esac
    done

    # 诱饵块指令：CEXEC(恒假谓词 4-7)，运行时跳过 eval → 数据零开销。
    # 每个诱饵块只生成 1 条指令（不散布 NOP），把指令解密成本降到最低。
    if [ "$decoy_level" -ge 1 ]; then
        local dci
        for ((dci = 0; dci < dc_total; dci++)); do
            inst_list+=("CEXEC:$((count + dci)):$((RANDOM % 3)):${VM_DECOY_MODES[$dci]}:$(gen_opaque_pred false)")
        done
    fi
    inst_list+=("HALT")

    # 批量化：INST_BATCH 条指令拼成一批（\x01 分隔，指令文本永不含 \x01），
    # 运行期一次 openssl 调用解密整批 → 进程数降到 1/INST_BATCH。
    # 批密钥链：批 b 用当前 _mk 加密；整批执行完 _am 推进（掺 $RANDOM 状态机，
    # sim_advance_mk 与运行时 _am 逐比特一致），再用新 _mk 重加密整批（自修改）
    local total=${#inst_list[@]}
    local nb=$(( (total + INST_BATCH - 1) / INST_BATCH ))
    local b j bp
    for ((b = 0; b < nb; b++)); do
        bp="${inst_list[$((b * INST_BATCH))]}"
        for ((j = b * INST_BATCH + 1; j < total && j < (b + 1) * INST_BATCH; j++)); do
            bp+=$'\x01'"${inst_list[$j]}"
        done
        VM_INSTRUCTIONS+=("$(enc_item "$bp" "$key" "$b")")
        sim_advance_mk "$key" "$b"
        key=$NEW_MK
    done

    echo "信息：V5编译完成，$count 真实块 / ${#VM_DATA[@]} 块总池，$total 条指令 / $nb 批（${CRYPTO_MODE:-aes}）" >&2
}

#==============================================================================
# 密钥分离（信封加密）
#
# 编译期：随机主密钥 M（256-bit）→ 用每个 passkey 独立包裹：
#   blob_i = AES-256-CTR( M + sha512(M)[0:16],
#                         key = PBKDF2(passkey_i, salt_i, UNWRAP_ITER) )
# 产物只携带 blob_i / salt_i；M 与 passkey 均不落盘。
# 运行期：read -s 取 passkey → 逐 blob 解包 → tag 校验通过得到 M →
#   P1 = sha512(_SEED + H_skel + 环境熵 + M) —— M 不在，一层壳永远解不开
#
# 多密钥安全性注记：
#   - N 个 blob = N 个独立的离线验证预言机：弱口令场景暴力破解成本降为 1/N；
#     默认生成 96-bit 随机密钥（openssl rand -hex 12）时实际无影响
#   - 任一密钥泄露 = 全量泄露（同权、无吊销）；分发多人时按需取舍
#==============================================================================
prepare_passkeys() {
    VM_MASTER_KEY=""
    PASSKEY_KEYS=()
    PASSKEY_BLOBS=()
    PASSKEY_SALTS=()
    [ "${PASSKEY_MODE:-0}" = 1 ] || return 0

    local n="${PASSKEY_COUNT:-1}" i k salt blob tag
    case "$n" in ''|*[!0-9]*) n=1 ;; esac
    [ "$n" -lt 1 ] && n=1
    [ "$n" -gt 16 ] && n=16

    # 主密钥与随机密钥生成：aes 用 openssl rand，builtin 用 /dev/urandom
    if [ "$CRYPTO_MODE" = "builtin" ]; then
        VM_MASTER_KEY=$(urandom_hex 32)
    else
        VM_MASTER_KEY=$("$OPENSSL_BIN" rand -hex 32)
    fi
    if [ -z "$VM_MASTER_KEY" ]; then
        echo "错误：主密钥生成失败" >&2
        return 1
    fi
    tag=$(printf '%s' "$VM_MASTER_KEY" | "$SHA512_BIN" | cut -c1-16)

    if [ -n "${PASSKEY_CUSTOM:-}" ]; then
        local -a keys=() filtered=()
        IFS='|' read -r -a keys <<< "$PASSKEY_CUSTOM"
        for k in "${keys[@]}"; do
            [ -n "$k" ] && filtered+=("$k")
        done
        if [ "${#filtered[@]}" -eq 0 ]; then
            echo "错误：PASSKEY_CUSTOM 未解析出任何非空密钥" >&2
            return 1
        fi
        PASSKEY_KEYS=("${filtered[@]}")
    else
        for ((i = 0; i < n; i++)); do
            if [ "$CRYPTO_MODE" = "builtin" ]; then
                PASSKEY_KEYS+=("$(urandom_hex 12)")
            else
                PASSKEY_KEYS+=("$("$OPENSSL_BIN" rand -hex 12)")
            fi
        done
    fi

    for k in "${PASSKEY_KEYS[@]}"; do
        if [ "$CRYPTO_MODE" = "builtin" ]; then
            salt=$(urandom_hex 8)
            # ku = 链式 sha512(passkey, salt)（运行期 unwrap 同公式）
            local ku kb db
            ku=$(kdf_builtin "PK|$k|$salt" "${BUILTIN_KDF_ITER:-600}")
            kb=$(printf '%s' "$ku" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
            db=$(printf '%s%s' "$VM_MASTER_KEY" "$tag" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
            blob=$(awk -v data="$db" -v kb="$kb" '
            function x8(a, b,   r, p) {
                r = 0; p = 1
                while (a > 0 || b > 0) {
                    r += ((a % 2 + b % 2) % 2) * p
                    a = int(a / 2); b = int(b / 2); p *= 2
                }
                return r
            }
            BEGIN {
                n = split(kb, k, " ")
                nd = split(data, d, " ")
                for (i = 1; i <= nd; i++) printf "%02x", x8(d[i], k[(i-1) % n + 1])
            }')
        else
            salt=$("$OPENSSL_BIN" rand -hex 8)
            blob=$(printf '%s%s' "$VM_MASTER_KEY" "$tag" \
                | "$OPENSSL_BIN" enc -aes-256-ctr -a -A -pbkdf2 \
                    -iter "${UNWRAP_ITER:-10000}" -md sha512 -S "$salt" \
                    -pass "pass:$k" 2>/dev/null)
        fi
        if [ -z "$blob" ]; then
            echo "错误：密钥包裹失败" >&2
            return 1
        fi
        PASSKEY_BLOBS+=("$blob")
        PASSKEY_SALTS+=("$salt")
    done
    return 0
}

generate_output_v6() {
    local output="$1"
    local timestamp i
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local ke="${KEY_ENTROPY:-2}"

    {
        echo "#!/usr/bin/env bash"
        echo "# Generated: $timestamp"
        echo ""

        # ===== 工具路径绑定（command -v → 绝对路径，密钥派生不走 PATH）=====
        # 契约名 N_* 为编译期随机名（compile_v5），与解释器/数据块逐字一致；
        # _GZ 仅 bootstrap 用（先于用户代码），保持字面名。
        # builtin 模式解释器不走 openssl，不绑定 _OS（产物在无 openssl 环境可跑）
        if [ "$CRYPTO_MODE" != "builtin" ]; then
            echo "${N_OS}=\$(command -v openssl 2>/dev/null || echo openssl)"
            echo "[ -x \"\$${N_OS}\" ] || exit 1"
        fi
        echo '_GZ=$(command -v gzip 2>/dev/null || echo gzip)'
        echo "${N_S5}=\$(command -v sha512sum 2>/dev/null || echo sha512sum)"
        echo "${N_S2}=\$(command -v sha256sum 2>/dev/null || echo sha256sum)"
        echo '[ -x "$_GZ" ] || exit 1'
        echo "[ -x \"\$${N_S5}\" ] || exit 1"
        echo "[ -x \"\$${N_S2}\" ] || exit 1"
        echo ""

        # ===== 加密指令批表（每条 = 一批指令 AES-CTR 密文的 base64）=====
        echo "declare -a ${N_C}"
        for ((i = 0; i < ${#VM_INSTRUCTIONS[@]}; i++)); do
            echo "${N_C}[$i]=\"${VM_INSTRUCTIONS[$i]}\""
        done
        echo ""

        # ===== 加密数据块表（检测代码已注入数据块，全部密文）=====
        echo "declare -a ${N_D}"
        for ((i = 0; i < ${#VM_DATA[@]}; i++)); do
            echo "${N_D}[$i]=\"${VM_DATA[$i]}\""
        done
        echo ""

        # ===== 状态初值（N_MK/N_CK 由下方 bootstrap 推导：依赖运行期指纹与 IH）=====
        echo "${N_RS}=$VM_INITIAL_RS"
        echo "$VM_S0_NAME=\"$VM_INITIAL_S\""
        echo "_hb=${HOST_BIND:-0}"
        echo "${N_SL}=\"$VM_AES_SALT\""
        if [ "$CRYPTO_MODE" = "builtin" ]; then
            echo "_BI=${BUILTIN_L1_ITER:-300}"
        else
            echo "_ITR=$L1_ITER"
        fi
        echo "_SEED=\"$VM_KEY_SEED\""
        echo ""

        # ===== 密钥分离（可选）：passkey 包裹的主密钥表（M 本体永不落盘）=====
        # _K/_KS/_PK/_UI/_nk 均为 bootstrap 私有名（先于用户代码执行）
        if [ "${PASSKEY_MODE:-0}" = 1 ]; then
            echo "_PK=1"
            if [ "$CRYPTO_MODE" = "builtin" ]; then
                echo "_UI=${BUILTIN_KDF_ITER:-600}"
            else
                echo "_UI=${UNWRAP_ITER:-10000}"
            fi
            echo "_nk=${#PASSKEY_BLOBS[@]}"
            echo "declare -a _K"
            for ((i = 0; i < ${#PASSKEY_BLOBS[@]}; i++)); do
                echo "_K[$i]=\"${PASSKEY_BLOBS[$i]}\""
            done
            echo "declare -a _KS"
            for ((i = 0; i < ${#PASSKEY_SALTS[@]}; i++)); do
                echo "_KS[$i]=\"${PASSKEY_SALTS[$i]}\""
            done
            echo ""
        fi

        # ===== 一层壳（占位，由 finalize_layer1 在最后一步加密替换）=====
        echo "_I=\"@@INTERP@@\""
        echo ""

        # ===== bootstrap：熵采集 → H_skel → P1 → 解密解释器 → IH → _mk → eval =====
        cat << 'BOOTSTRAP_EOF'
_e1=""
_e2=""
BOOTSTRAP_EOF
        if [ "$ke" -ge 1 ]; then
            echo 'if [ -x /system/bin/getprop ]; then _e2="$(/system/bin/getprop ro.product.cpu.abi 2>/dev/null)"; fi'
        fi
        if [ "$ke" -ge 2 ]; then
            echo 'if [ -x /system/bin/getprop ]; then _e1="$(/system/bin/getprop ro.build.version.release 2>/dev/null)"; fi'
        fi
        # 契约名经 __OS__/__S5__/__MK__/__CK__ 占位符由 sed 注入编译期随机名；
        # _SEED/_ITR/_BI/_hb/_GZ/_I 及 _hs/_p1/_k1/_fp/_dv 等为 bootstrap 私有
        # （先于任何用户代码执行，不可能被砸），保持字面名。
        # 结构：公共头（_hs/_M 初始化）→ 按模式中段（passkey 解包 + 一层壳
        # 解密）→ 公共尾（_iH/指纹/_mk 派生/eval/unset）
        local bsed="-e s/__OS__/${N_OS}/g -e s/__S5__/${N_S5}/g -e s/__MK__/${N_MK}/g -e s/__CK__/${N_CK}/g"
        cat << 'BS_HEAD_EOF' | sed $bsed
_hs=$(sed 's/_I="[^"]*"/_I=""/' "$0" 2>/dev/null | "$__S5__")
_hs=${_hs:0:128}
_M=""
BS_HEAD_EOF
        if [ "$CRYPTO_MODE" = "builtin" ]; then
            # builtin 中段：链式 sha512 解包 + x8 解密一层壳。
            # 解包/一层壳均为纯 XOR（密钥 = KDF 输出字符串的字节循环）
            cat << 'BS_MID_EOF' | sed $bsed
if [ "$_PK" = 1 ]; then
    _ok=0
    for _try in 1 2 3; do
        IFS= read -rs -p 'Key: ' _uk
        printf '\n' >&2
        [ -z "$_uk" ] && continue
        for ((_ki = 0; _ki < _nk; _ki++)); do
            _ku="PK|$_uk|${_KS[$_ki]}"
            for ((_kj = 0; _kj < _UI; _kj++)); do
                _ku=$(printf '%s' "$_ku" | "$__S5__" | cut -c1-64)
            done
            _kbb=$(printf '%s' "$_ku" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
            _rx=$(awk -v hex="${_K[$_ki]}" -v kb="$_kbb" '
            function x8(a, b,   r, p) {
                r = 0; p = 1
                while (a > 0 || b > 0) {
                    r += ((a % 2 + b % 2) % 2) * p
                    a = int(a / 2); b = int(b / 2); p *= 2
                }
                return r
            }
            BEGIN {
                n = split(kb, k, " ")
                hlen = length(hex)
                r = ""
                hx = "0123456789abcdef"
                for (i = 1; i <= hlen; i += 2) {
                    hi = index(hx, tolower(substr(hex, i, 1))) - 1
                    lo = index(hx, tolower(substr(hex, i+1, 1))) - 1
                    b = hi * 16 + lo
                    kk = k[int((i-1)/2) % n + 1]
                    r = r sprintf("\\x%02x", x8(b, kk))
                }
                printf "%s", r
            }')
            _ux=$(printf "$_rx" 2>/dev/null)
            if [ -n "$_ux" ] && [ "${_ux:64:16}" = "$(printf '%s' "${_ux:0:64}" | "$__S5__" | cut -c1-16)" ]; then
                _M="${_ux:0:64}"
                _ok=1
                break 2
            fi
        done
        printf 'key invalid\n' >&2
    done
    [ "$_ok" = 1 ] || exit 1
fi
_k1="L1|$_SEED|$_hs|$_e1|$_e2|$_M"
for ((_kj = 0; _kj < _BI; _kj++)); do
    _k1=$(printf '%s' "$_k1" | "$__S5__" | cut -c1-64)
done
_kbb=$(printf '%s' "$_k1" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
_rx=$(awk -v hex="$_I" -v kb="$_kbb" '
function x8(a, b,   r, p) {
    r = 0; p = 1
    while (a > 0 || b > 0) {
        r += ((a % 2 + b % 2) % 2) * p
        a = int(a / 2); b = int(b / 2); p *= 2
    }
    return r
}
BEGIN {
    n = split(kb, k, " ")
    hlen = length(hex)
    r = ""
    hx = "0123456789abcdef"
    for (i = 1; i <= hlen; i += 2) {
        hi = index(hx, tolower(substr(hex, i, 1))) - 1
        lo = index(hx, tolower(substr(hex, i+1, 1))) - 1
        b = hi * 16 + lo
        kk = k[int((i-1)/2) % n + 1]
        r = r sprintf("\\x%02x", x8(b, kk))
    }
    printf "%s", r
}')
{ _D=$(printf "$_rx" | base64 -d 2>/dev/null | "$_GZ" -dc 2>/dev/null); } 2>/dev/null
[ -n "$_D" ] || exit 1
BS_MID_EOF
        else
            cat << 'BS_MID_EOF' | sed $bsed
if [ "$_PK" = 1 ]; then
    _ok=0
    for _try in 1 2 3; do
        IFS= read -rs -p 'Key: ' _uk
        printf '\n' >&2
        [ -z "$_uk" ] && continue
        for ((_ki = 0; _ki < _nk; _ki++)); do
            { _ub=$(printf '%s' "${_K[$_ki]}" | "$__OS__" enc -d -aes-256-ctr -a -A -pbkdf2 -iter "$_UI" -md sha512 -S "${_KS[$_ki]}" -pass "pass:$_uk" 2>/dev/null); } 2>/dev/null
            _um=${_ub:0:64}
            _ut=${_ub:64:16}
            if [ -n "$_um" ] && [ "$_ut" = "$(printf '%s' "$_um" | "$__S5__" | cut -c1-16)" ]; then
                _M="$_um"
                _ok=1
                break 2
            fi
        done
        printf 'key invalid\n' >&2
    done
    [ "$_ok" = 1 ] || exit 1
fi
_p1=$(printf '%s%s%s|%s%s' "$_SEED" "$_hs" "$_e1" "$_e2" "$_M" | "$__S5__")
_p1=${_p1:0:64}
{ _D=$(printf '%s' "$_I" | "$__OS__" enc -d -aes-256-ctr -a -A -pbkdf2 -iter "$_ITR" -md sha512 -pass "pass:$_p1" 2>/dev/null | "$_GZ" -dc 2>/dev/null); } 2>/dev/null
[ -n "$_D" ] || exit 1
BS_MID_EOF
        fi
        cat << 'BS_TAIL_EOF' | sed $bsed
_iH=$(printf '%s' "$_D" | "$__S5__")
_iH=${_iH:0:16}
_m=$(uname -m 2>/dev/null || echo x)
case "$_m" in aarch64|armv7l|armv8l|armv6l) _f1=1 ;; *) _f1=0 ;; esac
[ -f /system/build.prop ] && _f2=1 || _f2=0
[ -x /system/bin/getprop ] && _f3=1 || _f3=0
[ -d /data/data/com.termux ] && _f4=1 || _f4=0
_f5=0
[ "$_f3" = 1 ] && { _v=$(/system/bin/getprop ro.build.version.release 2>/dev/null); case "$_v" in [0-9]*) _f5=1 ;; esac; }
_fp="$_f1$_f2$_f3$_f4$_f5"
_dv=""
if [ "$_hb" = 1 ]; then
    if [ -x /system/bin/getprop ]; then
        _dv="$(/system/bin/getprop ro.serialno 2>/dev/null)"
        [ -z "$_dv" ] && _dv="$(/system/bin/getprop ro.boot.serialno 2>/dev/null)"
    fi
    if [ -z "$_dv" ] && [ -x /system/bin/settings ]; then
        _dv="A:$(/system/bin/settings get secure android_id 2>/dev/null)"
    fi
fi
__MK__=$(printf '%s%s%s%s%s%d%d' "$_SEED" "$_fp" "$_dv" "$_iH" "$-" "${BASH_VERSINFO[0]}" "${#BASH_VERSINFO[@]}" | "$__S5__")
__MK__=${__MK__:0:16}
__CK__=$__MK__
eval "$_D"
unset _D _iH _p1 _k1 _hs _e1 _e2 _M _m _f1 _f2 _f3 _f4 _f5 _v _fp _dv _ub _um _ut _uk _ux _ok _try _ki _kj _ku _kbb _rx _K _KS _PK _UI _BI _nk 2>/dev/null
BS_TAIL_EOF

    } > "$output"
    chmod +x "$output"
}

#==============================================================================
# 输出文件压缩器
#
# 原理：
#   1. 去掉注释行和空行（注释会暴露代码结构）
#   2. 对每个语法块做内部压缩（多行→单行，用 ; 分隔）
#   3. 贪心合并：将可以用 ; 连接的连续块合并为一行
#==============================================================================

compact_output_file() {
    local file="$1"
    local content shebang

    content=$(<"$file")
    shebang=$(head -1 <<< "$content")
    content=$(tail -n +2 <<< "$content")

    # 去掉注释行和空行
    content=$(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' <<< "$content")

    # 拆分为语法块
    local blocks_file="$WORK_DIR/out_blocks.txt"
    split_into_blocks "$content" > "$blocks_file"

    # 读取块到数组，同时对每个块做内部压缩
    local -a blocks=()
    local blk
    while IFS= read -r -d '' blk || [ -n "$blk" ]; do
        [ -n "$blk" ] && blocks+=("$(compact_block "$blk")")
    done < "$blocks_file"

    # 贪心合并：将可以用 ; 连接的连续块合并为一行
    local -a merged=()
    local i=0 j combined err rc
    while [ "$i" -lt "${#blocks[@]}" ]; do
        local cur="${blocks[$i]}"
        j=$((i + 1))
        while [ "$j" -lt "${#blocks[@]}" ]; do
            combined="$cur; ${blocks[$j]}"
            err=$(bash -n <<< "$combined" 2>&1)
            rc=$?
            if [ $rc -eq 0 ] && [[ "$err" != *"here-document"* ]]; then
                cur="$combined"
                j=$((j + 1))
            else
                break
            fi
        done
        merged+=("$cur")
        i=$j
    done

    # 写回
    {
        printf '%s\n' "$shebang"
        for blk in "${merged[@]}"; do
            printf '%s\n' "$blk"
        done
    } > "$file"
    chmod +x "$file"

    echo "信息：输出文件已压缩（${#blocks[@]} 块 → ${#merged[@]} 段，$(wc -l < "$file") 行）" >&2
}

#==============================================================================
# 自完整性 hash 注入
#
# 原理：
#   1. 生成脚本时，_d[0] 里的完整性校验代码含占位符 @@INTEGRITY_HASH@@
#   2. 脚本生成+压缩后，计算真实 hash（用 sed 把 _d[0] 的值归一化为 "X"）
#   3. 把占位符替换为真实 hash，重新加密 _d[0]，更新到输出文件
#   4. 归一化保证：修改 _d[0] 不影响 hash，修改其他任何部分都会导致 hash 不匹配
#
# 攻击者改了脚本（比如加 echo "$_code"）→ hash 变了 → 第一个数据块检测到 → exit 1
# 攻击者无法修改预期 hash，因为它在加密的 _d[0] 里
#==============================================================================

inject_integrity_hash() {
    local file="$1"
    local hash d0_real encrypted_d0

    # 计算真实 hash：把 N_D[0] 归一化为 "X"、_I 归一化为空（与 d0 内运行期校验
    # 完全同款 sed；_I 归一化使后续 finalize_layer1 替换密文不影响 hash）
    # N_D 为编译期随机契约名（compile_v5 生成），两端逐字一致
    hash=$(sed "s/${N_D}\\[0\\]=\"[^\"]*\"/${N_D}[0]=\"X\"/; s/_I=\"[^\"]*\"/_I=\"\"/" "$file" | "$SHA256_BIN" | cut -c1-16)

    # 替换占位符为真实 hash
    d0_real="${VM_D0_PLAINTEXT/@@INTEGRITY_HASH@@/$hash}"

    # 重新加密 _d[0]（初始数据密钥 + d0 的多态索引，与 compile_v5 加密参数一致）
    encrypted_d0=$(enc_item "$d0_real" "$VM_INITIAL_KEY" "${VM_DMODES[0]}")

    # 更新输出文件中的 N_D[0]
    # 纯字符串 index/substr 替换：不用正则、不用转义序列。
    # 原因：awk 变体对 -v 值中 \[ 处理不一致 —— mawk 保留 \[（编译机自测通过），
    # gawk/Termux 警告并退化为 plain '[' → [0] 变字符类只匹配 '0' → 模式失配
    # → d0 替换静默失败 → 运行期完整性校验对不上占位符 → 产物静默 exit 1
    # （用户 Termux 实测踩坑）。index/substr 为 POSIX 必备函数，全变体一致。
    # base64 字母表无引号 → tail 里第一个 " 必然是真实收尾引号
    awk -v pre="${N_D}[0]=\"" -v nv="$encrypted_d0" '
        {
            i = index($0, pre)
            if (i > 0) {
                tail = substr($0, i + length(pre))
                j = index(tail, "\"")
                if (j > 0) $0 = substr($0, 1, i - 1) pre nv substr(tail, j)
            }
            print
        }' "$file" > "$file.tmp"
    mv "$file.tmp" "$file"
    chmod +x "$file"

    # 硬校验：新密文必须真实落盘（-F 字面匹配，无正则）。
    # 之前只有 sed 归一化 hash 复核 —— d0 行被归一化，替换失败它照样通过；
    # 现在直接断言新值在文件里，任何 awk 变体差异导致的静默失败立即编译报错
    if ! grep -qF "${N_D}[0]=\"${encrypted_d0}\"" "$file"; then
        echo "错误：完整性 d0 替换未生效（awk 兼容性问题），产物已作废" >&2
        return 1
    fi

    # 验证：重新计算 hash 确认一致
    local verify_hash
    verify_hash=$(sed "s/${N_D}\\[0\\]=\"[^\"]*\"/${N_D}[0]=\"X\"/; s/_I=\"[^\"]*\"/_I=\"\"/" "$file" | "$SHA256_BIN" | cut -c1-16)
    if [ "$verify_hash" != "$hash" ]; then
        echo "警告：完整性 hash 验证失败（$hash vs $verify_hash）" >&2
        return 1
    fi

    echo "信息：已注入完整性校验 hash（$hash）" >&2
}

#==============================================================================
# 一层壳封装（最后一步）
#
# P1 = sha512(_SEED + H_skel + 环境熵e1 + "|" + e2 + M)[0:64]
#   H_skel = sha512(骨架文件，_I 行归一化为空)[0:128]
#   —— 与运行期 bootstrap 的 _p1 公式逐比特一致
#   M = 密钥分离模式的主密钥（PASSKEY_MODE=1 时；空串 = 模式关闭）
#
# 攻击成本模型：
#   - 改骨架任何一个字节（插桩 echo/tee、换工具路径、改指令表）→ H_skel 变
#     → P1 变 → 解释器 AES 解不开 → 必须先枚举出正确 P1（每次尝试一次
#     PBKDF2 全迭代，L1_ITER=600000 次 sha512）才能伪造一层壳密文
#   - KEY_ENTROPY≥1 时 P1 还掺 abi/安卓版本：服务器重放的枚举空间再乘一个维度
#   - 错误 P1 → 解密乱码 → gzip 校验失败 → _D 空 → eval 空串 → 静默退出
#==============================================================================

finalize_layer1() {
    local file="$1"
    local hs ent e1 e2 p1 ct

    # H_skel：与运行期 _hs 同公式（_I 归一化 → 替换密文不改变自身哈希）
    hs=$(sed 's/_I="[^"]*"/_I=""/' "$file" | "$SHA512_BIN" | cut -c1-128)

    # 环境熵：与运行期 bootstrap 的 getprop 采集同公式（编译机=目标机时一致）
    ent="$(collect_env_entropy "${KEY_ENTROPY:-2}")"
    e1="${ent%%|*}"
    e2="${ent#*|}"

    local ct rt _l1
    if [ "$CRYPTO_MODE" = "builtin" ]; then
        # builtin 一层壳：k1 = 链式 sha512("L1|SEED|hs|e1|e2|M")（与运行期
        # bootstrap 的 _k1 循环逐字节一致）；解释器 gzip→base64→x8（密钥 =
        # k1 字符串字节循环）→ hex 密文（sed 安全字母表）
        local k1 kb db
        k1=$(kdf_builtin "L1|${VM_KEY_SEED}|${hs}|${e1}|${e2}|${VM_MASTER_KEY}" "${BUILTIN_L1_ITER:-300}")
        kb=$(printf '%s' "$k1" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
        # 解释器 gzip（二进制）→ base64 -w0（文本安全；Termux coreutils 支持）
        db=$(printf '%s' "$VM_INTERP_STRIPPED" | "$GZIP_BIN" -c 2>/dev/null | base64 -w0)
        db=$(printf '%s' "$db" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
        ct=$(awk -v data="$db" -v kb="$kb" '
        function x8(a, b,   r, p) {
            r = 0; p = 1
            while (a > 0 || b > 0) {
                r += ((a % 2 + b % 2) % 2) * p
                a = int(a / 2); b = int(b / 2); p *= 2
            }
            return r
        }
        BEGIN {
            n = split(kb, k, " ")
            nd = split(data, d, " ")
            for (i = 1; i <= nd; i++) printf "%02x", x8(d[i], k[(i-1) % n + 1])
        }')
        if [ -z "$ct" ] || [ "${#ct}" -lt 64 ]; then
            echo "错误：一层壳加密失败（builtin 加密返回空）" >&2
            return 1
        fi
        sed -i "s|@@INTERP@@|$ct|" "$file"
        chmod +x "$file"
        if grep -q '@@INTERP@@' "$file"; then
            echo "错误：一层壳占位符替换失败" >&2
            return 1
        fi
        _l1=$(grep -o '_I="[^"]*"' "$file" | head -1)
        _l1="${_l1#_I=\"}"
        _l1="${_l1%\"}"
        # 回环自检：与运行期 bootstrap 同款解密（x8 → base64 -d → gunzip）
        local rxb
        rxb=$(awk -v hex="$_l1" -v kb="$kb" '
        function x8(a, b,   r, p) {
            r = 0; p = 1
            while (a > 0 || b > 0) {
                r += ((a % 2 + b % 2) % 2) * p
                a = int(a / 2); b = int(b / 2); p *= 2
            }
            return r
        }
        BEGIN {
            n = split(kb, k, " ")
            hlen = length(hex)
            r = ""
            hx = "0123456789abcdef"
            for (i = 1; i <= hlen; i += 2) {
                hi = index(hx, tolower(substr(hex, i, 1))) - 1
                lo = index(hx, tolower(substr(hex, i+1, 1))) - 1
                b = hi * 16 + lo
                kk = k[int((i-1)/2) % n + 1]
                r = r sprintf("\\x%02x", x8(b, kk))
            }
            printf "%s", r
        }')
        rt=$(printf "$rxb" | base64 -d 2>/dev/null | "$GZIP_BIN" -dc 2>/dev/null)
        if [ "$rt" != "$VM_INTERP_STRIPPED" ]; then
            echo "错误：一层壳回环验证失败（builtin 解密与解释器明文不一致）" >&2
            return 1
        fi
        echo "信息：一层壳封装完成（builtin 链式 ${BUILTIN_L1_ITER:-300} 轮，密文 ${#ct} 字符，熵等级 ${KEY_ENTROPY:-2}）" >&2
        return 0
    fi

    # P1 口令（密钥分离模式：掺入主密钥 M；未启用时 VM_MASTER_KEY 为空串，
    # printf 尾部空 %s 不产生任何字符 —— 两种模式与运行期 _M 逐字节一致）
    p1=$(printf '%s%s%s|%s%s' "$VM_KEY_SEED" "$hs" "$e1" "$e2" "$VM_MASTER_KEY" | "$SHA512_BIN" | cut -c1-64)

    # gzip + PBKDF2-AES-256-CTR 加密解释器（明文 = compile_v5 剥净尾换行文本）
    ct=$(printf '%s' "$VM_INTERP_STRIPPED" | "$GZIP_BIN" -c \
        | "$OPENSSL_BIN" enc -aes-256-ctr -a -A -pbkdf2 -iter "$L1_ITER" -md sha512 \
          -pass "pass:$p1" 2>/dev/null)
    if [ -z "$ct" ] || [ "${#ct}" -lt 64 ]; then
        echo "错误：一层壳加密失败（openssl 返回空）" >&2
        return 1
    fi

    # 替换占位符（| 作分隔符，base64 字母表不含 | & \，sed 替换串安全）
    sed -i "s|@@INTERP@@|$ct|" "$file"
    chmod +x "$file"

    # 自检：占位符必须已消失，且密文可被同参数解回（编译机自证）。
    # 注意 _I 可能被 compact 合并进长行 → 用模式提取而非行锚定
    if grep -q '@@INTERP@@' "$file"; then
        echo "错误：一层壳占位符替换失败" >&2
        return 1
    fi
    _l1=$(grep -o '_I="[^"]*"' "$file" | head -1)
    _l1="${_l1#_I=\"}"
    _l1="${_l1%\"}"
    rt=$(printf '%s' "$_l1" \
        | "$OPENSSL_BIN" enc -d -aes-256-ctr -a -A -pbkdf2 -iter "$L1_ITER" -md sha512 \
          -pass "pass:$p1" 2>/dev/null | "$GZIP_BIN" -dc 2>/dev/null)
    if [ "$rt" != "$VM_INTERP_STRIPPED" ]; then
        echo "错误：一层壳回环验证失败（解密文本与解释器明文不一致）" >&2
        return 1
    fi

    echo "信息：一层壳封装完成（PBKDF2 ${L1_ITER} 轮，密文 ${#ct} 字符，熵等级 ${KEY_ENTROPY:-2}）" >&2
}

#==============================================================================
# 主混淆引擎
#==============================================================================

obfuscate_script() {
    local input_script="$1" output_script="$2"

    if [[ ! -f "$input_script" ]]; then
        echo "错误：输入文件 '$input_script' 不存在。" >&2
        return 1
    fi

    local script_content
    script_content=$(<"$input_script")

    if [[ "$script_content" =~ ^#!.* ]]; then
        script_content=$(sed '1d' <<< "$script_content")
    fi

    local blocks_file="$WORK_DIR/blocks.txt"
    split_into_blocks "$script_content" > "$blocks_file"

    REAL_BLOCKS=()
    local block
    while IFS= read -r -d '' block || [ -n "$block" ]; do
        [ -n "$block" ] && REAL_BLOCKS+=("$block")
    done < "$blocks_file"

    local real_count=${#REAL_BLOCKS[@]}
    if [ "$real_count" -eq 0 ]; then
        echo "错误：输入脚本为空或无法解析。" >&2
        return 1
    fi

    echo "信息：拆分为 $real_count 个代码块" >&2

    # JUNK_LEVEL：真执行垃圾块注入
    # 直接混入 REAL_BLOCKS → 垃圾块与真实块走完全相同的编译路径：
    #   同样的 det 检测/beacon/rt 捕获/_s 计算/_ck 派生/EXEC 指令
    # 结构上无法区分"哪块是垃圾"，且每块都推进密钥链，重放时一块都跳不过
    # （无论 JUNK_LEVEL 取值都要先记录原文：随机变量名/垃圾名都要避开它）
    USER_SCRIPT_CONTENT="$script_content"
    local junk_level="${JUNK_LEVEL:-0}"
    if [ "$junk_level" -ge 1 ]; then
        local -a mixed_blocks=()
        local jb jcode
        for ((j = 0; j < real_count; j++)); do
            mixed_blocks+=("${REAL_BLOCKS[$j]}")
            for ((jb = 0; jb < junk_level; jb++)); do
                jcode="$(gen_junk_code)"
                mixed_blocks+=("$jcode")
            done
        done
        REAL_BLOCKS=("${mixed_blocks[@]}")
        echo "信息：注入 $((junk_level * real_count)) 个真执行垃圾块（JUNK_LEVEL=$junk_level），总块数 ${#REAL_BLOCKS[@]}" >&2
    fi

    compile_v5

    # 密钥分离：生成主密钥与包裹表（必须在骨架输出前；模式关闭时为空操作）
    prepare_passkeys || return 1

    generate_output_v6 "$output_script"

    compact_output_file "$output_script"

    inject_integrity_hash "$output_script" || return 1

    # 一层壳必须在最后：H_skel 要覆盖 compact/inject 之后的最终骨架，
    # 且替换密文后不得再改动文件任何字节（否则 _hs 失配 → P1 失配）
    finalize_layer1 "$output_script" || return 1

    # 密钥分离模式：打印/保存密钥（M 与密钥均不在产物内）
    if [ "${PASSKEY_MODE:-0}" = 1 ]; then
        echo "信息：密钥分离模式已启用（${#PASSKEY_KEYS[@]} 个密钥，主密钥未嵌入产物）" >&2
        local kn=1 kv
        for kv in "${PASSKEY_KEYS[@]}"; do
            echo "  密钥 $kn: $kv" >&2
            kn=$((kn + 1))
        done
        if [ -n "${PASSKEY_FILE:-}" ]; then
            if printf '%s\n' "${PASSKEY_KEYS[@]}" > "$PASSKEY_FILE" 2>/dev/null; then
                chmod 600 "$PASSKEY_FILE" 2>/dev/null
                echo "信息：密钥已写入 $PASSKEY_FILE（权限 600）" >&2
            else
                echo "警告：密钥文件写入失败：$PASSKEY_FILE" >&2
            fi
        fi
        echo "警告：密钥丢失即无法运行，请立即妥善保存（切勿随产物一起分发）" >&2
    fi

    echo "成功：已生成 V5 混淆脚本 '$output_script'"
}

#==============================================================================
# 主程序入口
#==============================================================================

main() {
    if [[ $# -lt 1 ]]; then
        echo "用法: $0 <input_script.sh> [output_script.sh]"
        echo ""
        echo "V5 特性：AES-256-CTR 全链加密 + PBKDF2 一层壳 + 执行依赖密钥链"
        echo "环境变量：JUNK_LEVEL=N    每个真实块后注入 N 个真执行垃圾块（默认 0）"
        echo "          DECOY_LEVEL=N  注入 N×真实块数的死诱饵块（默认 0）"
        echo "          ANDROID_GATE=0 关闭安卓环境门控（默认 1）"
        echo "          KEY_ENTROPY=N  一层口令掺环境熵 0/1/2（默认 2）"
        echo "          HOST_BIND=1    密钥掺本机串号（产物仅本机可跑）"
        echo "          CRYPTO_MODE=builtin 纯 shell/awk 架构（零 openssl 依赖；默认 aes）"
        echo "          BUILTIN_KDF_ITER=N builtin 密钥分离 KDF 轮数（默认 600）"
        echo "          L1_ITER=N      一层 PBKDF2 迭代次数（默认 600000）"
        echo "          PASSKEY_MODE=1 密钥分离：运行期向用户要密钥（密钥不嵌入产物）"
        echo "          PASSKEY_COUNT=N 密钥个数 1-16（默认 1），或 PASSKEY_CUSTOM='k1|k2'"
        echo "          UNWRAP_ITER=N  解包裹 PBKDF2 迭代（默认 10000，弱口令请调高）"
        return 1
    fi

    # 编译期能力自检：openssl AES-256-CTR/PBKDF2 + gzip + sha512sum 回环
    check_crypto_capability || return 1

    local input_file="$1"
    local output_file="${2:-${input_file%.sh}_v5.sh}"

    obfuscate_script "$input_file" "$output_file"
    return $?
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi