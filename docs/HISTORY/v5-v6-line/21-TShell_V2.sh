#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md

# shell_script_obfuscator_v5.sh - VM 内嵌检测 + 绝对路径绑定 + eval 网关
#
# 相对 V4 的改进：
#   1. 安全检测编译成 VM 指令（CHKDBG/CHKEVAL/CHKPATH），混入字节码流
#      → 攻击者不解密字节码就不知道有哪些检测、何时触发
#   2. 关键命令绑定绝对路径，防止 PATH 篡改
#   3. 自定义 eval 网关 _E()，轻量级 per-call 检测
#   4. 检测指令随机散布在执行流中，不是集中在开头

OBFUSCATION_LEVEL=${OBFUSCATION_LEVEL:-3}
# 诱饵数据块等级：0 关闭，N≥1 时注入 N×真实块数的诱饵（运行时零开销）
DECOY_LEVEL=${DECOY_LEVEL:-0}
# 真执行垃圾块等级：0 关闭，N≥1 时在每个真实块后注入 N 个垃圾块。
# 垃圾块与真实块结构完全相同（det/beacon/rt/s/ck 链），会真正 eval 执行，
# 但对原始代码零影响；它们参与密钥链 → AI 重放 VM 时一个都跳不过去，
# 只能逐块解密求值，上下文/压缩次数成倍增长
JUNK_LEVEL=${JUNK_LEVEL:-0}
# 目标 bash 主版本（功能3 密钥绑定 BASH_VERSINFO[0]，需 bash≥5.1）
TARGET_BASH_MAJOR=${TARGET_BASH_MAJOR:-5}
WORK_DIR=$(mktemp -d)

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT INT TERM

#==============================================================================
# 工具函数
#==============================================================================

base64_encode() {
    if printf '' | base64 -w0 >/dev/null 2>&1; then
        base64 -w0
    else
        base64 | tr -d '\n'
    fi
}

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
# 数据块加密（4 种原语，段级多态化核心）
#
# mode 0: Vigenère 加法  enc=(b+k)%256          ↔ 运行时 (b-k+256)%256
# mode 1: XOR            enc=b^k                ↔ 运行时 b^k
# mode 2: 加法+位置      enc=(b+k+cnt)%256      ↔ 运行时 ((b-k-cnt)%256+256)%256
#   注意 mode 2 必须双取模：cnt 是字节位置，块 base64 长度可远超 512，
#   单靠 +512 在 cnt>512 时出现负数，awk/mawk 的 % 保留被除数符号 →
#   v 为负 → sprintf %02x 输出垃圾/NUL → 解密流损坏（块越长越必炸）
# mode 3: Vigenère 减法  enc=(b-k+256)%256      ↔ 运行时 (b+k)%256
#
# 每个数据块/指令随机选 mode，AI 写通用重放器必须 4 种全实现 + 还原选择逻辑
#
# 注意：mode 1 的 XOR 用 x8() 纯算术实现。awk 的 ^ 是幂运算（POSIX），
# mawk/busybox awk 无位运算且无 gawk 的 xor()，直接 ^ 会算出天文数字，
# mawk 的 %02x 对越界值输出 8 个 f → 密文膨胀 4 倍且无法解回（已踩坑）。
#==============================================================================

encrypt_block() {
    local block="$1" key="$2" mode="${3:-0}"
    local encoded keybytes databytes
    encoded=$(printf '%s' "$block" | base64_encode)
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

#==============================================================================
# XOR 加密（用于加密 VM 解释器，与 _f 的 Vigenère 减法不同）
# 攻击者需要理解两种不同的算法才能解密全部内容
#==============================================================================

xor_encrypt_block() {
    local block="$1" key="$2"
    local encoded hexdata result="" i j sc kc
    encoded=$(printf '%s' "$block" | base64_encode)
    hexdata=$(printf '%s' "$encoded" | od -An -tx1 -v | tr -d ' \n')
    for ((i = 0; i < ${#hexdata}; i += 2)); do
        sc=$((16#${hexdata:$i:2}))
        j=$(((i / 2) % ${#key}))
        kc=$(printf '%d' "'${key:$j:1}")
        result+=$(printf '%02x' $((sc ^ kc)))
    done
    printf '%s' "$result"
}

#==============================================================================
# 密钥派生模式生成器：为每个数据块生成不同的密钥演进代码
# 攻击者无法用统一公式模拟密钥链，必须逐块分析每段代码
#==============================================================================

gen_key_derivation() {
    local current_key="$1"
    local pattern zz factor temp
    pattern=$((RANDOM % 5))

    case $pattern in
        0)
            # 模式0：简单 hash
            printf '%s\x01%s' \
                '_ck=$(printf "%s" "$_ck" | sha256sum | cut -c1-16)' \
                "$(printf '%s' "$current_key" | sha256sum | cut -c1-16)"
            ;;
        1)
            # 模式1：hash + 随机数
            zz=$((RANDOM % 10000 + 1))
            printf '%s\x01%s' \
                "_zz=$zz; _ck=\$(printf '%s%d' \"\$_ck\" \"\$_zz\" | sha256sum | cut -c1-16)" \
                "$(printf '%s%d' "$current_key" "$zz" | sha256sum | cut -c1-16)"
            ;;
        2)
            # 模式2：hash + 运算结果
            zz=$((RANDOM % 1000 + 1))
            factor=$((RANDOM % 10 + 2))
            printf '%s\x01%s' \
                "_zz=\$(( $zz * $factor )); _ck=\$(printf '%s%d' \"\$_ck\" \"\$_zz\" | sha256sum | cut -c1-16)" \
                "$(printf '%s%d' "$current_key" "$((zz * factor))" | sha256sum | cut -c1-16)"
            ;;
        3)
            # 模式3：双重 hash
            temp=$(printf '%s' "$current_key" | sha256sum | cut -c1-16)
            printf '%s\x01%s' \
                '_ck=$(printf "%s" "$_ck" | sha256sum | cut -c1-16); _ck=$(printf "%s" "$_ck" | sha256sum | cut -c1-16)' \
                "$(printf '%s' "$temp" | sha256sum | cut -c1-16)"
            ;;
        4)
            # 模式4：hash + 反转 key（用 awk 替代 rev）
            temp=$(printf '%s' "$current_key" | awk '{for(i=length;i>0;i--)printf "%s",substr($0,i,1)}')
            printf '%s\x01%s' \
                '_zz=$(printf "%s" "$_ck" | awk '\''{for(i=length;i>0;i--)printf "%s",substr($0,i,1)}'\''); _ck=$(printf "%s%s" "$_ck" "$_zz" | sha256sum | cut -c1-16)' \
                "$(printf '%s%s' "$current_key" "$temp" | sha256sum | cut -c1-16)"
            ;;
    esac
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
    local current_s="$1" di="$2" rt="$3" rt_name="$4" s_in="$5" s_out="$6"
    local nvars=$((RANDOM % 2 + 2))
    local var_decls=""
    local all_items=()
    local i vname

    all_items+=("$s_in|%s|$current_s")
    all_items+=("_di|%d|$di")
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
                var_decls+="$vname=\$((_di * $factor + $offset)); "
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
        code="${var_decls}${s_out}=\$(printf \"$fmt\" $args| sha256sum | cut -c1-8); ${s_out}=\$(printf \"%s\" \"\${${s_out}}\" | sha256sum | cut -c1-8)"
    else
        code="${var_decls}${s_out}=\$(printf \"$fmt\" $args| sha256sum | cut -c1-8)"
    fi

    local new_s
    new_s=$(eval "${s_in}='$current_s'; _di=$di; ${rt_name}='$rt'; $code; printf '%s' \"\${${s_out}}\"")

    printf '%s\x01%s' "$code" "$new_s"
}

#==============================================================================
# _ck 密钥派生：同样随机生成唯一表达式
#==============================================================================

gen_ck_derivation_with_s() {
    # 多态化：s_name 由调用方传入（= 该块 s_out 名），内部临时变量随机命名
    # _ck 保持契约名（解释器用它作数据密钥），不可随机
    local current_ck="$1" new_s="$2" di="$3" s_name="$4"
    local nvars=$((RANDOM % 2 + 1))
    local var_decls=""
    local all_items=()
    local i vname

    all_items+=("_ck|%s|$current_ck")
    all_items+=("$s_name|%s|$new_s")
    all_items+=("_di|%d|$di")

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
                var_decls+="$vname=\$((_di * $factor)); "
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
        code="${var_decls}_ck=\$(printf \"$fmt\" $args| sha256sum | cut -c1-16); _ck=\$(printf \"%s\" \"\$_ck\" | sha256sum | cut -c1-16)"
    else
        code="${var_decls}_ck=\$(printf \"$fmt\" $args| sha256sum | cut -c1-16)"
    fi

    local new_ck
    new_ck=$(eval "_ck='$current_ck'; ${s_name}='$new_s'; _di=$di; $code; printf '%s' \"\$_ck\"")

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

# 模拟解释器 _am() 的密钥推进：RS 状态机推进 → 重播种 → 消费2次 → sha256 掺入
# 与运行时 _am() 逐比特一致（毒化分支在正常环境不触发，无需模拟）
# 结果写入 NEW_MK；调用方式: sim_advance_mk "$key" "$pos"; key=$NEW_MK
sim_advance_mk() {
    local ra rb
    VM_RS=$(( (VM_RS * 1103515245 + 12345) & 0x7fffffff ))
    sim_random_reset "$VM_RS"
    sim_random_next; ra=$SR_OUT
    sim_random_next; rb=$SR_OUT
    NEW_MK=$(printf '%s%d%d%d' "$1" "$2" "$ra" "$rb" | sha256sum | cut -c1-16)
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
            _dv|_hb) continue ;;
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
# 注意：与数据块共享的契约变量 _mk/_ck/_c/_d/_s/_di 保持不变（数据块生成
#       代码引用了它们），仅随机化解释器私有变量，保证正确性。
#==============================================================================

gen_randomized_interpreter() {
    local tlimit="${1:-120000000}"
    local I_DEC I_ENC V_DA V_KE V_KB V_R V_I V_J V_B
    local V_ENC V_HX V_BYT V_PC V_N V_INST V_CODE V_OK V_PT
    local V_AM V_RA V_RB V_PM V_NW V_T0 V_PP V_T V_MD
    I_DEC="$(gen_rand_var)"; I_ENC="$(gen_rand_var)"
    V_DA="$(gen_rand_var)"; V_KE="$(gen_rand_var)"; V_KB="$(gen_rand_var)"
    V_R="$(gen_rand_var)"; V_I="$(gen_rand_var)"; V_J="$(gen_rand_var)"; V_B="$(gen_rand_var)"
    V_ENC="$(gen_rand_var)"; V_HX="$(gen_rand_var)"; V_BYT="$(gen_rand_var)"
    V_PC="$(gen_rand_var)"; V_N="$(gen_rand_var)"; V_INST="$(gen_rand_var)"; V_CODE="$(gen_rand_var)"
    V_OK="$(gen_rand_var)"; V_PT="$(gen_rand_var)"
    V_AM="$(gen_rand_var)"; V_RA="$(gen_rand_var)"; V_RB="$(gen_rand_var)"; V_PM="$(gen_rand_var)"
    V_NW="$(gen_rand_var)"; V_T0="$(gen_rand_var)"; V_PP="$(gen_rand_var)"; V_T="$(gen_rand_var)"
    V_MD="$(gen_rand_var)"

    local ctrl=$((RANDOM % 2))
    local interp
    if [ "$ctrl" -eq 0 ]; then
        interp=$(cat <<'I_EOF'
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
    _mk=$(printf '%s%d%d%d' "$_mk" "$_p" "$_ra" "$_rb" | sha256sum | cut -c1-16)
    return 0
}
_t0=${EPOCHREALTIME:-0}
_t0=${_t0//.}
_p=0
_n=${#_c[@]}
while [ "$_p" -lt "$_n" ]; do
    _inst=$(_f "${_c[$_p]}" "$_mk" "$(( _p % 4 ))")
    case "$_inst" in
        EXEC:*)
            _t="${_inst#EXEC:}"
            _md="${_t##*:}"
            _t="${_t%:*}"
            _pp="${_t##*:}"
            _di="${_t%:*}"
            _code=$(_f "${_d[$_di]}" "$_ck" "$_md")
            case "$_pp" in
                0) builtin eval "$_code" ;;
                1) builtin source /dev/fd/9 9<<< "$_code" ;;
                *) builtin source <(printf '%s' "$_code") ;;
            esac
            unset _code
            _am
            _c[$_p]=$(_e "$_inst" "$_mk" "$(( _p % 4 ))")
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
                _code=$(_f "${_d[$_di]}" "$_ck" "$_md")
                case "$_pp" in
                    0) builtin eval "$_code" ;;
                    1) builtin source /dev/fd/9 9<<< "$_code" ;;
                    *) builtin source <(printf '%s' "$_code") ;;
                esac
                unset _code
            fi
            _am
            _c[$_p]=$(_e "$_inst" "$_mk" "$(( _p % 4 ))")
            ;;
        NOP)
            _am
            _c[$_p]=$(_e "$_inst" "$_mk" "$(( _p % 4 ))")
            ;;
        HALT)
            break
            ;;
        *)
            ;;
    esac
    unset _inst
    # 赋值形式恒返回 0：((_p++)) 在 _p=0 时算术值为 0 → 返回码 1，
    # 会被用户脚本的 set -e 误杀（首块即 set -e 时必死，rc=1 无输出）
    _p=$((_p + 1))
done
unset _mk _ck _p _n _s _di _rt _sa _sb _sc _sd _zz _zy _zv _rs _ra _rb _pm _nw _t0 _ok _pt _pp _t _md 2>/dev/null
I_EOF
)
    else
        interp=$(cat <<'I2_EOF'
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
    _mk=$(printf '%s%d%d%d' "$_mk" "$_p" "$_ra" "$_rb" | sha256sum | cut -c1-16)
    return 0
}
_t0=${EPOCHREALTIME:-0}
_t0=${_t0//.}
_p=0
_n=${#_c[@]}
while [ "$_p" -lt "$_n" ]; do
    _inst=$(_f "${_c[$_p]}" "$_mk" "$(( _p % 4 ))")
    if [ "${_inst#EXEC:}" != "$_inst" ]; then
        _t="${_inst#EXEC:}"
        _md="${_t##*:}"
        _t="${_t%:*}"
        _pp="${_t##*:}"
        _di="${_t%:*}"
        _code=$(_f "${_d[$_di]}" "$_ck" "$_md")
        case "$_pp" in
            0) builtin eval "$_code" ;;
            1) builtin source /dev/fd/9 9<<< "$_code" ;;
            *) builtin source <(printf '%s' "$_code") ;;
        esac
        unset _code
        _am
        _c[$_p]=$(_e "$_inst" "$_mk" "$(( _p % 4 ))")
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
            _code=$(_f "${_d[$_di]}" "$_ck" "$_md")
            case "$_pp" in
                0) builtin eval "$_code" ;;
                1) builtin source /dev/fd/9 9<<< "$_code" ;;
                *) builtin source <(printf '%s' "$_code") ;;
            esac
            unset _code
        fi
        _am
        _c[$_p]=$(_e "$_inst" "$_mk" "$(( _p % 4 ))")
    elif [ "$_inst" = "NOP" ]; then
        _am
        _c[$_p]=$(_e "$_inst" "$_mk" "$(( _p % 4 ))")
    elif [ "$_inst" = "HALT" ]; then
        break
    fi
    unset _inst
    _p=$((_p + 1))
done
unset _mk _ck _p _n _s _di _rt _sa _sb _sc _sd _zz _zy _zv _rs _ra _rb _pm _nw _t0 _ok _pt _pp _t _md 2>/dev/null
I2_EOF
)
    fi

    # 随机重命名解释器私有变量（\b 防止部分匹配，awk 内部无下划线 token 不受影响）
    # 注意：_rs 是契约变量（输出区赋初值 _rs=N），不参与改名
    interp=$(printf '%s' "$interp" | sed \
        -e "s/_f\b/${I_DEC}/g" \
        -e "s/_e\b/${I_ENC}/g" \
        -e "s/_da\b/${V_DA}/g" \
        -e "s/_ke\b/${V_KE}/g" \
        -e "s/_kb\b/${V_KB}/g" \
        -e "s/_r\b/${V_R}/g" \
        -e "s/_i\b/${V_I}/g" \
        -e "s/_j\b/${V_J}/g" \
        -e "s/_b\b/${V_B}/g" \
        -e "s/_encoded\b/${V_ENC}/g" \
        -e "s/_hexdata\b/${V_HX}/g" \
        -e "s/_bytes\b/${V_BYT}/g" \
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
        -e "s/_n\b/${V_N}/g" \
        -e "s/_inst\b/${V_INST}/g" \
        -e "s/_code\b/${V_CODE}/g" \
        -e "s/_ok\b/${V_OK}/g" \
        -e "s/_pt\b/${V_PT}/g" \
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

    # 解释器提前到此处生成：指令流初值密钥要掺解释器明文哈希（IH）。
    # 运行时 bootstrap 在 eval 前对解密出的解释器文本算同一哈希掺入 _mk：
    #   攻击者往解密后的解释器里插 tee 日志 → IH 变 → 全链静默报废；
    #   且 IH 期望值深埋在指令密文里 —— 他环境不符时连解释器明文都拿不到，
    #   想硬编码 IH 必须先伪造全部 5 项指纹解开解释器，成本叠加一个量级
    # tlimit 按块数估算（指令数 ≤ 2×块数，原公式按指令数，此处略放宽无害）
    local tlimit=$(( count * 8000000 + 30000000 ))
    VM_INTERP_TEXT="$(gen_randomized_interpreter "$tlimit")"
    # 剥尾换行：与运行期 _D=$(...) 命令替换的剥尾行为精确对齐（否则哈希分叉）
    VM_INTERP_HASH=$(printf '%s' "${VM_INTERP_TEXT%$'\n'}" | sha256sum | cut -c1-16)

    # 功能3：密钥掺入 bash 运行时变量（$- / BASH_VERSINFO）
    # 运行时公式（输出脚本内）: sha256(SEED + FP + DV + IH + "$-" + VERSINFO[0] + 6)
    # 非真 bash（zsh/python 模拟器假设错）、环境指纹不符或非绑定设备
    # → 密钥直接错误，一步都解不开，且无任何报错提示错在哪
    local key_seed
    key_seed=$(gen_rand 16)
    VM_KEY_SEED="$key_seed"
    key=$(printf '%s%s%s%s%s%d%d' "$key_seed" "$VM_PLATFORM_FP" "$VM_DEVICE_ID" "$VM_INTERP_HASH" "hB" "$TARGET_BASH_MAJOR" 6 | sha256sum | cut -c1-16)

    # 功能1：$RANDOM 状态机初始种子（解释器 _am 每条指令前用它重播种）
    VM_RS=$(( (RANDOM * 32768 + RANDOM) & 0x7fffffff ))
    VM_INITIAL_RS="$VM_RS"

    VM_INITIAL_KEY="$key"
    VM_INSTRUCTIONS=()
    VM_DATA=()

    local -a DETS=(
        '[[ $- == *x* ]] && exit 1; [ -n "${LD_PRELOAD:-}" ] && exit 1; [ -z "$(declare -f eval 2>/dev/null)" ] || exit 1'
        'if [ -r /proc/self/status ]; then _zv=$(grep "^TracerPid:" /proc/self/status 2>/dev/null | tr -dc "0-9"); [ "${_zv:-0}" != "0" ] && exit 1; fi'
        'if [ -r /proc/$PPID/cmdline ] 2>/dev/null; then _zv=$(tr "\0" " " < /proc/$PPID/cmdline 2>/dev/null); case "$_zv" in *strace*|*ltrace*|*gdb*|*ptrace*|*dbserver*) exit 1 ;; esac; fi'
        '[ -x "$_B64" ] || exit 1; [ -x "$_SH256" ] || exit 1'
        '[[ $- == *x* ]] && exit 1; [ -n "${LD_PRELOAD:-}" ] && exit 1'
        'if [ -r /proc/self/status ]; then _zv=$(grep "^TracerPid:" /proc/self/status 2>/dev/null | tr -dc "0-9"); [ "${_zv:-0}" != "0" ] && exit 1; fi; if [ -r /proc/$PPID/cmdline ] 2>/dev/null; then _zv=$(tr "\0" " " < /proc/$PPID/cmdline 2>/dev/null); case "$_zv" in *strace*|*ltrace*|*gdb*) exit 1 ;; esac; fi'
    )

    # 初始化 _s
    local s
    s=$(gen_rand 8)
    VM_INITIAL_S="$s"

    local integ_code='[ -f "$0" ] && { _zv=$(sed '\''s/_d\[0\]="[^"]*"/_d[0]="X"/'\'' "$0" | sha256sum | cut -c1-16); [ "$_zv" = "@@INTEGRITY_HASH@@" ] || exit 1; }'

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
        VM_DATA[$i]=$(encrypt_block "$wrapped" "$data_key" "$dmode")

        s="$new_s"
        s_cur="$s_next"
        data_key="$new_ck"
    done

    # 诱饵块：染大文件体积与 AI 分析上下文，运行时零开销
    local decoy_level="${DECOY_LEVEL:-0}"
    if [ "$decoy_level" -ge 1 ]; then
        local dc dc_total dc_det dc_wrapped dc_enc
        dc_total=$(( ${#VM_DATA[@]} * decoy_level ))
        for ((dc = 0; dc < dc_total; dc++)); do
            dc_det="${DETS[$((RANDOM % ${#DETS[@]}))]}"
            dc_wrapped=$(gen_decoy_wrapped "$data_key" "$dc_det" "$((1000 + dc))")
            dc_enc=$(encrypt_block "$dc_wrapped" "$data_key" "$((RANDOM % 4))")
            VM_DATA+=("$dc_enc")
            # 链式推进密钥（仅外观，诱饵永不执行，不影响真实 _ck 链）
            data_key=$(printf '%s%d' "$data_key" "$dc" | sha256sum | cut -c1-16)
        done
        echo "信息：注入 $dc_total 个诱饵数据块（DECOY_LEVEL=$decoy_level）" >&2
    fi

    # 编译指令：真实块随机 EXEC/CEXEC(恒真)，诱饵块 CEXEC(恒假)，随机 NOP 散布
    # 功能1：每条指令的 key 推进掺入 $RANDOM 状态机（sim_advance_mk 与运行时 _am 一致）
    # 功能2：EXEC/CEXEC 带 path 字段（0=eval 1=fd here-string 2=process-sub），拆散单点
    state=$(( RANDOM * RANDOM + $$ ))
    local pos=0
    local inst_target

    # 真实块指令
    for ((i = 0; i < count; i++)); do
        state=$(( (state * 1103515245 + 12345) & 0x7fffffff ))
        pattern=$((state % 3))

        # 随机选择 EXEC 或 CEXEC(恒真谓词 0-3)，均带随机执行路径 + 数据块解密原语
        # 指令格式：EXEC:块:路径:原语 / CEXEC:块:路径:原语:谓词
        if [ $((RANDOM % 2)) -eq 1 ]; then
            inst_target="CEXEC:$i:$((RANDOM % 3)):${VM_DMODES[$i]}:$(gen_opaque_pred true)"
        else
            inst_target="EXEC:$i:$((RANDOM % 3)):${VM_DMODES[$i]}"
        fi

        case $pattern in
            0)
                encrypted=$(encrypt_block "$inst_target" "$key" "$((pos % 4))")
                VM_INSTRUCTIONS+=("$encrypted")
                sim_advance_mk "$key" "$pos"; key=$NEW_MK; ((pos++))
                ;;
            1)
                encrypted=$(encrypt_block "NOP" "$key" "$((pos % 4))")
                VM_INSTRUCTIONS+=("$encrypted")
                sim_advance_mk "$key" "$pos"; key=$NEW_MK; ((pos++))

                encrypted=$(encrypt_block "$inst_target" "$key" "$((pos % 4))")
                VM_INSTRUCTIONS+=("$encrypted")
                sim_advance_mk "$key" "$pos"; key=$NEW_MK; ((pos++))
                ;;
            2)
                encrypted=$(encrypt_block "$inst_target" "$key" "$((pos % 4))")
                VM_INSTRUCTIONS+=("$encrypted")
                sim_advance_mk "$key" "$pos"; key=$NEW_MK; ((pos++))

                encrypted=$(encrypt_block "NOP" "$key" "$((pos % 4))")
                VM_INSTRUCTIONS+=("$encrypted")
                sim_advance_mk "$key" "$pos"; key=$NEW_MK; ((pos++))
                ;;
        esac
    done

    # 诱饵块指令：CEXEC(恒假谓词 4-7)，运行时跳过 eval → 数据零开销。
    # 每个诱饵块只生成 1 条指令（不散布 NOP），把指令解密成本降到最低。
    if [ "$decoy_level" -ge 1 ]; then
        local dci
        for ((dci = 0; dci < dc_total; dci++)); do
            inst_target="CEXEC:$((count + dci)):$((RANDOM % 3)):$((RANDOM % 4)):$(gen_opaque_pred false)"
            encrypted=$(encrypt_block "$inst_target" "$key" "$((pos % 4))")
            VM_INSTRUCTIONS+=("$encrypted")
            sim_advance_mk "$key" "$pos"; key=$NEW_MK; ((pos++))
        done
    fi

    encrypted=$(encrypt_block "HALT" "$key" "$((pos % 4))")
    VM_INSTRUCTIONS+=("$encrypted")

    echo "信息：V5编译完成，$count 数据块（执行依赖密钥），${#VM_INSTRUCTIONS[@]} 条指令" >&2
}

#==============================================================================
# 输出脚本生成器（检测代码已注入数据块，输出不含明文检测逻辑）
#==============================================================================

generate_output_with_e() {
    local output="$1"
    local timestamp i
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    {
        echo "#!/usr/bin/env bash haothtrteen 2026.8.27"
        echo "# Generated: $timestamp"
        echo ""

        # ===== 路径绑定（_f/_e 需要 base64/sha256sum，必须明文）=====
        echo '_B64=$(command -v base64 2>/dev/null || echo base64)'
        echo '_SH256=$(command -v sha256sum 2>/dev/null || echo sha256sum)'
        echo '_PRF=$(command -v printf 2>/dev/null || echo printf)'
        echo ""

        # ===== 十六进制查找表（_f/_e 依赖）=====
        printf '_h=('
        for ((i = 0; i < 256; i++)); do
            printf '%02x' "$i"
            [ $i -lt 255 ] && printf ' '
        done
        echo ')'
        echo ""

        # ===== 解密 + 加密函数（VM 基础设施，必须明文）=====
        cat << 'CRYPTO_EOF'
_f() {
    local _r="" _i _j _b _kb
    local _da="$1" _ke="$2"
    for ((_i=0; _i<${#_da}; _i+=2)); do
        _b=$((16#${_da:_i:2}))
        _j=$((_i/2 % ${#_ke}))
        _kb=$(printf '%d' "'${_ke:_j:1}")
        _r+="\\x${_h[$(((_b - _kb + 256) % 256))]}"
    done
    printf "$_r" | base64 -d
}

_e() {
    local _encoded _hexdata _r="" _i _j _b _kb
    local _da="$1" _ke="$2"
    _encoded=$(printf '%s' "$_da" | base64 -w0 2>/dev/null || printf '%s' "$_da" | base64 | tr -d '\n')
    _hexdata=$(printf '%s' "$_encoded" | od -An -tx1 -v | tr -d ' \n')
    for ((_i=0; _i<${#_hexdata}; _i+=2)); do
        _b=$((16#${_hexdata:_i:2}))
        _j=$((_i/2 % ${#_ke}))
        _kb=$(printf '%d' "'${_ke:_j:1}")
        _r+=$(printf '%02x' $(((_b + _kb) % 256)))
    done
    printf '%s' "$_r"
}
CRYPTO_EOF
        echo ""

        # ===== 加密指令表 =====
        echo "declare -a _c"
        for ((i = 0; i < ${#VM_INSTRUCTIONS[@]}; i++)); do
            echo "_c[$i]=\"${VM_INSTRUCTIONS[$i]}\""
        done
        echo ""

        # ===== 加密数据表（含注入的检测代码，全部密文）=====
        echo "declare -a _d"
        for ((i = 0; i < ${#VM_DATA[@]}; i++)); do
            echo "_d[$i]=\"${VM_DATA[$i]}\""
        done
        echo ""

        # ===== 初始密钥 =====
        echo "_mk=\"$VM_INITIAL_KEY\""
        echo "_ck=\"$VM_INITIAL_KEY\""
        echo ""

        # ===== VM 解释器（极简：只有 EXEC/NOP/HALT，不泄露检测逻辑）=====
        cat << 'VM_EOF'
_p=0
_n=${#_c[@]}

while [ "$_p" -lt "$_n" ]; do
    _inst=$(_f "${_c[$_p]}" "$_mk")

    case "$_inst" in
        EXEC:*)
            _di="${_inst#EXEC:}"
            _code=$(_f "${_d[$_di]}" "$_ck")
            builtin eval "$_code"
            unset _code
            _mk=$(printf '%s%d' "$_mk" "$_p" | sha256sum | cut -c1-16)
            _c[$_p]=$(_e "$_inst" "$_mk")
            ;;
        NOP)
            _mk=$(printf '%s%d' "$_mk" "$_p" | sha256sum | cut -c1-16)
            _c[$_p]=$(_e "$_inst" "$_mk")
            ;;
        HALT)
            break
            ;;
        *)
            ;;
    esac

    unset _inst
    ((_p++))
done

unset _mk _ck _p _n 2>/dev/null
VM_EOF

    } > "$output"
    chmod +x "$output"
}

#==============================================================================
# V6 输出生成器：VM 解释器整体加密
#
# 输出脚本结构：
#   1. 路径绑定、hex 表（基础设施，必须明文）
#   2. 加密指令表 _c、加密数据表 _d（密文）
#   3. 初始密钥 _mk、_ck
#   4. 加密的 VM 解释器 _I（XOR 加密，含 _f/_e/while 循环，全部密文）
#   5. 极简 bootstrap（内联 XOR 解密 + eval，无函数定义）
#
# 攻击者面临的挑战：
#   步骤1：阅读 bootstrap，理解 XOR 解密算法
#   步骤2：理解密钥派生（从 _c 数组拼接后 sha256）
#   步骤3：解密 VM 解释器，获得 _f/_e 函数
#   步骤4：阅读 _f，理解 Vigenère 减法解密算法
#   步骤5：模拟 _mk 密钥链（sha256(key+pos)）
#   步骤6：逐块解密 _d，每块的 _ck 派生模式不同，必须逐块分析
#==============================================================================

generate_output_v6() {
    local output="$1"
    local timestamp i
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # 解释器已在 compile_v5 提前生成（指令流初值密钥需掺其明文哈希 IH）
    local interpreter="$VM_INTERP_TEXT"

    # 计算解释器密钥：从 _c 数组值拼接后 sha256（非显而易见）
    # 功能3：掺入 bash 运行时变量（$-/BASH_VERSINFO），与 bootstrap 内公式一致
    # 掺入平台指纹 + 设备熵：环境不符/非绑定设备时连解释器都解不开 ——
    # 攻击者在服务器重放时第一步就得到乱码，且没有任何报错提示错在哪
    local all_c=""
    for ((i = 0; i < ${#VM_INSTRUCTIONS[@]}; i++)); do
        all_c+="${VM_INSTRUCTIONS[$i]}"
    done
    local interp_key
    interp_key=$(printf '%s%s%s%s%d%d' "$all_c" "$VM_PLATFORM_FP" "$VM_DEVICE_ID" "hB" "$TARGET_BASH_MAJOR" 6 | sha256sum | cut -c1-16)

    # XOR 加密 VM 解释器
    local encrypted_interp
    encrypted_interp=$(xor_encrypt_block "$interpreter" "$interp_key")

    {
        echo "#!/usr/bin/env bash"
        echo "# Generated: $timestamp"
        echo ""

        # 路径绑定
        echo '_B64=$(command -v base64 2>/dev/null || echo base64)'
        echo '_SH256=$(command -v sha256sum 2>/dev/null || echo sha256sum)'
        echo '_PRF=$(command -v printf 2>/dev/null || echo printf)'
        echo ""

        # Hex 表（bootstrap 和解释器都依赖）
        printf '_h=('
        for ((i = 0; i < 256; i++)); do
            printf '%02x' "$i"
            [ $i -lt 255 ] && printf ' '
        done
        echo ')'
        echo ""

        # 加密指令表
        echo "declare -a _c"
        for ((i = 0; i < ${#VM_INSTRUCTIONS[@]}; i++)); do
            echo "_c[$i]=\"${VM_INSTRUCTIONS[$i]}\""
        done
        echo ""

        # 加密数据表
        echo "declare -a _d"
        for ((i = 0; i < ${#VM_DATA[@]}; i++)); do
            echo "_d[$i]=\"${VM_DATA[$i]}\""
        done
        echo ""

        # 执行状态变量（_mk/_ck 在下方 bootstrap 内生成：依赖运行期指纹与 IH）
        # 功能1：_rs 是 $RANDOM 状态机种子，解释器 _am() 每条指令前用它重播种
        # 多态化：s 链首变量名每次生成随机（VM_S0_NAME），块内链式传递
        # _hb：设备绑定标志（1=启用 HOST_BIND；值本身无秘密，秘密在设备熵里）
        echo "_rs=$VM_INITIAL_RS"
        echo "$VM_S0_NAME=\"$VM_INITIAL_S\""
        echo "_hb=${HOST_BIND:-0}"
        echo ""

        # 加密的 VM 解释器（XOR 密文）
        echo "_I=\"$encrypted_interp\""
        echo ""

        # 极简 bootstrap（三段式，无函数定义，变量名不冲突）：
        #   段1 平台指纹采集（与编译期 collect_platform_entropy 同公式）
        #      + 设备熵采集（_hb=1 时，与 collect_device_entropy 同公式）
        #      + 指令拼接 + 解释器密钥（掺指纹/设备熵）+ XOR 解密 + IH 计算
        #   段2 初始密钥 _mk（掺指纹 + 设备熵 + IH，与编译期公式逐比特一致）
        #   段3 eval 解释器 + 清理
        cat << 'BOOTSTRAP_EOF'
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
_a=""
for ((_bi=0; _bi<${#_c[@]}; _bi++)); do _a+="${_c[$_bi]}"; done
_k=$(printf '%s%s%s%s%d%d' "$_a" "$_fp" "$_dv" "$-" "${BASH_VERSINFO[0]}" "${#BASH_VERSINFO[@]}" | sha256sum | cut -c1-16)
_r=""
for ((_bi=0; _bi<${#_I}; _bi+=2)); do
    _bb=$((16#${_I:_bi:2}))
    _bj=$((_bi/2 % ${#_k}))
    _bk=$(printf '%d' "'${_k:_bj:1}")
    _r+="\\x${_h[$((_bb ^ _bk))]}"
done
_D=$(printf "$_r" | base64 -d)
_iH=$(printf '%s' "$_D" | sha256sum | cut -c1-16)
BOOTSTRAP_EOF
        # 初始密钥：掺平台指纹 + 设备熵 + 解释器明文哈希 IH
        # （环境不符/非绑定设备/解释器被篡改 → 密钥错 → 全链解出乱码，
        #   静默失败不暴露错在哪一步）
        echo "_mk=\$(printf '%s%s%s%s%s%d%d' '$VM_KEY_SEED' \"\$_fp\" \"\$_dv\" \"\$_iH\" \"\$-\" \"\${BASH_VERSINFO[0]}\" \"\${#BASH_VERSINFO[@]}\" | sha256sum | cut -c1-16)"
        echo "_ck=\$_mk"
        cat << 'BOOTSTRAP_EOF'
eval "$_D"
unset _a _k _r _I _D _iH _bi _bb _bj _bk _m _f1 _f2 _f3 _f4 _f5 _v _fp _dv _hb 2>/dev/null
BOOTSTRAP_EOF

    } > "$output"
    chmod +x "$output"
}
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

    # 计算真实 hash：把 _d[0]="..." 归一化为 _d[0]="X" 后做 sha256
    hash=$(sed 's/_d\[0\]="[^"]*"/_d[0]="X"/' "$file" | sha256sum | cut -c1-16)

    # 替换占位符为真实 hash
    d0_real="${VM_D0_PLAINTEXT/@@INTEGRITY_HASH@@/$hash}"

    # 重新加密 _d[0]（使用初始数据密钥 + d0 的多态原语 mode）
    encrypted_d0=$(encrypt_block "$d0_real" "$VM_INITIAL_KEY" "${VM_DMODES[0]}")

    # 更新输出文件中的 _d[0]
    # 用 awk 替换（比 sed 更可靠地处理长 hex 字符串，且不依赖 perl）
    awk -v nv="$encrypted_d0" '{gsub(/_d\[0\]="[^"]*"/, "_d[0]=\"" nv "\"")} 1' "$file" > "$file.tmp"
    mv "$file.tmp" "$file"
    chmod +x "$file"

    # 验证：重新计算 hash 确认一致
    local verify_hash
    verify_hash=$(sed 's/_d\[0\]="[^"]*"/_d[0]="X"/' "$file" | sha256sum | cut -c1-16)
    if [ "$verify_hash" != "$hash" ]; then
        echo "警告：完整性 hash 验证失败（$hash vs $verify_hash）" >&2
        return 1
    fi

    echo "信息：已注入完整性校验 hash（$hash）" >&2
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

    generate_output_v6 "$output_script"

    compact_output_file "$output_script"

    inject_integrity_hash "$output_script"

    echo "成功：已生成 V5 混淆脚本 '$output_script'"
}

#==============================================================================
# 主程序入口
#==============================================================================

main() {
    if [[ $# -lt 1 ]]; then
        echo "用法: $0 <input_script.sh> [output_script.sh]"
        echo ""
        echo "V5 特性：VM内嵌检测 + 绝对路径绑定 + eval网关 + 自修改VM"
        echo "环境变量：JUNK_LEVEL=N   每个真实块后注入 N 个真执行垃圾块（默认 0）"
        echo "          DECOY_LEVEL=N 注入 N×真实块数的死诱饵块（默认 0）"
        echo "          ANDROID_GATE=0 关闭安卓环境门控（默认 1）"
        return 1
    fi

    local input_file="$1"
    local output_file="${2:-${input_file%.sh}_v5.sh}"

    obfuscate_script "$input_file" "$output_file"
    return $?
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi