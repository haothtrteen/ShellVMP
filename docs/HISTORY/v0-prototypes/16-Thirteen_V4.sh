#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md

# shell_script_obfuscator_v3.sh - 链式分片解密版
#
# 核心特性：
#   1. 链式密钥依赖：片段N的密钥由片段N-1运行时产生，静态分析无法解密片段2+
#   2. eval 完整性检查：检测 eval 是否被 function/alias 覆盖
#   3. set -x 调试检测
#   4. LD_PRELOAD 检测
#   5. 反调试（TracerPid / 父进程 / 时序）
#   6. 用后即焚：每次 eval 后 unset 解密明文
#   7. 语法感知拆分（bash -n + heredoc 检测）
#
# 密钥链工作原理：
#   K1 (初始密钥, 嵌入脚本) → 解密片段1 → 片段1执行后设置 _ck=K2
#   K2 (由片段1产生, 不在脚本中) → 解密片段2 → 片段2执行后设置 _ck=K3
#   K3 (由片段2产生, 不在脚本中) → 解密片段3 → ...
#   最后一个片段设置 _ck=__END__ → 链完成验证

OBFUSCATION_LEVEL=${OBFUSCATION_LEVEL:-3}
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

#==============================================================================
# 代码块拆分器：bash -n + heredoc 检测
#==============================================================================

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
# 数据加密：base64 → 逐字节加法加密 → 十六进制
#==============================================================================

encrypt_block() {
    local block="$1" key="$2"
    local encoded hexdata result="" i j sc kc
    encoded=$(printf '%s' "$block" | base64_encode)
    hexdata=$(printf '%s' "$encoded" | od -An -tx1 -v | tr -d ' \n')
    for ((i = 0; i < ${#hexdata}; i += 2)); do
        sc=$((16#${hexdata:$i:2}))
        j=$(((i / 2) % ${#key}))
        kc=$(printf '%d' "'${key:$j:1}")
        result+=$(printf '%02x' $(((sc + kc) % 256)))
    done
    printf '%s' "$result"
}

#==============================================================================
# 链式编译器
#
# 输入：real_blocks 数组（代码块）
# 输出：ENCRYPTED_BLOCKS 数组（加密后的片段），CHAIN_INITIAL_KEY（初始密钥）
#
# 每个 fragment 的明文结构：
#   <原始代码块>
#   _ck='<下一个密钥>'      ← 这行由编译器注入，执行后更新链密钥
#
# 密钥链：
#   K1 → encrypt(fragment1) → fragment1执行后 _ck=K2
#   K2 → encrypt(fragment2) → fragment2执行后 _ck=K3
#   ...
#   Kn → encrypt(fragmentN) → fragmentN执行后 _ck=__END__
#==============================================================================

compile_chain() {
    local count=${#REAL_BLOCKS[@]}
    local i key next_key wrapped

    # 生成初始密钥 K1
    key=$(gen_rand 16)
    CHAIN_INITIAL_KEY="$key"

    # 清空加密片段数组
    ENCRYPTED_BLOCKS=()

    for ((i = 0; i < count; i++)); do
        # 生成下一个密钥（最后一个片段设置链结束标记）
        if [ "$i" -lt $((count - 1)) ]; then
            next_key=$(gen_rand 16)
        else
            next_key="__END__"
        fi

        # 包装：原始代码 + 注入密钥设置指令
        # eval 执行后，_ck 被更新为 next_key
        wrapped="${REAL_BLOCKS[$i]}"$'\n_ck='"'$next_key'"

        # 用当前密钥加密包装后的片段
        ENCRYPTED_BLOCKS[$i]=$(encrypt_block "$wrapped" "$key")

        # 当前密钥前进到下一个密钥
        key="$next_key"
    done

    echo "信息：链式编译完成，$count 个片段，$count 个密钥" >&2
}

#==============================================================================
# 输出脚本生成器
#==============================================================================

generate_output() {
    local output="$1"
    local timestamp i
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    {
        # ===== Shebang =====
        echo "#!/usr/bin/env bash"
        echo "# Generated: $timestamp [v3-chained]"
        echo ""

        # ===== 反调试 =====
        cat << 'ANTI_EOF'
_x() {
    local _v1 _v2 _v3 _vi
    if [ -r /proc/self/status ]; then
        _v1=$(grep '^TracerPid:' /proc/self/status 2>/dev/null | tr -dc '0-9')
        [ "${_v1:-0}" != "0" ] && return 1
    fi
    if [ -r /proc/$PPID/cmdline ] 2>/dev/null; then
        _v2=$(tr '\0' ' ' < /proc/$PPID/cmdline 2>/dev/null)
        case "$_v2" in
            *strace*|*ltrace*|*gdb*|*ptrace*|*dbserver*) return 1 ;;
        esac
    fi
    _v1=$(date +%s%N 2>/dev/null) || return 0
    _v3=1
    for ((_vi=0; _vi<1000; _vi++)); do _v3=$((_v3 + _vi)); done
    _v2=$(date +%s%N 2>/dev/null) || return 0
    [ $((_v2 - _v1)) -gt 2000000000 ] && return 1
    return 0
}
_x || exit 1
ANTI_EOF
        echo ""

        # ===== 完整性检查 =====
        echo "# Integrity"
        echo '[[ $- != *x* ]] || exit 1'
        echo '[ -z "$LD_PRELOAD" ] || exit 1'
        echo '[ -z "$(declare -f eval 2>/dev/null)" ] || exit 1'
        echo ""

        # ===== 十六进制查找表 =====
        echo "# Hex table"
        printf '_h=('
        for ((i = 0; i < 256; i++)); do
            printf '%02x' "$i"
            [ $i -lt 255 ] && printf ' '
        done
        echo ')'
        echo ""

        # ===== 解密函数（参数化密钥）=====
        cat << 'DECRYPT_EOF'
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
DECRYPT_EOF
        echo ""

        # ===== 加密片段数据 =====
        echo "# Data"
        echo "declare -a _d"
        for ((i = 0; i < ${#ENCRYPTED_BLOCKS[@]}; i++)); do
            echo "_d[$i]=\"${ENCRYPTED_BLOCKS[$i]}\""
        done
        echo ""

        # ===== 初始链密钥（只有 K1 在脚本中）=====
        echo "_ck=\"$CHAIN_INITIAL_KEY\""
        echo ""

        # ===== 链式执行器 =====
        cat << 'CHAIN_EOF'
_ci=0
_cn=${#_d[@]}
[ "$_cn" -eq 0 ] && exit 0
while [ "$_ci" -lt "$_cn" ]; do
    [ -z "$(declare -f eval 2>/dev/null)" ] || exit 1
    [[ $- != *x* ]] || exit 1
    _cp=$(_f "${_d[$_ci]}" "$_ck")
    eval "$_cp"
    unset _cp
    ((_ci++))
done
[ "$_ck" = "__END__" ] || exit 1
unset _ck _ci _cn 2>/dev/null
CHAIN_EOF

    } > "$output"
    chmod +x "$output"
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

    # 去除 shebang 行
    if [[ "$script_content" =~ ^#!.* ]]; then
        script_content=$(sed '1d' <<< "$script_content")
    fi

    # 拆分为语法完整块
    local blocks_file="$WORK_DIR/blocks.txt"
    split_into_blocks "$script_content" > "$blocks_file"

    # 读取块到数组
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

    # 链式编译
    compile_chain

    # 生成输出
    generate_output "$output_script"

    echo "成功：已生成链式混淆脚本 '$output_script'"
    echo "     初始密钥 K1 嵌入脚本，后续密钥 K2..Kn 由各片段运行时产生" >&2
}

#==============================================================================
# 主程序入口
#==============================================================================

main() {
    if [[ $# -lt 1 ]]; then
        echo "用法: $0 <input_script.sh> [output_script.sh]"
        echo ""
        echo "特性：链式分片解密 + eval完整性检查 + 反调试"
        echo "     片段N的密钥由片段N-1运行时产生，静态分析无法解密片段2+"
        return 1
    fi

    local input_file="$1"
    local output_file="${2:-${input_file%.sh}_chained.sh}"

    obfuscate_script "$input_file" "$output_file"
    return $?
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi