#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md

# shell_script_obfuscator_v2.sh - 增强版 Shell 脚本混淆器
#
# 实现特性：
#   1. 多操作码真虚拟机 (LOAD/EXEC/STATE/CHK/JNZ/JZ/JMP/POP/NOP/HALT)
#   2. LCG 状态机驱动的不透明谓词（真假路径交织）
#   3. Base64 + 加法加密的数据保护（避免空字节问题）
#   4. 反调试检测（TracerPid / 父进程 / 时序）
#   5. 基于语法完整性的代码块拆分（bash -n）

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

gen_seed() {
    printf '%d' $((RANDOM * RANDOM * RANDOM + $$ + SECONDS))
}

#==============================================================================
# 代码块拆分器：使用 bash -n 检测语法完整性
#==============================================================================

split_into_blocks() {
    # 输出以 null 字节分隔的块，保留多行块完整性
    # bash -n 对未终止的 heredoc 仍返回 0，需额外检查 stderr
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

        # 语法错误或未终止 heredoc → 继续累积
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
    hexdata=$(printf '%s' "$encoded" | od -An -tx1 | tr -d ' \n')
    for ((i = 0; i < ${#hexdata}; i += 2)); do
        sc=$((16#${hexdata:$i:2}))
        j=$(((i / 2) % ${#key}))
        kc=$(printf '%d' "'${key:$j:1}")
        result+=$(printf '%02x' $(((sc + kc) % 256)))
    done
    printf '%s' "$result"
}

#==============================================================================
# VM 字节码编译器
#==============================================================================

declare -a BC
BC_PC=0

bc_emit() {
    BC[$BC_PC]="$1"
    ((BC_PC++))
}

compile_bytecode() {
    local real_count="$1" fake_count="$2" seed="$3" level="$4"
    local state="$seed" i pattern mod expected fake_idx

    BC=()
    BC_PC=0

    for ((i = 0; i < real_count; i++)); do
        state=$(((state * 1103515245 + 12345) & 0x7fffffff))

        if [ "$level" -eq 1 ]; then
            bc_emit "LOAD"
            bc_emit "$i"
            bc_emit "EXEC"
        elif [ "$level" -eq 2 ]; then
            pattern=$((state % 2))
            case $pattern in
                0)
                    bc_emit "NOP"
                    bc_emit "LOAD"
                    bc_emit "$i"
                    bc_emit "EXEC"
                    bc_emit "NOP"
                    ;;
                1)
                    mod=$((state % 997 + 100))
                    expected=1
                    bc_emit "STATE"
                    bc_emit "CHK"
                    bc_emit "$mod"
                    bc_emit "$expected"
                    bc_emit "JNZ"
                    local jnz_pos=$BC_PC
                    bc_emit "0"
                    bc_emit "LOAD"
                    bc_emit "$i"
                    bc_emit "EXEC"
                    bc_emit "JMP"
                    local jmp_pos=$BC_PC
                    bc_emit "0"
                    BC[$jnz_pos]=$BC_PC
                    fake_idx=$((real_count + (i % fake_count)))
                    bc_emit "LOAD"
                    bc_emit "$fake_idx"
                    bc_emit "EXEC"
                    BC[$jmp_pos]=$BC_PC
                    ;;
            esac
        else
            pattern=$((state % 4))
            case $pattern in
                0)
                    bc_emit "NOP"
                    bc_emit "NOP"
                    bc_emit "STATE"
                    bc_emit "LOAD"
                    bc_emit "$i"
                    bc_emit "EXEC"
                    bc_emit "NOP"
                    bc_emit "NOP"
                    ;;
                1)
                    mod=$((state % 997 + 100))
                    expected=1
                    bc_emit "STATE"
                    bc_emit "CHK"
                    bc_emit "$mod"
                    bc_emit "$expected"
                    bc_emit "JNZ"
                    local jnz_pos=$BC_PC
                    bc_emit "0"
                    bc_emit "LOAD"
                    bc_emit "$i"
                    bc_emit "EXEC"
                    bc_emit "JMP"
                    local jmp_pos=$BC_PC
                    bc_emit "0"
                    BC[$jnz_pos]=$BC_PC
                    fake_idx=$((real_count + (i % fake_count)))
                    bc_emit "LOAD"
                    bc_emit "$fake_idx"
                    bc_emit "EXEC"
                    bc_emit "NOP"
                    BC[$jmp_pos]=$BC_PC
                    ;;
                2)
                    mod=$((state % 997 + 100))
                    expected=0
                    bc_emit "STATE"
                    bc_emit "CHK"
                    bc_emit "$mod"
                    bc_emit "$expected"
                    bc_emit "JZ"
                    local jz_pos=$BC_PC
                    bc_emit "0"
                    fake_idx=$((real_count + (i % fake_count)))
                    bc_emit "LOAD"
                    bc_emit "$fake_idx"
                    bc_emit "EXEC"
                    bc_emit "JMP"
                    local jmp_pos2=$BC_PC
                    bc_emit "0"
                    BC[$jz_pos]=$BC_PC
                    bc_emit "LOAD"
                    bc_emit "$i"
                    bc_emit "EXEC"
                    BC[$jmp_pos2]=$BC_PC
                    ;;
                3)
                    bc_emit "NOP"
                    bc_emit "STATE"
                    bc_emit "CHK"
                    bc_emit "$((state % 900 + 200))"
                    bc_emit "0"
                    bc_emit "POP"
                    bc_emit "NOP"
                    bc_emit "LOAD"
                    bc_emit "$i"
                    bc_emit "EXEC"
                    bc_emit "NOP"
                    ;;
            esac
        fi
    done
    bc_emit "HALT"
}

#==============================================================================
# 输出脚本生成器
#==============================================================================

gen_anti_debug() {
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
}

generate_output() {
    local output="$1" key="$2" seed="$3" level="$4"
    local timestamp i
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    {
        echo "#!/usr/bin/env bash"
        echo "# Generated: $timestamp"
        echo "# Level: $level"
        echo ""

        if [ "$level" -ge 2 ]; then
            gen_anti_debug
            echo ""
        fi

        echo "# Hex lookup table"
        printf '_h=('
        for ((i = 0; i < 256; i++)); do
            printf '%02x' "$i"
            [ $i -lt 255 ] && printf ' '
        done
        echo ')'
        echo ""

        echo "_k=\"$key\""
        echo "_s=$seed"
        echo ""

        echo "# Data table"
        echo "declare -a _d"
        for ((i = 0; i < ${#ENCRYPTED_BLOCKS[@]}; i++)); do
            echo "_d[$i]=\"${ENCRYPTED_BLOCKS[$i]}\""
        done
        echo ""

        cat << 'DECRYPT_EOF'
_f() {
    local _r="" _i _j _b _kb
    for ((_i=0; _i<${#_d[$1]}; _i+=2)); do
        _b=$((16#${_d[$1]:_i:2}))
        _j=$((_i/2 % ${#_k}))
        _kb=$(printf '%d' "'${_k:_j:1}")
        _r+="\\x${_h[$(((_b - _kb + 256) % 256))]}"
    done
    printf "$_r" | base64 -d
}
DECRYPT_EOF
        echo ""

        echo "# VM state"
        echo "declare -a _c"
        echo "declare -a _t"
        echo "_p=0"
        echo "_u=-1"
        echo ""

        echo "# Bytecode"
        for ((i = 0; i < ${#BC[@]}; i++)); do
            echo "_c[$i]=\"${BC[$i]}\""
        done
        echo ""

        cat << 'VM_EOF'
_v() {
    local _v1 _v2 _v3
    while [ $_p -lt ${#_c[@]} ]; do
        case "${_c[$_p]}" in
            LOAD)
                ((_p++))
                ((_u++))
                _t[$_u]=$(_f "${_c[$_p]}")
                ;;
            EXEC)
                eval "${_t[$_u]}"
                ((_u--))
                ;;
            STATE)
                _s=$((_s * 1103515245 + 12345 & 0x7fffffff))
                ;;
            CHK)
                ((_p++))
                _v1="${_c[$_p]}"
                ((_p++))
                _v2="${_c[$_p]}"
                ((_u++))
                if [ $((_s % _v1)) -eq $_v2 ]; then
                    _t[$_u]=1
                else
                    _t[$_u]=0
                fi
                ;;
            JNZ)
                ((_p++))
                if [ "${_t[$_u]}" != "0" ]; then
                    _p="${_c[$_p]}"
                    ((_u--))
                    continue
                fi
                ((_u--))
                ;;
            JZ)
                ((_p++))
                if [ "${_t[$_u]}" = "0" ]; then
                    _p="${_c[$_p]}"
                    ((_u--))
                    continue
                fi
                ((_u--))
                ;;
            JMP)
                ((_p++))
                _p="${_c[$_p]}"
                continue
                ;;
            POP)
                ((_u--))
                ;;
            NOP)
                :
                ;;
            HALT)
                return 0
                ;;
            *)
                ((_p++))
                ;;
        esac
        ((_p++))
    done
}
_v "$@"
VM_EOF

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
    local -a real_blocks=()
    local block
    while IFS= read -r -d '' block || [ -n "$block" ]; do
        [ -n "$block" ] && real_blocks+=("$block")
    done < "$blocks_file"

    local real_count=${#real_blocks[@]}
    if [ "$real_count" -eq 0 ]; then
        echo "错误：输入脚本为空或无法解析。" >&2
        return 1
    fi

    echo "信息：拆分为 $real_count 个代码块" >&2

    # 生成密钥和种子
    local key seed
    key=$(gen_rand 16)
    seed=$(gen_seed)

    # 加密真实块
    declare -a ENCRYPTED_BLOCKS=()
    local i
    for ((i = 0; i < real_count; i++)); do
        ENCRYPTED_BLOCKS[$i]=$(encrypt_block "${real_blocks[$i]}" "$key")
    done

    # 生成虚假块（无害命令）
    local fake_count=4
    local fake_blocks=("true" ":" "true" ":")
    for ((i = 0; i < fake_count; i++)); do
        ENCRYPTED_BLOCKS[$((real_count + i))]=$(encrypt_block "${fake_blocks[$i]}" "$key")
    done

    # 编译字节码
    compile_bytecode "$real_count" "$fake_count" "$seed" "$OBFUSCATION_LEVEL"

    echo "信息：生成 ${#BC[@]} 条字节码" >&2

    # 生成输出
    generate_output "$output_script" "$key" "$seed" "$OBFUSCATION_LEVEL"

    echo "成功：已生成混淆脚本 '$output_script'"
}

#==============================================================================
# 主程序入口
#==============================================================================

main() {
    if [[ $# -lt 1 ]]; then
        echo "用法: $0 <input_script.sh> [output_script.sh]"
        echo "选项:"
        echo "  OBFUSCATION_LEVEL=1|2|3  设置混淆级别 (默认: 3)"
        return 1
    fi

    local input_file="$1"
    local output_file="${2:-${input_file%.sh}_obfuscated.sh}"

    obfuscate_script "$input_file" "$output_file"
    return $?
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi