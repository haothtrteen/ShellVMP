#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md

# shell_script_obfuscator_v4.sh - 自修改 VM 版
#
# 核心机制：
#   1. 字节码以加密形式存储在数组中，任何时候都是密文
#   2. VM 执行每条指令前 JIT 解密，执行后立即用新密钥重新加密
#   3. 变异密钥随执行状态演进，每条指令执行后密钥都变化
#   4. 静态 dump 数组只能看到密文，无法还原指令
#   5. 密钥派生依赖执行状态，不暴露明文密钥
#
# 自修改过程：
#   指令存储: _c[i] = encrypt(opcode, K_i)
#   执行时:   opcode = decrypt(_c[i], K_i) → eval → K_i 演进 → _c[i] = encrypt(opcode, K_i')
#   重新访问时: 需要 K_i' 才能解密，而 K_i' 取决于之前的完整执行历史

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
# 代码块拆分器
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
# 加密：base64 → 逐字节加法 → 十六进制
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
# 自修改 VM 编译器
#
# 编译策略：
#   1. 将每个代码块包装为一条 EXEC 指令（操作码 + 加密数据索引）
#   2. 所有指令用初始变异密钥加密存储
#   3. 编译时预计算：每条指令的加密形式 + 执行后的变异密钥
#   4. 变异密钥 = sha256sum(当前密钥 + 指令位置) 的前16字符
#      → 不依赖代码执行结果（避免不可移植）
#      → 但攻击者必须知道变异算法才能解密下一条指令
#      → 变异算法在 VM 解释器中（运行时才执行）
#
# 指令编码格式（加密前）：
#   "EXEC:<data_index>"   — 加载并执行数据块
#   "HALT"                — 停止
#
# 指令存储格式（加密后）：
#   encrypt("EXEC:5", K_0) → 十六进制字符串
#==============================================================================

compile_self_mod_vm() {
    local count=${#REAL_BLOCKS[@]}
    local i key next_key instruction encrypted

    # 生成初始变异密钥
    key=$(gen_rand 16)
    VM_INITIAL_KEY="$key"

    # 清空数组
    VM_INSTRUCTIONS=()
    VM_DATA=()

    # 加密所有数据块（使用 sha256 链式派生密钥，与运行时一致）
    local data_key="$key"
    for ((i = 0; i < count; i++)); do
        # 数据块 = 原始代码 + 密钥派生命令（sha256派生，不暴露明文）
        local wrapped
        wrapped="${REAL_BLOCKS[$i]}"$'\n_ck=$(printf "%s" "$_ck" | sha256sum | cut -c1-16)'
        VM_DATA[$i]=$(encrypt_block "$wrapped" "$data_key")
        # 编译时用相同的 sha256 派生推进密钥，与运行时 _ck 演进一致
        data_key=$(printf '%s' "$data_key" | sha256sum | cut -c1-16)
    done

    # 编译指令序列（每条指令加密存储）
    for ((i = 0; i < count; i++)); do
        instruction="EXEC:$i"
        encrypted=$(encrypt_block "$instruction" "$key")
        VM_INSTRUCTIONS[$i]="$encrypted"
        # 变异密钥演进：sha256(key + position)
        key=$(printf '%s%d' "$key" "$i" | sha256sum | cut -c1-16)
    done

    # HALT 指令
    VM_INSTRUCTIONS[$count]=$(encrypt_block "HALT" "$key")

    echo "信息：自修改VM编译完成，$count 条指令，$count 个数据块" >&2
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
        echo "# Generated: $timestamp [v4-self-mod-vm]"
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
    return 0
}
_x || exit 1
ANTI_EOF
        echo ""

        # ===== 完整性检查 =====
        echo "# Integrity"
        echo '[[ $- != *x* ]] || exit 1'
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

        # ===== 解密函数 =====
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

# 加密函数（自修改VM需要运行时加密）
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
DECRYPT_EOF
        echo ""

        # ===== 加密指令表 =====
        echo "# Encrypted instructions (self-modifying)"
        echo "declare -a _c"
        for ((i = 0; i < ${#VM_INSTRUCTIONS[@]}; i++)); do
            echo "_c[$i]=\"${VM_INSTRUCTIONS[$i]}\""
        done
        echo ""

        # ===== 加密数据表 =====
        echo "# Encrypted data blocks"
        echo "declare -a _d"
        for ((i = 0; i < ${#VM_DATA[@]}; i++)); do
            echo "_d[$i]=\"${VM_DATA[$i]}\""
        done
        echo ""

        # ===== 初始变异密钥 =====
        echo "_mk=\"$VM_INITIAL_KEY\""
        echo ""

        # ===== 数据块解密密钥（链式派生）=====
        echo "_ck=\"$VM_INITIAL_KEY\""
        echo ""

        # ===== 自修改 VM 解释器 =====
        cat << 'VM_EOF'
_p=0
_n=${#_c[@]}

while [ "$_p" -lt "$_n" ]; do
    # 完整性检查（每次执行指令前）
    [[ $- != *x* ]] || exit 1
    [ -z "$(declare -f eval 2>/dev/null)" ] || exit 1

    # JIT 解密当前指令
    _inst=$(_f "${_c[$_p]}" "$_mk")

    # 解析指令
    case "$_inst" in
        EXEC:*)
            # 提取数据块索引
            _di="${_inst#EXEC:}"

            # 用链式密钥解密数据块
            _code=$(_f "${_d[$_di]}" "$_ck")

            # 执行代码
            eval "$_code"
            unset _code

            # 执行后，_ck 已被代码内部的 sha256sum 派生更新
            # 不暴露明文密钥，攻击者无法 grep

            # 自修改：用变异密钥重新加密当前指令
            # 变异密钥演进
            _mk=$(printf '%s%d' "$_mk" "$_p" | sha256sum | cut -c1-16)

            # 重新加密当前指令（密文变化）
            _c[$_p]=$(_e "$_inst" "$_mk")
            ;;
        HALT)
            break
            ;;
        *)
            # 未知指令，跳过
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

    # 自修改 VM 编译
    compile_self_mod_vm

    # 生成输出
    generate_output "$output_script"

    echo "成功：已生成自修改VM混淆脚本 '$output_script'"
}

#==============================================================================
# 主程序入口
#==============================================================================

main() {
    if [[ $# -lt 1 ]]; then
        echo "用法: $0 <input_script.sh> [output_script.sh]"
        echo ""
        echo "特性：自修改VM + JIT解密 + 密钥派生 + 反调试"
        return 1
    fi

    local input_file="$1"
    local output_file="${2:-${input_file%.sh}_selfmod.sh}"

    obfuscate_script "$input_file" "$output_file"
    return $?
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi