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
# V5 编译器：检测代码注入数据块 + 简化指令集
#
# 核心改变（相对之前）：
#   - 检测代码不再是 VM 指令（CHKDBG/CHKEVAL/CHKPATH），而是普通 bash 代码
#   - 检测代码被注入到每个数据块的开头，和原始代码一起加密
#   - 攻击者看到的数据块都是密文，无法知道有哪些检测、何时触发
#   - VM 指令简化为 EXEC:N / NOP / HALT，case 分支不泄露任何检测逻辑
#==============================================================================

compile_v5() {
    local count=${#REAL_BLOCKS[@]}
    local i key instruction encrypted state pattern

    key=$(gen_rand 16)
    VM_INITIAL_KEY="$key"
    VM_INSTRUCTIONS=()
    VM_DATA=()

    # 检测代码片段（将作为普通 bash 代码注入数据块，加密后不可见）
    local -a DETS=(
        # 0: 调试模式 + LD_PRELOAD + eval 完整性
        '[[ $- == *x* ]] && exit 1; [ -n "${LD_PRELOAD:-}" ] && exit 1; [ -z "$(declare -f eval 2>/dev/null)" ] || exit 1'
        # 1: TracerPid 反调试
        'if [ -r /proc/self/status ]; then _v=$(grep "^TracerPid:" /proc/self/status 2>/dev/null | tr -dc "0-9"); [ "${_v:-0}" != "0" ] && exit 1; fi'
        # 2: 父进程检测
        'if [ -r /proc/$PPID/cmdline ] 2>/dev/null; then _v=$(tr "\0" " " < /proc/$PPID/cmdline 2>/dev/null); case "$_v" in *strace*|*ltrace*|*gdb*|*ptrace*|*dbserver*) exit 1 ;; esac; fi'
        # 3: 路径完整性
        '[ -x "$_B64" ] || exit 1; [ -x "$_SH256" ] || exit 1'
        # 4: 轻量组合检测
        '[[ $- == *x* ]] && exit 1; [ -n "${LD_PRELOAD:-}" ] && exit 1'
        # 5: TracerPid + 父进程组合
        'if [ -r /proc/self/status ]; then _v=$(grep "^TracerPid:" /proc/self/status 2>/dev/null | tr -dc "0-9"); [ "${_v:-0}" != "0" ] && exit 1; fi; if [ -r /proc/$PPID/cmdline ] 2>/dev/null; then _v=$(tr "\0" " " < /proc/$PPID/cmdline 2>/dev/null); case "$_v" in *strace*|*ltrace*|*gdb*) exit 1 ;; esac; fi'
    )

    # 加密数据块：每个块开头注入随机检测代码 + 原始代码 + 密钥派生
    local data_key="$key"
    local det_idx=0
    for ((i = 0; i < count; i++)); do
        local wrapped det
        # 随机选一个检测片段注入
        det_idx=$((RANDOM % ${#DETS[@]}))
        det="${DETS[$det_idx]}"
        # 结构：检测代码 + 原始代码 + 密钥链派生
        wrapped="${det}"$'\n'"${REAL_BLOCKS[$i]}"$'\n_ck=$(printf "%s" "$_ck" | sha256sum | cut -c1-16)'
        VM_DATA[$i]=$(encrypt_block "$wrapped" "$data_key")
        data_key=$(printf '%s' "$data_key" | sha256sum | cut -c1-16)
    done

    # 编译指令：EXEC + 随机 NOP 噪音（不再有 CHK* 指令）
    state=$(( RANDOM * RANDOM + $$ ))
    local pos=0
    for ((i = 0; i < count; i++)); do
        state=$(( (state * 1103515245 + 12345) & 0x7fffffff ))
        pattern=$((state % 3))

        case $pattern in
            0)
                # 模式0：直接执行
                encrypted=$(encrypt_block "EXEC:$i" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))
                ;;
            1)
                # 模式1：NOP + 执行（NOP 只推进密钥，增加分析难度）
                encrypted=$(encrypt_block "NOP" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))

                encrypted=$(encrypt_block "EXEC:$i" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))
                ;;
            2)
                # 模式2：执行 + NOP
                encrypted=$(encrypt_block "EXEC:$i" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))

                encrypted=$(encrypt_block "NOP" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))
                ;;
        esac
    done

    # HALT
    encrypted=$(encrypt_block "HALT" "$key")
    VM_INSTRUCTIONS+=("$encrypted")

    echo "信息：V5编译完成，$count 数据块（含内嵌检测），${#VM_INSTRUCTIONS[@]} 条指令" >&2
}

#==============================================================================
# 输出脚本生成器（检测代码已注入数据块，输出不含明文检测逻辑）
#==============================================================================

generate_output_with_e() {
    local output="$1"
    local timestamp i
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    {
        echo "#!/usr/bin/env bash"
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
# 输出文件压缩器：对生成的混淆脚本做后处理压缩
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

    compile_v5

    generate_output_with_e "$output_script"

    compact_output_file "$output_script"

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
        return 1
    fi

    local input_file="$1"
    local output_file="${2:-${input_file%.sh}_v8.sh}"

    obfuscate_script "$input_file" "$output_file"
    return $?
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi