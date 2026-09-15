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
    local encoded keybytes databytes
    encoded=$(printf '%s' "$block" | base64_encode)
    keybytes=$(printf '%s' "$key" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    databytes=$(printf '%s' "$encoded" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    awk -v data="$databytes" -v kb="$keybytes" '
    BEGIN {
        n = split(kb, k, " ")
        nd = split(data, d, " ")
        for (i = 1; i <= nd; i++) {
            printf "%02x", (d[i] + k[(i-1) % n + 1]) % 256
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
# _s 执行状态计算器：随机生成唯一表达式，无固定模式可枚举
#
# 核心思路：
#   不是从 N 种模式中选一种，而是每次随机拼装一个多项式表达式
#   随机变量数 (2-4)、随机运算 (+, *, %)、随机常量、随机拼接顺序
#   AI 无法建查找表，必须逐块阅读代码并求值
#==============================================================================

gen_s_computation() {
    local current_s="$1" di="$2"
    local nvars=$((RANDOM % 2 + 2))
    local var_decls=""
    local all_items=()
    local i

    all_items+=("_s|%s|$current_s")
    all_items+=("_di|%d|$di")

    for ((i = 0; i < nvars; i++)); do
        local vname="_sa"
        [ $i -eq 1 ] && vname="_sb"
        [ $i -eq 2 ] && vname="_sc"
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
    local fmt="" args="" i idx
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
        code="${var_decls}_s=\$(printf \"$fmt\" $args| sha256sum | cut -c1-8); _s=\$(printf \"%s\" \"\$_s\" | sha256sum | cut -c1-8)"
    else
        code="${var_decls}_s=\$(printf \"$fmt\" $args| sha256sum | cut -c1-8)"
    fi

    local new_s
    new_s=$(eval "_s='$current_s'; _di=$di; $code; printf '%s' \"\$_s\"")

    printf '%s\x01%s' "$code" "$new_s"
}

#==============================================================================
# _ck 密钥派生：同样随机生成唯一表达式
#==============================================================================

gen_ck_derivation_with_s() {
    local current_ck="$1" new_s="$2" di="$3"
    local nvars=$((RANDOM % 2 + 1))
    local var_decls=""
    local all_items=()
    local i

    all_items+=("_ck|%s|$current_ck")
    all_items+=("_s|%s|$new_s")
    all_items+=("_di|%d|$di")

    for ((i = 0; i < nvars; i++)); do
        local vname="_zz"
        [ $i -eq 1 ] && vname="_zy"
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
    new_ck=$(eval "_ck='$current_ck'; _s='$new_s'; _di=$di; $code; printf '%s' \"\$_ck\"")

    printf '%s\x01%s' "$code" "$new_ck"
}

#==============================================================================
# V5 编译器：执行依赖密钥链
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

    key=$(gen_rand 16)
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

    # 加密数据块：每个块注入检测 + 原始代码 + _s 计算 + _ck 派生
    local data_key="$key"
    local det_idx=0

    for ((i = 0; i < count; i++)); do
        local wrapped det s_code new_s ck_code new_ck s_result ck_result

        det_idx=$((RANDOM % ${#DETS[@]}))
        det="${DETS[$det_idx]}"

        s_result=$(gen_s_computation "$s" "$i")
        s_code="${s_result%%$'\x01'*}"
        new_s="${s_result#*$'\x01'}"

        ck_result=$(gen_ck_derivation_with_s "$data_key" "$new_s" "$i")
        ck_code="${ck_result%%$'\x01'*}"
        new_ck="${ck_result#*$'\x01'}"

        if [ "$i" -eq 0 ]; then
            wrapped="${integ_code}"$'\n'"${det}"$'\n'"${REAL_BLOCKS[$i]}"$'\n'"${s_code}"$'\n'"${ck_code}"
            VM_D0_PLAINTEXT="$wrapped"
        else
            wrapped="${det}"$'\n'"${REAL_BLOCKS[$i]}"$'\n'"${s_code}"$'\n'"${ck_code}"
        fi

        VM_DATA[$i]=$(encrypt_block "$wrapped" "$data_key")

        s="$new_s"
        data_key="$new_ck"
    done

    # 编译指令：EXEC + 随机 NOP
    state=$(( RANDOM * RANDOM + $$ ))
    local pos=0
    for ((i = 0; i < count; i++)); do
        state=$(( (state * 1103515245 + 12345) & 0x7fffffff ))
        pattern=$((state % 3))

        case $pattern in
            0)
                encrypted=$(encrypt_block "EXEC:$i" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))
                ;;
            1)
                encrypted=$(encrypt_block "NOP" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))

                encrypted=$(encrypt_block "EXEC:$i" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))
                ;;
            2)
                encrypted=$(encrypt_block "EXEC:$i" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))

                encrypted=$(encrypt_block "NOP" "$key")
                VM_INSTRUCTIONS+=("$encrypted")
                key=$(printf '%s%d' "$key" "$pos" | sha256sum | cut -c1-16); ((pos++))
                ;;
        esac
    done

    encrypted=$(encrypt_block "HALT" "$key")
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

    # 构建 VM 解释器字符串（将被整体加密）
    local interpreter
    interpreter=$(cat << 'INTERP_EOF'
_f() {
    local _da="$1" _ke="$2"
    local _kb _r
    _kb=$(printf '%s' "$_ke" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    _r=$(awk -v hex="$_da" -v kb="$_kb" '
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
            r = r sprintf("\\x%02x", (b - k[cnt % n + 1] + 256) % 256)
        }
        printf "%s", r
    }')
    printf "$_r" | base64 -d
}
_e() {
    local _da="$1" _ke="$2"
    local _encoded _kb _bytes
    _encoded=$(printf '%s' "$_da" | base64 -w0 2>/dev/null || printf '%s' "$_da" | base64 | tr -d '\n')
    _kb=$(printf '%s' "$_ke" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    _bytes=$(printf '%s' "$_encoded" | od -An -td1 -v | tr -d '\n' | tr -s ' ' | sed 's/^ //;s/ $//')
    awk -v data="$_bytes" -v kb="$_kb" '
    BEGIN {
        n = split(kb, k, " ")
        nd = split(data, d, " ")
        for (i = 1; i <= nd; i++) {
            printf "%02x", (d[i] + k[(i-1) % n + 1]) % 256
        }
    }'
}
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
unset _mk _ck _p _n _s _di _sa _sb _sc _sd _zz _zy _zv 2>/dev/null
INTERP_EOF
)

    # 计算解释器密钥：从 _c 数组值拼接后 sha256（非显而易见）
    local all_c=""
    for ((i = 0; i < ${#VM_INSTRUCTIONS[@]}; i++)); do
        all_c+="${VM_INSTRUCTIONS[$i]}"
    done
    local interp_key
    interp_key=$(printf '%s' "$all_c" | sha256sum | cut -c1-16)

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

        # 初始密钥 + 执行状态变量
        echo "_mk=\"$VM_INITIAL_KEY\""
        echo "_ck=\"$VM_INITIAL_KEY\""
        echo "_s=\"$VM_INITIAL_S\""
        echo ""

        # 加密的 VM 解释器（XOR 密文）
        echo "_I=\"$encrypted_interp\""
        echo ""

        # 极简 bootstrap：内联 XOR 解密 + eval（无函数定义，变量名不冲突）
        cat << 'BOOTSTRAP_EOF'
_a=""
for ((_bi=0; _bi<${#_c[@]}; _bi++)); do _a+="${_c[$_bi]}"; done
_k=$(printf '%s' "$_a" | sha256sum | cut -c1-16)
_r=""
for ((_bi=0; _bi<${#_I}; _bi+=2)); do
    _bb=$((16#${_I:_bi:2}))
    _bj=$((_bi/2 % ${#_k}))
    _bk=$(printf '%d' "'${_k:_bj:1}")
    _r+="\\x${_h[$((_bb ^ _bk))]}"
done
eval "$(printf "$_r" | base64 -d)"
unset _a _k _r _I _bi _bb _bj _bk 2>/dev/null
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

    # 重新加密 _d[0]（使用初始数据密钥 = VM_INITIAL_KEY）
    encrypted_d0=$(encrypt_block "$d0_real" "$VM_INITIAL_KEY")

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