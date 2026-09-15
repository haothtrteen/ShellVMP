#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md

# shell_script_obfuscator.sh - 纯Shell脚本混淆器 (修复版)
# 兼容 Termux 环境
#
# 修复要点：
#   1. str_to_hex: 修复 tr ' ' '\\x' 转义错误，改用循环拼接 \xNN
#   2. exec_* 函数: 原实现在混淆时执行命令而非生成代码，已改为 gen_* 代码生成函数
#   3. install_useless_traps: trap 中使用 local 非法，已改用函数定义
#   4. simulate_function_splitting: 嵌套 heredoc 引用混乱，已简化重写
#   5. base64 兼容: 添加 -w0 支持检测与回退
#   6. compile_to_pseudo_vm_bytecode: 修复变量引用和字节码生成
#   7. Level 2: 修复 sed 's/^/# /' 导致原始脚本被注释化无法执行
#   8. exec_brace_expand / exec_via_env_concat: 语法错误且未使用，已移除
#   9. 输出脚本自包含: 确保输出脚本不依赖混淆器中的函数定义
#  10. insert_useless_branches: 修复 if (true || false || true) 等非标准语法

OBFUSCATION_LEVEL=${OBFUSCATION_LEVEL:-3}
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

#==============================================================================
# 工具函数
#==============================================================================

# base64 编码（兼容不支持 -w0 的环境，如部分 Termux / macOS 配置）
base64_encode() {
    if printf '' | base64 -w0 >/dev/null 2>&1; then
        base64 -w0
    else
        base64 | tr -d '\n'
    fi
}

# 将字符串转换为 \xNN 格式的十六进制表示
# 修复：原实现 tr ' ' '\\x' 在单引号中 \\x 为字面量双反斜杠+x，导致格式错误
str_to_hex() {
    local str="$1"
    local hex result="" i
    hex=$(printf '%s' "$str" | od -An -tx1 | tr -d ' \n')
    for ((i = 0; i < ${#hex}; i += 2)); do
        result+="\\x${hex:$i:2}"
    done
    printf '%s' "$result"
}

# 生成随机后缀（兼容无 /dev/urandom 的环境）
gen_random_suffix() {
    local suffix
    suffix=$(tr -dc a-z0-9 </dev/urandom 2>/dev/null | head -c 10)
    printf '%s' "${suffix:-$(printf '%x' $$)}"
}

#==============================================================================
# 代码生成函数
# 所有函数将生成的代码输出到 stdout，在 { } > output 重定向中写入输出文件
# 修复核心：原 exec_* 函数在混淆时直接执行命令，现改为 gen_* 函数生成代码
#==============================================================================

# 生成 hex 编码的 printf 语句（视觉混淆，运行时输出到 /dev/null）
gen_hex_comment() {
    local str="$1"
    local hex
    hex=$(str_to_hex "$str")
    printf "printf '%s' > /dev/null 2>&1" "$hex"
}

# 生成 base64 编码执行代码
gen_base64_exec() {
    local content="$1"
    local encoded
    encoded=$(printf '%s' "$content" | base64_encode)
    printf 'echo "%s" | base64 -d | bash -s -- "$@"' "$encoded"
}

#==============================================================================
# 控制流混淆
#==============================================================================

# 生成虚假分支（恒假条件，永不执行）
# 修复：原 if (true || false || true) 非标准 bash 语法，改为合法条件表达式
gen_dead_branches() {
    cat << 'DEAD_EOF'
_j1=$((RANDOM ^ $$))
if [ $((_j1 % 7)) -eq 99 ]; then
    _k=0
    while [ "$_k" -lt 10 ]; do
        _k=$((_k + 1))
    done
fi
if [ -z "${_UNDEF_XYZ_:-}" ] && [ -n "${_UNDEF_XYZ_:-}" ]; then
    :
fi
DEAD_EOF
}

# 生成无用信号处理器
# 修复：原实现在 trap 内使用 local 关键字（非法，local 只能在函数内使用）
gen_useless_traps() {
    cat << 'TRAP_EOF'
_tn() { :; }
trap _tn USR1 2>/dev/null || true
trap _tn USR2 2>/dev/null || true
TRAP_EOF
}

#==============================================================================
# 函数拆分模拟
#==============================================================================

# 生成无意义函数拆分代码
# 修复：原 simulate_function_splitting 嵌套 heredoc 引用混乱，已简化
gen_function_split() {
    local s
    s=$(gen_random_suffix)
    cat << FS_EOF
_fs_${s}_a() {
    local _v_${s}=0
}
_fs_${s}_b() {
    return 0
}
_fs_${s}_a
_fs_${s}_b
FS_EOF
}

#==============================================================================
# 轻量级伪虚拟机
#==============================================================================

# 生成伪VM字节码解释器
# 修复：原 compile_to_pseudo_vm_bytecode 变量引用错误，heredoc 转义问题
gen_pseudo_vm() {
    local content="$1"
    local encoded vm
    encoded=$(printf '%s' "$content" | base64_encode)
    vm="_vm_$(gen_random_suffix)"

    cat << VM_EOF
declare -a ${vm}
${vm}[0]="EXEC"
${vm}[1]="${encoded}"
${vm}_run() {
    local _pc=0
    while [ \$_pc -lt \${#${vm}[@]} ]; do
        case "\${${vm}[\$_pc]}" in
            EXEC)
                _pc=\$((_pc + 1))
                echo "\${${vm}[\$_pc]}" | base64 -d | bash -s -- "\$@"
                ;;
            *)
                _pc=\$((_pc + 1))
                ;;
        esac
        _pc=\$((_pc + 1))
    done
}
${vm}_run "\$@"
VM_EOF
}

#==============================================================================
# 主混淆引擎
#==============================================================================

obfuscate_script() {
    local input_script="$1"
    local output_script="$2"

    if [[ ! -f "$input_script" ]]; then
        echo "错误：输入文件 '$input_script' 不存在。" >&2
        return 1
    fi

    local script_content
    script_content=$(<"$input_script")

    {
        echo "#!/usr/bin/env bash"
        echo "# 混淆生成于 $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# 原始文件: $(basename "$input_script")"
        echo ""

        case $OBFUSCATION_LEVEL in
            1)
                # 基础混淆：Base64 编码执行
                echo "# Basic obfuscation layer"
                gen_dead_branches
                echo ""
                gen_base64_exec "$script_content"
                echo ""
                ;;
            2)
                # 中级混淆：控制流 + 函数拆分 + Base64
                echo "# Medium obfuscation layer"
                gen_dead_branches
                echo ""
                gen_useless_traps
                echo ""
                gen_function_split
                echo ""
                gen_dead_branches
                echo ""
                gen_base64_exec "$script_content"
                echo ""
                ;;
            3)
                # 高级混淆：伪VM + 多层
                echo "# Advanced obfuscation layer (Pseudo-VM)"
                gen_hex_comment "Advanced obfuscation layer"
                echo ""
                gen_dead_branches
                echo ""
                gen_useless_traps
                echo ""
                gen_function_split
                echo ""
                gen_pseudo_vm "$script_content"
                echo ""
                gen_dead_branches
                echo ""
                ;;
            *)
                echo "未知混淆级别: $OBFUSCATION_LEVEL" >&2
                return 1
                ;;
        esac
    } > "$output_script"

    chmod +x "$output_script"
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