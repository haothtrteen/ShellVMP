#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md

# shell_script_obfuscator.sh - 纯Shell脚本混淆器
# 功能：对输入的Shell脚本进行深度混淆，实现控制流重写、无用跳转插入、函数拆分模拟、指令封装等。
# 特性：不依赖任何第三方库，仅使用Bash内置命令和语法特性。
# 输出：生成功能等价但结构高度混淆的Shell脚本。

#------------------------------------------------------------------------------
# 配置与初始化
#------------------------------------------------------------------------------

# 混淆级别 (1-3)
OBFUSCATION_LEVEL=${OBFUSCATION_LEVEL:-3}

# 临时工作目录
WORK_DIR=$(mktemp -d)

# 清理函数
cleanup() {
    rm -rf "$WORK_DIR"
}

# 注册清理钩子
trap cleanup EXIT INT TERM

#------------------------------------------------------------------------------
# 工具函数：字符串编码与动态执行
#------------------------------------------------------------------------------

# 将字符串转换为十六进制表示
str_to_hex() {
    local str="$1"
    printf '%s' "$str" | od -An -tx1 | tr ' ' '\\x'
}

# 使用printf "\\x.." 执行命令（基础混淆）
exec_hex_encoded() {
    local cmd_hex=$(str_to_hex "$1")
    $(printf "$cmd_hex")
}

# Base64编码执行（中高级混淆）
exec_base64_encoded() {
    local cmd="$1"
    echo "$cmd" | base64 -w0 | { read encoded; echo "$encoded" | base64 -d | bash; }
}

# 环境变量拼接执行
exec_via_env_concat() {
    local part1="${1:0:2}"
    local part2="${1:2}"
    local arg="$2"
    export CMD_PART_A="$part1"
    export CMD_PART_B="$part2"
    $CMD_PART_A$CMD_PART_B "$arg"
}

# 大括号扩展执行（仅适用于特定命令）
exec_brace_expand() {
    local cmd="$1"
    local arg="$2"
    ${s,u,d,o} "${l}" # 示例：sudo -l，需根据实际命令调整
}

#------------------------------------------------------------------------------
# 控制流重写与无用跳转插入
#------------------------------------------------------------------------------

# 插入虚假条件分支（恒真/恒假）
insert_useless_branches() {
    cat << 'EOF'
if (true || false || true); then
    # --- 虚假路径开始 ---
    if [ -z "$(echo "dummy_check" 2>/dev/null)" ]; then
        for i in $(seq 1 0); do
            echo "This path is unreachable." > /dev/null 2>&1 || continue
        done
    else
        case $(echo "probe" | cut -c1) in
            p) 
                # 伪清理操作
                trap 'echo "Simulated cleanup..."; exit 0' USR1
                kill -USR1 $$ 2>/dev/null || true
                ;;
        esac
    fi
    # --- 虚假路径结束 ---
fi
EOF
}

# 注册无意义的信号处理器（无用跳转）
install_useless_traps() {
    cat << 'EOF'
# 安装虚假信号处理器
trap '
    echo "[TRAP] SIGUSR1 received. Performing dummy action..." > /dev/null
    sleep 0.01
    echo "Dummy action completed." > /dev/null
' USR1

trap '
    local fake_counter=0
    while [ $fake_counter -lt 1 ]; do
        ((fake_counter++))
    done
    echo "[TRAP] Fake loop terminated." > /dev/null
' USR2

# 触发一个无害信号以激活陷阱逻辑（视觉干扰）
kill -USR1 $$ 2>/dev/null || true
EOF
}

# 启用调试输出造成视觉噪声
enable_debug_noise() {
    set -x
    # 此处后续命令将被追踪，增加阅读难度
}

#------------------------------------------------------------------------------
# 函数拆分与重组模拟
#------------------------------------------------------------------------------

# 模拟函数拆分：将核心逻辑片段化并延迟加载
simulate_function_splitting() {
    local script_name="$1"
    local core_func_file="$WORK_DIR/core_logic.sh"

    # 提取原始脚本的核心功能（简化版：假设内容为待混淆主体）
    cat > "$core_func_file" << 'EOF_CORE'
_core_main_logic() {
$(printf "\\x65\\x63\\x68\\x6f") "Obfuscated Script Execution Started."
# 用户原始脚本内容将在此处被插入并进一步处理
}
EOF_CORE

    # 生成加载代码
    cat << EOF
# --- 模拟模块化加载开始 ---
# 动态定位库文件路径
__LIB_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
__CORE_FILE="\$__LIB_DIR/$script_name.core.sh"

# 加载守卫
[[ \${CORE_LOGIC_LOADED:-0} -eq 1 ]] && return 0
export CORE_LOGIC_LOADED=1

# 写入核心逻辑到临时文件（模拟source）
cat > "\$__CORE_FILE" << 'INNER_EOF'
$(cat "$core_func_file")
INNER_EOF

# 来源并执行（模拟函数拆分重组）
source "\$__CORE_FILE" 2>/dev/null && _core_main_logic "$@"
rm -f "\$__CORE_FILE"
# --- 模拟模块化加载结束 ---
EOF
}

#------------------------------------------------------------------------------
# 轻量级虚拟机指令模拟 (Pseudo-VM)
#------------------------------------------------------------------------------

# 编译原始命令为伪字节码数组
compile_to_pseudo_vm_bytecode() {
    local raw_cmd="$1"
    local encoded_cmd=$(echo "$raw_cmd" | base64 -w0)
    local opcode="EXEC_BASH_BASE64"
    local bytecode_var="__VM_CODE_$(tr -dc A-Za-z </dev/urandom | head -c 8)"

    cat << EOF
# --- 轻量级伪虚拟机开始 ---
declare -a $bytecode_var
${bytecode_var}[0]="$opcode"
${bytecode_var}[1]="$encoded_cmd"

# 虚拟机解释器
_interpret_vm_bytecode() {
    local pc=0
    local max_pc=\${#$bytecode_var[@]}
    while [ \$pc -lt \$max_pc ]; do
        case "\${$bytecode_var[\$pc]}" in
            "EXEC_BASH_BASE64")
                ((pc++))
                echo "\${$bytecode_var[\$pc]}" | base64 -d | bash
                ;;
            *)
                echo "Unknown opcode at PC=\$pc" >&2
                return 1
                ;;
        esac
        ((pc++))
    done
}

# 执行虚拟机
_interpret_vm_bytecode
# --- 轻量级伪虚拟机结束 ---
EOF
}

#------------------------------------------------------------------------------
# 主混淆引擎
#------------------------------------------------------------------------------

obfuscate_script() {
    local input_script="$1"
    local output_script="$2"

    # 读取输入脚本内容
    if [[ ! -f "$input_script" ]]; then
        echo "错误：输入文件 '$input_script' 不存在。" >&2
        return 1
    fi

    local script_content
    script_content=$(<"$input_script")

    # 开始构建混淆后脚本
    {
        # Shebang保留或重写
        echo "#!/usr/bin/env bash"
        echo ""
        echo "# 混淆生成于 $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# 原始文件: $(basename "$input_script")"
        echo ""

        # 根据级别插入混淆层
        case $OBFUSCATION_LEVEL in
            1)
                # 基础混淆：仅命令编码
                echo "$(printf "\\x23\\x20\\x42\\x61\\x73\\x69\\x63\\x20\\x6F\\x62\\x66\\x75\\x73\\x63\\x61\\x74\\x69\\x6F\\x6E\\x20\\x6C\\x61\\x79\\x65\\x72")"
                exec_hex_encoded "echo Starting obfuscated script..."
                echo ""
                echo "# --- 原始逻辑嵌入 ---"
                # 简单编码原始内容
                exec_base64_encoded "$script_content"
                ;;
            2)
                # 中级混淆：控制流+无用跳转+函数模拟
                echo "$(printf "\\x23\\x20\\x4D\\x65\\x64\\x69\\x75\\x6D\\x20\\x6F\\x62\\x66\\x75\\x73\\x63\\x61\\x74\\x69\\x6F\\x6E\\x20\\x6C\\x61\\x79\\x65\\x72")"
                insert_useless_branches
                install_useless_traps
                echo ""
                simulate_function_splitting "$(basename "$input_script")"
                echo ""
                echo "# --- 嵌入原始逻辑（Base64）---"
                exec_base64_encoded "
$(echo "$script_content" | sed 's/^/# /') # 注释化原内容以避免直接暴露
"
                ;;
            3)
                # 高级混淆：伪VM + 多层编码
                echo "$(printf "\\x23\\x20\\x41\\x64\\x76\\x61\\x6E\\x63\\x65\\x64\\x20\\x6F\\x62\\x66\\x75\\x73\\x63\\x61\\x74\\x69\\x6F\\x6E\\x20\\x6C\\x61\\x79\\x65\\x72\\x20\\x28\\x50\\x73\\x65\\x75\\x64\\x6F\\x2D\\x56\\x4D\\x29")"
                # 包含多层混淆
                compile_to_pseudo_vm_bytecode "$script_content"
                # 可加入更多层...
                ;;
            *)
                echo "未知混淆级别: $OBFUSCATION_LEVEL" >&2
                return 1
                ;;
        esac

    } > "$output_script"

    # 确保输出文件可执行
    chmod +x "$output_script"
    echo "成功：已生成混淆脚本 '$output_script'"
}

#------------------------------------------------------------------------------
# 主程序入口
#------------------------------------------------------------------------------

main() {
    if [[ $# -lt 1 ]]; then
        echo "用法: $0 <input_script.sh> [output_script.sh]"
        echo "选项:"
        echo "  OBFUSCATION_LEVEL=1|2|3  设置混淆级别 (默认: 2)"
        return 1
    fi

    local input_file="$1"
    local output_file="${2:-$(basename "${input_file%.sh}")_obfuscated.sh"}"

    obfuscate_script "$input_file" "$output_file"
    return $?
}

# 如果脚本被直接执行，则运行主函数
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi