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
# 工具函数：字符串编码【生成代码字符串】，不是当场执行！
#------------------------------------------------------------------------------

# 将字符串转换为十六进制表示
str_to_hex() {
    local str="$1"
    printf '%s' "$str" | od -An -tx1 | tr ' ' '\\x'
}

# 生成hex执行代码片段（基础混淆，返回字符串，不执行）
gen_hex_code() {
    local cmd="$1"
    local hex_str=$(str_to_hex "$cmd")
    cat <<EOF
{
    local h="${hex_str}"
    printf "\$h" | bash
}
EOF
}

# 生成Base64执行代码片段（中高级混淆，返回字符串）
gen_base64_code() {
    local cmd="$1"
    local b64=$(echo -n "$cmd" | base64 -w0)
    cat <<EOF
{
    echo '${b64}' | base64 -d | bash
}
EOF
}

# 环境变量拼接执行代码片段
gen_env_concat_code() {
    local full_cmd="$1"
    local part1="${full_cmd:0:2}"
    local part2="${full_cmd:2}"
    cat <<EOF
{
    export CMD_PART_A="${part1}"
    export CMD_PART_B="${part2}"
    \$CMD_PART_A\$CMD_PART_B
}
EOF
}

#------------------------------------------------------------------------------
# 控制流重写与无用跳转插入【生成代码字符串】
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

#------------------------------------------------------------------------------
# 函数拆分与重组模拟【生成代码字符串】
#------------------------------------------------------------------------------

# 模拟函数拆分：将核心逻辑片段化并延迟加载
simulate_function_splitting() {
    local script_name="$1"
    local core_func_file="$WORK_DIR/core_logic.sh"

    # 提取原始脚本的核心功能（简化版：待嵌入主体）
    cat > "$core_func_file" << 'EOF_CORE'
_core_main_logic() {
$(printf "\\x65\\x63\\x68\\x6f") "Obfuscated Script Execution Started."
# ORIGIN_CODE_PLACEHOLDER
}
EOF_CORE

    local core_content
    core_content=$(< "$core_func_file")

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
$core_content
INNER_EOF

# source并执行
source "\$__CORE_FILE" 2>/dev/null && _core_main_logic "\$@"
rm -f "\$__CORE_FILE"
# --- 模拟模块化加载结束 ---
EOF
}

#------------------------------------------------------------------------------
# 轻量级虚拟机指令模拟 (Pseudo-VM)【修复动态数组语法】
#------------------------------------------------------------------------------

# 编译原始命令为伪字节码数组，生成VM代码字符串
compile_to_pseudo_vm_bytecode() {
    local raw_cmd="$1"
    local encoded_cmd=$(echo -n "$raw_cmd" | base64 -w0)
    local opcode="EXEC_BASH_BASE64"
    local rand_name=$(tr -dc A-Za-z </dev/urandom | head -c 8)
    local bytecode_var="__VM_CODE_${rand_name}"

    cat << EOF
# --- 轻量级伪虚拟机开始 ---
declare -a ${bytecode_var}
${bytecode_var}[0]="$opcode"
${bytecode_var}[1]="$encoded_cmd"

# 虚拟机解释器
_interpret_vm_bytecode() {
    local pc=0
    local -n ref_arr=${bytecode_var}
    local max_pc=\${#ref_arr[@]}
    while [ \$pc -lt \$max_pc ]; do
        case "\${ref_arr[\$pc]}" in
            "EXEC_BASH_BASE64")
                ((pc++))
                echo "\${ref_arr[\$pc]}" | base64 -d | bash
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
unset -n ref_arr
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
        # Shebang保留
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
                gen_hex_code "echo Starting obfuscated script..."
                echo ""
                echo "# --- 原始逻辑嵌入 ---"
                gen_base64_code "$script_content"
                ;;
            2)
                # 中级混淆：控制流+无用跳转+函数模拟
                echo "$(printf "\\x23\\x20\\x4D\\x65\\x64\\x69\\x75\\x6D\\x20\\x6F\\x62\\x66\\x75\\x73\\x63\\x61\\x74\\x69\\x6F\\x6E\\x20\\x6C\\x61\\x79\\x65\\x72")"
                insert_useless_branches
                install_useless_traps
                echo ""
                simulate_function_splitting "$(basename "$input_script")" | sed "s|# ORIGIN_CODE_PLACEHOLDER|${script_content}|g"
                echo ""
                ;;
            3)
                # 高级混淆：伪VM + 多层编码
                echo "$(printf "\\x23\\x20\\x41\\x64\\x76\\x61\\x6E\\x63\\x65\\x64\\x20\\x6F\\x62\\x66\\x75\\x73\\x63\\x61\\x74\\x69\\x6F\\x6E\\x20\\x6C\\x61\\x79\\x65\\x72\\x20\\x28\\x50\\x73\\x65\\x75\\x64\\x6F\\x2D\\x56\\x4D\\x29")"
                compile_to_pseudo_vm_bytecode "$script_content"
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
        echo "环境变量选项:"
        echo "  OBFUSCATION_LEVEL=1|2|3  设置混淆级别 (默认: 3)"
        return 1
    fi

    local input_file="$1"
    local output_file="${2:-$(basename "${input_file%.sh}")_obfuscated.sh}"

    obfuscate_script "$input_file" "$output_file"
    return $?
}

# 如果脚本被直接执行，则运行主函数
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
