#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md

# ==============================================================================
# Shell Script Obfuscation and Protection Tool (SSOPT)
# 功能：对Shell脚本进行加密混淆加固，包含代码混淆、字符串加密和反调试机制
# 生成时间：2026-07-22
# 依赖工具：shc, openssl, gpg, coreutils
# 使用方式：./ss_opt.sh -i input.sh -o output.bin [options]
# ==============================================================================

set -euo pipefail

# 默认配置
INPUT_FILE="vm.sh"
OUTPUT_FILE="1.sh"
EXPIRE_DATE=""
EXPIRE_MSG=""
USE_ANTI_DEBUG=false
USE_MEMORY_LOAD=false
ENCRYPTION_TYPE="shc"  # shc | aes | gpg
PASSWORD_FILE=""
VERBOSE=false
CLEAN_INTERMEDIATE=true

# 日志函数
log() {
    local level="$1"
    shift
    if [[ "$VERBOSE" == true ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" >&2
    fi
}

error() {
    echo "ERROR: $*" >&2
    exit 1
}

usage() {
    cat << EOF
用法: $0 [选项]

选项:
    -i FILE            指定输入的shell脚本文件 (必需)
    -o FILE            指定输出的加密后文件名 (必需)
    -e DATE            设置过期日期 (格式: dd/mm/yyyy)
    -m MESSAGE         自定义过期提示信息
    -a                 启用反调试保护 (使用shc -U)
    -t                 启用内存加载模式 (防止临时文件泄露)
    -E TYPE            加密类型: shc (默认), aes, gpg
    -p PASSFILE        密码文件路径 (用于aes/gpg加密)
    -v                 启用详细输出
    -k                 保留中间文件 (不清理临时文件)
    -h                 显示此帮助信息

示例:
    # 使用SHC编译并设置过期时间
    $0 -i script.sh -o protected.bin -e 31/12/2027 -a

    # 使用OpenSSL AES-256加密
    $0 -i script.sh -o encrypted.bin -E aes -p ./secret.key -v

    # 使用GPG对称加密
    $0 -i script.sh -o secured.bin -E gpg
EOF
}

# 检查命令是否存在
require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error "缺少必要命令: $cmd，请先安装"
    fi
}

# 字符串混淆：Base64编码敏感字符串（示例性混淆）
obfuscate_strings() {
    local file="$1"
    local temp_file=$(mktemp)
    cp "$file" "$temp_file"

    # 对常见命令进行编码替换（仅作演示，实际应更复杂）
    sed -i 's|echo "\(.*\)"|eval $(echo "ZWNobyAi\1Ig==" | base64 -d)|g' "$temp_file" 2>/dev/null || true
    sed -i 's|ls |eval $(echo "bHMgLQ==" | base64 -d)|g' "$temp_file" 2>/dev/null || true

    log INFO "已完成字符串混淆处理"
    echo "$temp_file"
}

# 变量名混淆：将变量重命名为随机字符串（简化版）
obfuscate_variables() {
    local file="$1"
    local temp_file=$(mktemp)
    cp "$file" "$temp_file"

    # 提取所有变量名（简单正则，适用于基础场景）
    local vars=$(grep -oE '\$?[a-zA-Z_][a-zA-Z0-9_]*' "$temp_file" | \
                grep -E '^[a-zA-Z_][a-zA-Z0-9_]*$' | sort -u | \
                grep -Ev '^(if|then|else|elif|fi|for|while|do|done|case|esac)$')

    for var in $vars; do
        # 生成6位随机变量名
        local new_var=$(cat /dev/urandom | tr -dc 'a-z' | fold -w 6 | head -n 1)
        # 替换变量（确保不是子串匹配）
        sed -i "s/\b$var\b/$new_var/g" "$temp_file"
    done

    log INFO "已完成变量名混淆处理"
    echo "$temp_file"
}

# SHC加密编译
encrypt_with_shc() {
    local input="$1"
    local output="$2"
    local args=("-f" "$input" "-o" "$output")

    [[ -n "$EXPIRE_DATE" ]] && args+=("-e" "$EXPIRE_DATE")
    [[ -n "$EXPIRE_MSG" ]] && args+=("-m" "$EXPIRE_MSG")
    [[ "$USE_ANTI_DEBUG" == true ]] && args+=("-U")
    [[ "$USE_MEMORY_LOAD" == true ]] && args+=("-T")
    [[ "$VERBOSE" == true ]] && args+=("-v")

    log INFO "正在使用shc进行加密编译..."
    if shc "${args[@]}"; then
        log INFO "shc加密成功: $output"
        # 清理C源码
        [[ "$CLEAN_INTERMEDIATE" == true ]] && rm -f "${input}.x.c"
        return 0
    else
        error "shc加密失败"
    fi
}

# OpenSSL AES-256加密
encrypt_with_aes() {
    local input="$1"
    local output="$2"

    if [[ ! -f "$PASSWORD_FILE" ]]; then
        log WARN "未指定密码文件，将生成随机密钥"
        PASSWORD_FILE=$(mktemp)
        openssl rand -base64 32 > "$PASSWORD_FILE"
        chmod 600 "$PASSWORD_FILE"
        log INFO "生成临时密钥: $PASSWORD_FILE"
    fi

    log INFO "正在使用OpenSSL AES-256-CBC加密..."
    if openssl enc -aes-256-cbc -salt -pbkdf2 -iter 10000 \
               -in "$input" -out "$output" -pass "file:$PASSWORD_FILE"; then
        log INFO "AES加密成功: $output"
        return 0
    else
        error "AES加密失败"
    fi
}

# GPG对称加密
encrypt_with_gpg() {
    local input="$1"
    local output="$2"

    log INFO "正在使用GPG进行对称加密..."
    if gpg --symmetric --cipher-algo AES256 --output "$output" "$input"; then
        log INFO "GPG加密成功: $output"
        return 0
    else
        error "GPG加密失败"
    fi
}

# 完整性校验生成
generate_checksum() {
    local file="$1"
    local checksum_file="${file}.sha256"
    sha256sum "$file" > "$checksum_file"
    chmod 600 "$checksum_file"
    log INFO "完整性校验已生成: $checksum_file"
}

# 文件属性加固
harden_file() {
    local file="$1"
    # 设置权限：仅所有者可读写执行
    chmod 500 "$file" 2>/dev/null || true
    # 尝试设置不可变属性（需root权限）
    if command -v chattr >/dev/null 2>&1; then
        chattr +i "$file" 2>/dev/null || true
    fi
    log INFO "文件已加固: $file"
}

# 主函数
main() {
    # 解析参数
    while getopts "i:o:e:m:atE:p:vhk" opt; do
        case $opt in
            i) INPUT_FILE="$OPTARG" ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            e) EXPIRE_DATE="$OPTARG" ;;
            m) EXPIRE_MSG="$OPTARG" ;;
            a) USE_ANTI_DEBUG=true ;;
            t) USE_MEMORY_LOAD=true ;;
            E) ENCRYPTION_TYPE="$OPTARG" ;;
            p) PASSWORD_FILE="$OPTARG" ;;
            v) VERBOSE=true ;;
            k) CLEAN_INTERMEDIATE=false ;;
            h) usage; exit 0 ;;
            *) usage; exit 1 ;;
        esac
    done

    # 参数验证
    [[ -z "$INPUT_FILE" ]] && error "必须指定输入文件 (-i)"
    [[ -z "$OUTPUT_FILE" ]] && error "必须指定输出文件 (-o)"
    [[ ! -f "$INPUT_FILE" ]] && error "输入文件不存在: $INPUT_FILE"
    [[ "$ENCRYPTION_TYPE" != "shc" && "$ENCRYPTION_TYPE" != "aes" && "$ENCRYPTION_TYPE" != "gpg" ]] && \
        error "不支持的加密类型: $ENCRYPTION_TYPE"

    log INFO "开始对脚本进行加密混淆加固: $INPUT_FILE -> $OUTPUT_FILE"

    # 检查依赖
    case "$ENCRYPTION_TYPE" in
        shc) require_cmd shc ;;
        aes) require_cmd openssl ;;
        gpg) require_cmd gpg ;;
    esac

    local work_file="$INPUT_FILE"

    # 执行混淆（仅在使用shc时进行，因aes/gpg直接加密原文件）
    if [[ "$ENCRYPTION_TYPE" == "shc" ]]; then
        log INFO "开始执行混淆处理..."
        work_file=$(obfuscate_strings "$work_file")
        work_file=$(obfuscate_variables "$work_file")
    fi

    # 执行加密
    case "$ENCRYPTION_TYPE" in
        shc) encrypt_with_shc "$work_file" "$OUTPUT_FILE" ;;
        aes) encrypt_with_aes "$INPUT_FILE" "$OUTPUT_FILE" ;;
        gpg) encrypt_with_gpg "$INPUT_FILE" "$OUTPUT_FILE" ;;
    esac

    # 生成校验和
    generate_checksum "$OUTPUT_FILE"

    # 文件加固
    harden_file "$OUTPUT_FILE"

    # 清理混淆临时文件
    if [[ "$work_file" != "$INPUT_FILE" && "$CLEAN_INTERMEDIATE" == true ]]; then
        rm -f "$work_file"
    fi

    # 清理临时密钥
    if [[ -n "$PASSWORD_FILE" && "$PASSWORD_FILE" == /tmp/* && "$CLEAN_INTERMEDIATE" == true ]]; then
        rm -f "$PASSWORD_FILE"
    fi

    log INFO "加密混淆加固完成！输出文件: $OUTPUT_FILE"
    log INFO "校验文件: ${OUTPUT_FILE}.sha256"
    [[ "$ENCRYPTION_TYPE" == "aes" && -n "$PASSWORD_FILE" ]] && \
        log INFO "加密密钥: $PASSWORD_FILE (请及时备份或删除)"

    exit 0
}

# 入口点
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi