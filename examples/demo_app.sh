#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# 示例：一个"值得保护"的脚本形态
#
# 这个脚本故意写得像真实业务逻辑（含函数、循环、条件、字符串），
# 用来演示混淆效果。
#
#   原始：cat examples/demo_app.sh          → 一眼看懂
#   产物：cat demo.protected.sh             → 只有随机令牌
#
# 用法:
#   ANDROID_GATE=0 bash v6/shell_script_obfuscator_v6.sh \
#       examples/demo_app.sh demo.protected.sh
#   bash demo.protected.sh

set -u

APP_NAME="demo"
VERSION="1.0.0"

# 模拟"商业逻辑"：一个校验函数
check_license() {
    local key="$1"
    local expected="XK7-DEMO-9F2A"

    if [ "$key" = "$expected" ]; then
        return 0
    fi
    return 1
}

# 模拟"业务逻辑"
process_items() {
    local items=("alpha" "beta" "gamma")
    local count=0

    for item in "${items[@]}"; do
        echo "  processing: $item"
        count=$((count + 1))
    done

    echo "  total: $count"
}

main() {
    echo "=== $APP_NAME v$VERSION ==="

    # 环境检查
    case "$(uname -m)" in
        aarch64|arm64) echo "arch: arm64" ;;
        x86_64)        echo "arch: x86_64" ;;
        *)             echo "arch: unknown" ;;
    esac

    # 授权检查
    if check_license "${LICENSE_KEY:-}"; then
        echo "license: valid"
    else
        echo "license: trial mode"
    fi

    # 业务
    process_items

    echo "done"
}

main "$@"
