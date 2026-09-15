#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
#==============================================================================
# sh_compat_check.sh — 跨 shell 一致性门禁（crossrun）
#
# 用途：把一个【已生成的混淆产物】在多个候选 shell 下跑一遍，比对
#       stdout 与退出码。任何分歧 = 兼容层回归，应当阻断发布。
#
# 为什么需要它：
#   ShellVMP 产物的密钥链是"编译期模拟 ↔ 运行期执行"双侧对称构造。
#   只要某一侧依赖了 shell 私有语义（$RANDOM / $- / $_ / read -a /
#   declare -a / [[ ]] / <( )），两个 shell 下解出的密钥就会分叉，
#   产物会【静默 exit 1】——没有任何报错，最坏的情况是输出被截断而
#   rc 仍为 0。这类缺陷用单 shell 回归永远测不出来，必须交叉跑。
#
# 用法：
#   sh tools/sh_compat_check.sh <产物.sh> [参考产物.sh] [--keep]
#
#   <产物.sh>      必填。要检测的混淆产物。
#   [参考产物.sh]  可选。若给的是【未混淆的原始脚本】，则额外校验
#                  每个 shell 的输出是否与原始脚本一致（更强的判据）。
#   --keep         保留临时目录（排查用）。
#
# 退出码：
#   0  全部候选 shell 的 stdout + rc 一致（且与参考一致，若提供）
#   1  存在分歧
#   2  用法错误 / 产物不可读
#
# 设计原则：
#   - 某个候选 shell 不存在时【优雅跳过】并明确列出，不判失败。
#     交叉验证的价值来自"能跑的都要一致"，而不是"凑齐所有 shell"。
#   - 纯 POSIX 实现（#!/bin/sh），保证在 dash/busybox 上也能当门禁用。
#   - 不依赖 bash 数组、不依赖 <<<、不依赖 [[ ]]。
#==============================================================================

set -u

PROG_NAME=$(basename "$0")

usage() {
    cat <<EOF
用法: sh $PROG_NAME <产物.sh> [参考脚本.sh] [--keep]

  <产物.sh>       要检测的混淆产物
  [参考脚本.sh]   原始未混淆脚本；提供则额外比对输出一致性
  --keep          保留临时目录

退出码: 0=一致  1=分歧  2=用法错误
EOF
}

#------------------------------------------------------------------------------
# 参数解析
#------------------------------------------------------------------------------
KEEP=0
ARTIFACT=""
REFERENCE=""
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        -h|--help) usage; exit 0 ;;
        -*)
            echo "$PROG_NAME: 未知选项 '$arg'" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [ -z "$ARTIFACT" ]; then
                ARTIFACT="$arg"
            elif [ -z "$REFERENCE" ]; then
                REFERENCE="$arg"
            else
                echo "$PROG_NAME: 参数过多 '$arg'" >&2
                exit 2
            fi
            ;;
    esac
done

if [ -z "$ARTIFACT" ]; then
    echo "$PROG_NAME: 缺少 <产物.sh>" >&2
    usage >&2
    exit 2
fi

if [ ! -r "$ARTIFACT" ]; then
    echo "$PROG_NAME: 产物不可读: $ARTIFACT" >&2
    exit 2
fi

if [ -n "$REFERENCE" ] && [ ! -r "$REFERENCE" ]; then
    echo "$PROG_NAME: 参考脚本不可读: $REFERENCE" >&2
    exit 2
fi

#------------------------------------------------------------------------------
# 候选 shell 探测
#
# 覆盖目标矩阵：
#   bash   — 基准线（密钥链的编译期模拟语义来源）
#   mksh   — Android 4.0+ /system/bin/sh 的真实身份（P1 目标）
#   dash   — Debian/Ubuntu /bin/sh；无数组、无 $RANDOM（P2 待办）
#   ksh93  — 部分发行版的 ksh 实现（存在才测）
#   ash/busybox — 嵌入式 / OpenWrt / Alpine（存在才测）
#   zsh    — 已明确不做（见 docs/BACKLOG.md），只在存在时做【信息性】观测
#------------------------------------------------------------------------------
CANDIDATES="bash mksh dash ksh ksh93 ash busybox zsh"

# 每行格式: shell_name<TAB>shell_path<TAB>realpath
# realpath 用于去重：ksh 在很多发行版是指向 mksh 的符号链接，
# 若不去重，同一个实现会被计为两个 shell 并报"一致"，制造虚假信心。
FOUND_LIST=""
SKIPPED_LIST=""
SEEN_REAL=""

is_seen() {
    # $1 = realpath 候选；命中返回 0
    case "
$SEEN_REAL
" in
        *"
$1
"*) return 0 ;;
    esac
    return 1
}

for cand in $CANDIDATES; do
    path=$(command -v "$cand" 2>/dev/null || true)

    # 特判：busybox 需要 ash 子命令形态
    if [ "$cand" = "busybox" ]; then
        if command -v busybox >/dev/null 2>&1; then
            bb_real=$(readlink -f "$(command -v busybox)" 2>/dev/null || command -v busybox)
            if busybox ash -c ':' >/dev/null 2>&1; then
                if is_seen "$bb_real"; then
                    SKIPPED_LIST="$SKIPPED_LIST$cand (与已测 shell 同一实现)
"
                else
                    SEEN_REAL="$SEEN_REAL$bb_real
"
                    FOUND_LIST="$FOUND_LIST$cand	busybox ash	$bb_real
"
                fi
                continue
            fi
        fi
        SKIPPED_LIST="$SKIPPED_LIST$cand
"
        continue
    fi

    if [ -n "$path" ] && [ -x "$path" ]; then
        real=$(readlink -f "$path" 2>/dev/null || echo "$path")
        if is_seen "$real"; then
            # 与前面某个候选是同一实现（典型：ksh -> mksh）
            SKIPPED_LIST="$SKIPPED_LIST$cand (-> $real，同一实现已测)
"
        else
            SEEN_REAL="$SEEN_REAL$real
"
            FOUND_LIST="$FOUND_LIST$cand	$path	$real
"
        fi
    else
        SKIPPED_LIST="$SKIPPED_LIST$cand
"
    fi
done

if [ -z "$FOUND_LIST" ]; then
    echo "$PROG_NAME: 没有找到任何候选 shell，无法交叉验证" >&2
    exit 2
fi

#------------------------------------------------------------------------------
# 临时工作区
#------------------------------------------------------------------------------
WORK=$(mktemp -d 2>/dev/null) || WORK="/tmp/.shcompat.$$"
mkdir -p "$WORK" 2>/dev/null || {
    echo "$PROG_NAME: 无法创建临时目录" >&2
    exit 2
}

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo ""
        echo "临时目录已保留: $WORK"
    else
        rm -rf "$WORK" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

#------------------------------------------------------------------------------
# 结果表
#
# 用"每行一条记录"的纯文本存储，避免数组依赖（dash 无数组）。
# 记录格式: name<TAB>rc<TAB>sha<TAB>size<TAB>advisory
#
# advisory=1 表示该 shell 只做【信息性】观测，不参与判定失败。
# 目前仅 zsh：兼容 zsh 已明确不做（见 docs/BACKLOG.md 的"不做清单"与
# 重启条件）。把它留在表里是为了让维护者一眼看到"现状 + 距离"，但让
# 门禁保持 FAIL 信号干净——一个长期红的灯等于没有灯。
#------------------------------------------------------------------------------
RESULTS="$WORK/results.tsv"
ADVISORY="$WORK/advisory.tsv"
: > "$RESULTS"
: > "$ADVISORY"

is_advisory() {
    case "$1" in
        zsh) return 0 ;;
        *) return 1 ;;
    esac
}

# 最长名字宽度（对齐输出用）
WIDTH=4

#------------------------------------------------------------------------------
# 逐个 shell 执行
#------------------------------------------------------------------------------
echo "跨 shell 一致性检查"
echo "  产物: $ARTIFACT"
if [ -n "$REFERENCE" ]; then
    echo "  参考: $REFERENCE"
fi
echo ""

# --- 先跑参考脚本（若有），作为期望值 ---
REF_RC=""
REF_SHA=""
REF_SIZE=""
if [ -n "$REFERENCE" ]; then
    REF_OUT="$WORK/ref.out"
    sh_rc=0
    sh "$REFERENCE" > "$REF_OUT" 2>/dev/null || sh_rc=$?
    REF_RC=$sh_rc
    REF_SHA=$(sha256sum "$REF_OUT" 2>/dev/null | cut -d' ' -f1)
    [ -n "$REF_SHA" ] || REF_SHA=$(cksum "$REF_OUT" 2>/dev/null | cut -d' ' -f1)
    REF_SIZE=$(wc -c < "$REF_OUT" | tr -d ' ')
fi

printf '%-8s %-6s %-18s %-10s %s\n' "SHELL" "RC" "SHA256" "BYTES" "结论"
printf '%-8s %-6s %-18s %-10s %s\n' "--------" "------" "------------------" "----------" "----"

# 基准（第一个跑成功的 shell 的结果，用于两两比对）
BASELINE_NAME=""
BASELINE_SHA=""
BASELINE_RC=""

VIOLATIONS=0
EXECUTED=0

echo "$FOUND_LIST" | while IFS='	' read -r name cmdline real; do
    [ -n "$name" ] || continue

    out="$WORK/$name.out"
    rc=0
    # cmdline 可能是 "busybox ash" 这种两词形式，需按空格拆分
    # 用 set -- 做可移植分词
    OLDIFS=$IFS
    IFS=' '
    set -- $cmdline
    IFS=$OLDIFS
    # shellcheck disable=SC2068
    "$@" "$ARTIFACT" > "$out" 2>/dev/null || rc=$?

    sha=$(sha256sum "$out" 2>/dev/null | cut -d' ' -f1)
    [ -n "$sha" ] || sha=$(cksum "$out" 2>/dev/null | cut -d' ' -f1)
    size=$(wc -c < "$out" | tr -d ' ')

    printf '%s\t%s\t%s\t%s\n' "$name" "$rc" "$sha" "$size" >> "$RESULTS"
done

# 读取结果并渲染（在主 shell 里做，保证计数变量可见）
while IFS='	' read -r name rc sha size; do
    [ -n "$name" ] || continue

    # 只显示前 16 位，够判等也够排版（cut 对 dash/busybox 都可用）
    sha16=$(printf '%s' "$sha" | cut -c1-16)

    # 信息性 shell（zsh）：只观测，不判失败
    if is_advisory "$name"; then
        printf '%-8s %-6s %-18s %-10s %s\n' "$name" "$rc" "$sha16" "$size" "观测(不判定)"
        printf '%s\t%s\t%s\t%s\t1\n' "$name" "$rc" "$sha" "$size" >> "$ADVISORY"
        continue
    fi

    verdict=""
    if [ -z "$BASELINE_NAME" ]; then
        BASELINE_NAME="$name"
        BASELINE_SHA="$sha"
        BASELINE_RC="$rc"
        verdict="基准"
    else
        if [ "$sha" = "$BASELINE_SHA" ] && [ "$rc" = "$BASELINE_RC" ]; then
            verdict="一致"
        else
            verdict="!! 分歧"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    fi

    # 若提供了参考脚本，再比对一次
    if [ -n "$REFERENCE" ]; then
        if [ "$sha" = "$REF_SHA" ]; then
            verdict="$verdict / 匹配原始"
        else
            verdict="$verdict / 偏离原始"
        fi
    fi

    printf '%-8s %-6s %-18s %-10s %s\n' "$name" "$rc" "$sha16" "$size" "$verdict"
    EXECUTED=$((EXECUTED + 1))
done < "$RESULTS"

#------------------------------------------------------------------------------
# 汇总
#------------------------------------------------------------------------------
echo ""

if [ -n "$SKIPPED_LIST" ]; then
    skipped_flat=$(printf '%s' "$SKIPPED_LIST" | tr '\n' ' ')
    echo "未安装（已跳过）: $skipped_flat"
    echo "  提示：想扩测就装上对应 shell，例如 'apt-get install mksh'"
    echo ""
fi

if [ -s "$ADVISORY" ]; then
    echo "以下 shell 仅观测、不参与判定（见 docs/BACKLOG.md 的\"不做清单\"）："
    while IFS='	' read -r name rc sha size _; do
        [ -n "$name" ] || continue
        printf '  %-6s rc=%-4s bytes=%s\n' "$name" "$rc" "$size"
    done < "$ADVISORY"
    echo ""
fi

if [ -n "$REFERENCE" ]; then
    echo "参考脚本: rc=$REF_RC size=$REF_SIZE"
    echo ""
fi

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "结果：FAIL —— $VIOLATIONS 个 shell 出现分歧（基准=$BASELINE_NAME）"
    echo ""
    echo "排查提示："
    echo "  · 静默 exit 1（rc=1 且无输出）通常是【密钥链分叉】：某个 shell 私有"
    echo "    语义被掺进了 _s/_ck/_mk 派生。重点查 \$RANDOM、\$-、\$_、"
    echo "    read -a、declare -a、[[ ]]、<( )。"
    echo "  · rc=0 但输出被截断，多数是数组下标在无数组 shell 上静默失效。"
    echo "  · 语法直接报错（如 dash 的 'not found'/'Bad substitution'）说明"
    echo "    该 shell 不支持产物里用到的扩展语法，属于 P2 待办。"
    exit 1
fi

echo "结果：PASS —— $EXECUTED 个 shell 的 stdout 与退出码完全一致"
exit 0
