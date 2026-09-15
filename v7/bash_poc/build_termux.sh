#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
# 分发内含魔改 bash 的产物时必须提供对应完整源码。
# =============================================================================
# build_termux.sh —— 在 Termux（Android arm64）内**本地**构建魔改 bash
#
# 为什么需要它：
#   glibc 静态 bash 在 Termux（app 域）里死于 SIGSYS(31)：Android O 起 zygote
#   装的 seccomp 白名单以 bionic SYSCALLS.TXT 为界，而 glibc 2.35+ 静态启动要
#   打 rseq(arm64 #293)，bionic 不用它 → 被拦。musl 静态能绕开 rseq，但只要
#   还有别的 syscall 落在白名单外，照样 SIGSYS。
#
#   **本地构建**是唯一根治法：宿主本身就是 aarch64/bionic，编出来的 bash 用的
#   就是 bionic 自己那套 syscall，永远在白名单内；宿主即目标，不需要 qemu，
#   V6 的块切分/模拟执行（V7_SIM_BASH）可以直接拿它跑。
#
# 用法（Termux 内）：
#   pkg install clang make python3          # 静态再装：pkg install ndk-multilib
#   bash build_termux.sh                    # 动态链接（体积小，本机用足够）
#   bash build_termux.sh --static           # 静态链接（可脱离 Termux 裸跑）
#   bash build_termux.sh --src ~/bash-5.2   # 指定已有源码目录
#   bash build_termux.sh --vmp              # 附加 VMP 保护（需自备 vmpacker）
# =============================================================================
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
STATIC=0; DO_VMP=0; SRC=""; BASH_VER="5.2.37"

for a in "$@"; do
  case "$a" in
    --static) STATIC=1;;
    --vmp)    DO_VMP=1;;
    --src)    shift; SRC="${1:-}";;
    --src=*)  SRC="${a#--src=}";;
    -h|--help) sed -n '2,25p' "$0"; exit 0;;
  esac
done

# ---- 0) 环境检查 ------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || { echo "错误：缺 python3（pkg install python）" >&2; exit 1; }
command -v make    >/dev/null 2>&1 || { echo "错误：缺 make（pkg install make）" >&2; exit 1; }

# Termux 的 cc 是 clang；没有 gcc。V7_CC 让 build_poc.sh 用它。
CC_BIN="${V7_CC:-}"
if [ -z "$CC_BIN" ]; then
  for c in clang cc gcc; do
    if command -v "$c" >/dev/null 2>&1; then CC_BIN="$c"; break; fi
  done
fi
[ -n "$CC_BIN" ] || { echo "错误：找不到 C 编译器（pkg install clang）" >&2; exit 1; }
echo "==> 编译器: $CC_BIN"

if [ "$STATIC" = 1 ]; then
  # Termux 没有 libc-static；bionic 静态库由 ndk-multilib 提供
  if ! ls "$PREFIX"/lib/libc.a "$PREFIX"/*/lib/libc.a >/dev/null 2>&1; then
    echo "提示：未发现 bionic 静态库，静态链接大概率失败。" >&2
    echo "      pkg install ndk-multilib  然后重试" >&2
  fi
fi

# ---- 1) 准备 bash 源码（上游 GNU 源码；Termux 打包补丁见下方说明）----------
if [ -z "$SRC" ]; then SRC="$HOME/bash-src-$BASH_VER"; fi
if [ ! -f "$SRC/lib/sh/zread.c" ]; then
  echo "==> 准备 bash $BASH_VER 源码 → $SRC"
  mkdir -p "$SRC"
  TARBALL="${TMPDIR:-$PREFIX/tmp}/bash-$BASH_VER.tar.gz"
  mkfifo /dev/null 2>/dev/null || true
  if [ ! -f "$TARBALL" ]; then
    # r20：GNU 官方源在国内/移动网络下常慢到超时，镜像优先、官方兜底
    echo "    下载 bash $BASH_VER 源码（国内镜像优先）..."
    _dl_ok=0
    for _m in "https://mirrors.tuna.tsinghua.edu.cn/gnu/bash" \
              "https://mirrors.aliyun.com/gnu/bash" \
              "https://mirrors.ustc.edu.cn/gnu/bash" \
              "https://ftp.gnu.org/gnu/bash"; do
        echo "    尝试 $_m/bash-$BASH_VER.tar.gz"
        if curl -fsSL --connect-timeout 8 --max-time 180 \
             -o "$TARBALL" "$_m/bash-$BASH_VER.tar.gz"; then
            _dl_ok=1; break
        fi
    done
    [ "$_dl_ok" = 1 ] || { echo "错误：所有镜像均下载失败。可手动下载后放到 $SRC 并重跑 --src $SRC" >&2; exit 1; }
  fi
  tar xzf "$TARBALL" -C "$(dirname "$SRC")"
  # GNU 包解出的是 bash-<ver>/ 目录
  if [ -d "$(dirname "$SRC")/bash-$BASH_VER" ] && [ ! -d "$SRC" ]; then
    mv "$(dirname "$SRC")/bash-$BASH_VER" "$SRC"
  fi
fi
[ -f "$SRC/lib/sh/zread.c" ] || { echo "错误：$SRC 不是（魔改）bash 源码目录" >&2; exit 1; }

# ---- 2) 构建 ----------------------------------------------------------------
BP_ARGS=("$SRC")
[ "$STATIC" = 1 ] && BP_ARGS+=(--static)
[ "$DO_VMP" = 1 ] && BP_ARGS+=(--vmp)
echo "==> 构建: build_poc.sh ${BP_ARGS[*]}  （V7_CC=$CC_BIN）"
V7_CC="$CC_BIN" bash "$HERE/build_poc.sh" "${BP_ARGS[@]}"

# ---- 3) 自测 ----------------------------------------------------------------
BASH_OUT="$SRC/bash"
[ -x "$BASH_OUT" ] || { echo "错误：未产出 $BASH_OUT" >&2; exit 1; }
echo "==> 自测（本机直接执行，无需 qemu）"
"$BASH_OUT" -c 'echo "  版本: $BASH_VERSION"; a=(1 2 3); echo "  数组: ${a[2]}"; \
  declare -A m=([k]=v); echo "  关联数组: ${m[k]}"; printf "  命令替换: %s\n" "$(echo ok)"; exit 0' \
  || { echo "错误：自测失败" >&2; exit 1; }
echo "  bash -n 语法检查: $(echo 'if true; then echo x; fi' | "$BASH_OUT" -n /dev/stdin && echo OK)"

cat <<EOF

==> 完成：$BASH_OUT
    $(ls -l "$BASH_OUT" | awk '{print "体积: "$5" 字节"}')

用它做 V6 模拟执行（块切分/压缩/模拟都靠它）：
    export V7_SIM_BASH=$BASH_OUT
然后照常跑 v7_build.sh / v7bash_build.sh —— 宿主即目标，不需要 qemu。

关于 Termux 官方打包补丁（packages/bash 下 14 个 .patch）：
  绝大多数是 readline / loadables / Termux 路径相关，本构建已
  --disable-readline --without-bash-malloc，不需要它们；唯一值得留意的是
  lib-sh-tmpfile.c.patch（Android/Termux 的临时目录不是 /tmp）。若你在
  产物里用到 tmpfile/mktemp 类能力，记得 TMPDIR 指向 \$PREFIX/tmp。
EOF
