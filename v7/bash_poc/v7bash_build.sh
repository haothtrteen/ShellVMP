#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
# 分发内含魔改 bash 的产物时必须提供对应完整源码。
# =============================================================================
# v7bash_build.sh —— TShell「单进程 bash 路线」一键构建
#
# 全流程：明文脚本 → V6 骨架（内层口令可选）→ scrypt+HMAC 密钥流加密 →
#         嵌入改版 bash 尾部 → 输出单文件可执行 out.bash
#
# 用法：
#   bash v7bash_build.sh <明文.sh> -o <输出.bash> \
#        [--outer-pass '外层口令']       # 不给 = 离线分发模式（白盒 seed，运行无需口令）
#        [--pass '内层passkey']          # 不给则骨架无内层口令
#        [--scrypt-n N]                  # 口令模式 KDF 内存参数（默认 131072 → 16MB）
#        [--crypto aes|builtin]          # V6 数据块算法（默认 builtin）
#                                        #   builtin = 纯 bash XOR 多态（r33 起唯一可用档：
#                                        #             零 openssl 依赖，见下方强度建议）
#                                        #   aes     = 【当前不可用】AES-256-CTR + PBKDF2 600000 轮，
#                                        #             依赖 openssl，见强度建议
#        [--android-gate 0|1]            # r33：安卓环境门控（默认 1=生产；沙箱/桌面联调设 0。
#                                        #   此前硬编码 0，一键产物静默缺门控，已修）
#        [--unwrap-iter N]               # 内层 passkey 解包裹 PBKDF2 迭代（默认 10000；
#                                        #   aes 档建议 600000，builtin 档毫秒级无压力）
#        [--l1-iter N]                   # V6 一层壳迭代（默认 600000，一般无需改）
#        [--junk 0|1] [--decoy 0|1]      # 垃圾块 / 诱饵块（默认 1，全防护）
#        [--bash <改版bash路径>]         # 复用已构建的改版 bash
#        [--src <bash-5.2源码目录>]      # 首次：现场构建改版 bash
#        [--diag]                        # r13：排障版 —— 编译期开 V7_DIAG，
#                                        #   产物运行时设 V7_DIAG=1 才输出阶段
#                                        #   进度与拒绝原因（"卡在哪一步"）。
#                                        #   仅与 --src 同用有效（编译期决定）。
#
# 运行（运行契约：必须带一个 argv 文件参数，惯例 /dev/null）：
#   口令模式： echo '内层passkey' | V7_SELF=1 V7_PASS='外层口令' ./out.bash /dev/null
#   离线模式： echo '内层passkey' | V7_SELF=1                    ./out.bash /dev/null
#
# 强度建议（r33：aes 档当前不可用——openssl 无法内置进单进程解释器 +
#   v6openssl builtin 劫持命令名导致 v6 解密静默失败，真机确认。固定 builtin）：
#   默认/唯一： --crypto builtin（JUNK/DECOY 默认开；口令模式加 --outer-pass）
#   aes 档待 F1（v6openssl builtin 写路径让位）解决后再启用。
# =============================================================================
set -e

# 调用者目录：必须在任何 cd 之前记下 —— 本脚本会切进自身目录，
# 之后相对路径的入参（明文脚本/--bash/--src/输出）就都指错了地方。
PWD_AT_ENTRY="$(pwd)"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
V6_GEN="$SELF_DIR/../../v6/shell_script_obfuscator_v6.sh"
[ -f "$V6_GEN" ] || V6_GEN="$SELF_DIR/../shell_script_obfuscator_v6.sh"

# ===== r14：统一临时目录（Termux/安卓适配）=====================================
# 安卓（含 Termux）**没有可写的 /tmp**。硬编码 /tmp 会让构建第一步就挂：
#   mktemp: failed to create file via template '/tmp/v7bash_skel.XXXXXX': Permission denied
# 更隐蔽的是：下游脚本（V6 的 `mktemp -d`、无参数的 mktemp）都会**遵循 $TMPDIR**
# —— 若调用者的 TMPDIR 指向不存在/不可写的目录，它们会在深处炸开。所以这里
# 不只改自己的 mktemp，而是**先归一化 TMPDIR**，让整条链都拿到可用目录。
# 优先级：原 TMPDIR（确实可用时）→ $PREFIX/tmp（Termux 标准）→
#         /data/local/tmp（安卓全局可写，adb shell 常见）→ /tmp。
_V7TMP=""
for _c in "${TMPDIR:-}" "${PREFIX:+$PREFIX/tmp}" /data/local/tmp /tmp; do
    [ -n "$_c" ] && [ -d "$_c" ] && [ -w "$_c" ] && { _V7TMP="$_c"; break; }
done
if [ -n "$_V7TMP" ]; then
    TMPDIR="$_V7TMP"; export TMPDIR
else
    echo "错误：找不到可写的临时目录（已试 TMPDIR / \$PREFIX/tmp / /data/local/tmp / /tmp）。" >&2
    echo "      请显式指定后重试： TMPDIR=<可写目录> bash $0 ..." >&2
    exit 1
fi

PLAIN="" OUT="" OUTER_PASS="" INNER_PASS="" BASH_BIN="" SRC="" SCRYPT_N=0 ISA_TABLE=""
V6_CRYPTO="builtin" UNWRAP_ITER="" L1_ITER="" JUNK=1 DECOY=1 DO_DIAG=0 DO_AARCH64=0 KEEP_XTRACE=0
# r33：安卓门控默认开（生产=仅安卓环境可跑）。此前硬编码 0 —— 一键产物
#   全都缺环境门控，属静默降防护。沙箱/桌面联调时显式 ANDROID_GATE=0。
ANDROID_GATE="${ANDROID_GATE:-1}"
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUT="$2"; shift 2;;
    --outer-pass) OUTER_PASS="$2"; shift 2;;
    --pass) INNER_PASS="$2"; shift 2;;
    --scrypt-n) SCRYPT_N="$2"; shift 2;;
    --crypto) V6_CRYPTO="$2"; shift 2;;
    --unwrap-iter) UNWRAP_ITER="$2"; shift 2;;
    --l1-iter) L1_ITER="$2"; shift 2;;
    --junk) JUNK="$2"; shift 2;;
    --decoy) DECOY="$2"; shift 2;;
    --android-gate) ANDROID_GATE="$2"; shift 2;;
    --bash) BASH_BIN="$2"; shift 2;;
    --src) SRC="$2"; shift 2;;
    --isa-table) ISA_TABLE="$2"; shift 2;;
    --diag) DO_DIAG=1; shift;;
    --aarch64) DO_AARCH64=1; shift;;
    --keep-xtrace) KEEP_XTRACE=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) if [ -z "$PLAIN" ]; then PLAIN="$1"; shift; else echo "多余参数: $1" >&2; exit 2; fi;;
  esac
done

[ -n "$PLAIN" ] || { echo "缺少明文脚本参数（-h 看用法）" >&2; exit 2; }
case "$V6_CRYPTO" in aes|builtin) ;; *) echo "错误：--crypto 只能是 aes 或 builtin（当前: $V6_CRYPTO）" >&2; exit 2;; esac
case "$JUNK" in 0|1) ;; *) echo "错误：--junk 只能是 0 或 1" >&2; exit 2;; esac
case "$DECOY" in 0|1) ;; *) echo "错误：--decoy 只能是 0 或 1" >&2; exit 2;; esac
for _v in "$UNWRAP_ITER" "$L1_ITER"; do
  [ -n "$_v" ] && { case "$_v" in *[!0-9]*) echo "错误：迭代次数须为数字（当前: $_v）" >&2; exit 2;; esac; }
done
[ -f "$PLAIN" ] || { echo "明文脚本不存在: $PLAIN" >&2; exit 2; }
[ -n "$OUT" ] || OUT="${PLAIN%.*}.bash"

# 口令强度校验：KDF 是全链路保密性终点，弱口令可被 GPU 暴力
# （100000 轮 HMAC-SHA256）。要求 ≥8 位且字母/数字/符号三类至少占两类。
check_pass_strength() {
  local p="$1" what="$2" cls=0
  [ ${#p} -ge 8 ] || { echo "错误：$what 至少 8 位（当前 ${#p} 位）" >&2; return 1; }
  case "$p" in *[A-Za-z]*) cls=$((cls+1));; esac
  case "$p" in *[0-9]*) cls=$((cls+1));; esac
  case "$p" in *[!A-Za-z0-9]*) cls=$((cls+1));; esac
  [ "$cls" -ge 2 ] || { echo "错误：$what 至少包含字母/数字/符号中的两类" >&2; return 1; }
  return 0
}
if [ -n "$OUTER_PASS" ]; then check_pass_strength "$OUTER_PASS" "外层口令" || exit 2; fi
if [ -n "$INNER_PASS" ]; then check_pass_strength "$INNER_PASS" "内层 passkey" || exit 2; fi
[ -n "$BASH_BIN" ] || [ -n "$SRC" ] || {
  echo "需要 --bash <改版bash> 或 --src <bash-5.2源码目录>（二选一）" >&2; exit 2; }
# r13：--diag 是编译期开关，复用现成二进制时无从生效 —— 明确提示而非静默忽略。
if [ "$DO_DIAG" = 1 ] && [ -z "$SRC" ]; then
  echo "警告：--diag 需要 --src（现场从源码构建）。诊断代码在编译期生成，" >&2
  echo "      复用的 --bash 二进制里没有，产物设 V7_DIAG=1 不会输出任何内容。" >&2
fi

# 路径解析：本脚本开头已 cd 进自身目录，调用者给的相对路径会失效。
# 先按原始 cwd 复核一次，再退回脚本目录（兼容"从包根调用"与"cd 进来调用"）。
_INV_DIR="$PWD_AT_ENTRY"
if [ -n "$BASH_BIN" ] && [ ! -x "$BASH_BIN" ]; then
  for _c in "$_INV_DIR/$BASH_BIN" "$SELF_DIR/$BASH_BIN"; do
    [ -x "$_c" ] && BASH_BIN="$_c" && break
  done
fi
if [ -n "$SRC" ] && [ ! -d "$SRC" ]; then
  for _c in "$_INV_DIR/$SRC" "$SELF_DIR/$SRC"; do
    [ -d "$_c" ] && SRC="$_c" && break
  done
fi
if [ -n "$PLAIN" ] && [ ! -f "$PLAIN" ]; then
  for _c in "$_INV_DIR/$PLAIN" "$SELF_DIR/$PLAIN"; do
    [ -f "$_c" ] && PLAIN="$_c" && break
  done
fi
# 产物输出路径同理：相对路径应落在调用者目录，而不是脚本目录
case "$OUT" in
    /*) ;;
    *)  [ -n "$OUT" ] && OUT="$_INV_DIR/$OUT" ;;
esac

# 1) 改版 bash：给 --src 就现场构建（产物留在源码目录，可复用）
if [ -z "$BASH_BIN" ]; then
  echo "==> [1/3] 构建/复用改版 bash（源码: $SRC）"
  # r14：诊断能力与**目标架构**都是编译期决定的，必须显式传到 build_poc.sh
  # —— 否则现场构建出的 bash 是宿主架构（x86_64），内嵌进产物后拿到
  # aarch64 设备上直接 "Invalid ELF image for this architecture"。
  # 若 $SRC 下已有 bash 且架构与本次请求不符，也在这里重构建。
  _bpargs=("$SRC")
  [ "$DO_AARCH64" = 1 ] && _bpargs+=(--aarch64)
  [ "$DO_DIAG" = 1 ]    && _bpargs+=(--diag)
  [ "$KEEP_XTRACE" = 1 ] && _bpargs+=(--keep-xtrace)
  bash "$SELF_DIR/build_poc.sh" "${_bpargs[@]}" >/dev/null
  BASH_BIN="$SRC/bash"
  # r13：build_poc.sh 会同时产出符号表快照（<SRC>/bash.unstripped.map），
  # 供 V7_VMP_VERIFY=1 的逐函数裁剪使用；此处提示路径便于后续流程。
  [ -f "$SRC/bash.unstripped.map" ] && \
    echo "    符号表快照: $SRC/bash.unstripped.map（VMP 裁剪用，勿随产物分发）"
fi
# r14 修复：此处**只校验存在/可读，不再要求可执行位**（旧版用 `-x` 是误判）。
# 原因：本脚本的典型用法就是"在 x86 宿主机（含 Termux）上构建 aarch64 产物"，
# 而宿主**根本无法执行**目标架构的改版 bash —— Termux 会被 seccomp 直接拦截，
# 即便 `chmod +x` 也跑不起来。也就是说在跨架构复用场景下 `-x` **必然为假**，
# 旧写法会把一个完全正确的路径误报成"不可执行"并中止构建。
# 真正需要可执行的是**产物运行时**（在安卓 shell 侧跑 app.bash），与构建侧无关：
# 构建只是把该二进制作为数据读进来加密嵌入。
[ -f "$BASH_BIN" ] || { echo "错误：改版 bash 不存在: $BASH_BIN" >&2; exit 1; }
[ -r "$BASH_BIN" ] || { echo "错误：改版 bash 不可读: $BASH_BIN" >&2; exit 1; }
if [ ! -x "$BASH_BIN" ]; then
  echo "提示：$BASH_BIN 没有可执行权限。跨架构复用时这是正常的（宿主执行目标架构" >&2
  echo "      bash 会被 Termux seccomp 拦截）。构建只需读取它，不影响产物。" >&2
fi

# 2) V6 骨架（内层口令可选；算法/迭代/垃圾块由参数控制）
# 临时目录已在上方统一归一化（$TMPDIR 现在保证可写），这里直接用即可。
SKEL="$(mktemp "$TMPDIR/v7bash_skel.XXXXXX")" || {
    echo "错误：无法在 $TMPDIR 创建临时文件。" >&2; exit 1; }
trap 'rm -f "$SKEL"' EXIT
echo "==> [2/3] 生成 V6 骨架（内层口令: ${INNER_PASS:+已设置}${INNER_PASS:-无}；算法: $V6_CRYPTO）"
# 组装 V6 环境变量（只在显式给了参数时才覆盖模板默认值）
V6_ENVS="JUNK_LEVEL=$JUNK DECOY_LEVEL=$DECOY CRYPTO_MODE=$V6_CRYPTO ANDROID_GATE=$ANDROID_GATE"
# r16-7（A3）：ISA 改写过的明文，V6 的 simulate_execution 必须用【魔改 bash +
# 表】跑模拟 —— 否则构建期捕获 rc=127（随机名不存在）而运行期 C hook 还原后
# rc=0 → _ck 链分叉 → 产物跑到一半静默退出。见 R10_CHANGES G.5。
if [ -n "$ISA_TABLE" ]; then
  [ -f "$ISA_TABLE" ] || { echo "错误：--isa-table 指向的表不存在: $ISA_TABLE" >&2; exit 1; }
  [ -n "$BASH_BIN" ] || { echo "错误：--isa-table 需要同时指定 --bash（魔改 bash 用于模拟）" >&2; exit 1; }
  V6_ENVS="$V6_ENVS V7_SIM_BASH=$BASH_BIN V7_SIM_ISA_TABLE=$ISA_TABLE V7_SIM_REQUIRED=1"
  # r17：跨架构构建 —— 目标架构的魔改 bash 在宿主上跑不了（x86 宿主 + aarch64
  # ELF → Exec format error），V6 的块切分/压缩/模拟三处判定都需要 qemu 作
  # 执行器。这里按魔改 bash 的 ELF 机器码自动挑 qemu，避免用户手填。
  if [ ! -x "$BASH_BIN" ] || ! "$BASH_BIN" -c 'exit 0' 2>/dev/null; then
    _tgt=""
    # ELF e_machine 在偏移 18（2 字节 LE）：aarch64=183(0xB7) x86_64=62(0x3E)。
    # 用 od + awk 取值，避免 `tr` 产生空行导致行号错位（第一版踩过：拿到 0）。
    _mach=$(od -An -tu1 -j18 -N2 "$BASH_BIN" 2>/dev/null | awk '{print $1}')
    case "$_mach" in
        183) _tgt="aarch64" ;;
         62) _tgt="x86_64" ;;
    esac
    [ -z "$_tgt" ] && case "$V7_CC" in *aarch64*|*arm64*) _tgt="aarch64" ;; esac
    _host="$(uname -m)"; case "$_host" in arm64) _host="aarch64" ;; esac
    if [ -n "$_tgt" ] && [ "$_tgt" != "$_host" ]; then
      for _q in "qemu-${_tgt}-static" "qemu-${_tgt}"; do
        if command -v "$_q" >/dev/null 2>&1; then
          V6_ENVS="$V6_ENVS V7_SIM_QEMU=$_q"
          echo "    跨架构模拟：$_q（宿主 $_host → 目标 $_tgt）"
          break
        fi
      done
      case "$V6_ENVS" in
        *V7_SIM_QEMU*) ;;
        *) echo "错误：目标架构 $_tgt 的魔改 bash 在宿主 $_host 上不可执行，且找不到 qemu。" >&2
           echo "      请安装 qemu-user-static（apt-get install -y qemu-user-static）。" >&2
           exit 1 ;;
      esac
    fi
  fi
fi
[ -n "$UNWRAP_ITER" ] && V6_ENVS="$V6_ENVS UNWRAP_ITER=$UNWRAP_ITER"
[ -n "$L1_ITER" ]     && V6_ENVS="$V6_ENVS L1_ITER=$L1_ITER"
if [ "$V6_CRYPTO" = "aes" ] && [ -z "$UNWRAP_ITER" ]; then
  # aes 档：passkey 解包裹走真 PBKDF2，成本远低于 builtin，默认拉满
  V6_ENVS="$V6_ENVS UNWRAP_ITER=600000"
  echo "    （aes 档：内层 passkey 迭代默认 600000）"
fi
if [ -n "$INNER_PASS" ]; then
  env PASSKEY_MODE=1 PASSKEY_CUSTOM="$INNER_PASS" $V6_ENVS \
    bash "$V6_GEN" "$PLAIN" "$SKEL" >/dev/null
else
  env $V6_ENVS bash "$V6_GEN" "$PLAIN" "$SKEL" >/dev/null
fi

# r33c：V7_SKEL_KEEP=<路径> 时把 V6 骨架额外落一份（构建中间产物保留，
# 排障/对拍/研究用；mktemp 临时文件本身仍由 trap 清理）。路径由 v7_build.sh
# 按产物名生成（<out>.v6.skel.sh，绝对路径）；直连调用本脚本时可自行指定。
# 复制点必须在 V6_GEN 完成之后、嵌入之前 —— 这样即使嵌入失败，骨架也已留底。
if [ -n "${V7_SKEL_KEEP:-}" ]; then
    cp -f "$SKEL" "$V7_SKEL_KEEP" \
        && echo "    （V6 骨架副本：$V7_SKEL_KEEP）" \
        || echo "警告：V6 骨架副本写入失败：$V7_SKEL_KEEP" >&2
fi

# 3) scrypt+HMAC 密钥流+tag 加密嵌入 → 单文件输出（r12：与路线 A 同源）
echo "==> [3/3] 加密嵌入 → $OUT"
if [ -n "$OUTER_PASS" ]; then
  if [ "$SCRYPT_N" -gt 0 ] 2>/dev/null; then
    python3 "$SELF_DIR/v7_embed.py" "$SKEL" "$BASH_BIN" "$OUT" --pass "$OUTER_PASS" --scrypt-n "$SCRYPT_N"
  else
    python3 "$SELF_DIR/v7_embed.py" "$SKEL" "$BASH_BIN" "$OUT" --pass "$OUTER_PASS"
  fi
else
  echo "    （未给 --outer-pass → 离线分发模式：seed 随机 + 白盒编码，运行无需口令）"
  if [ "$SCRYPT_N" -gt 0 ] 2>/dev/null; then
    python3 "$SELF_DIR/v7_embed.py" "$SKEL" "$BASH_BIN" "$OUT" --scrypt-n "$SCRYPT_N"
  else
    python3 "$SELF_DIR/v7_embed.py" "$SKEL" "$BASH_BIN" "$OUT"
  fi
fi

echo
echo "完成。构建摘要：算法=$V6_CRYPTO  junk=$JUNK decoy=$DECOY  模式=$([ -n "$OUTER_PASS" ] && echo 口令 || echo 离线)  V6_CRYPTO=$V6_CRYPTO"
echo "运行（内层口令走 stdin）："
if [ -n "$OUTER_PASS" ]; then
  if [ -n "$INNER_PASS" ]; then
    echo "  echo '$INNER_PASS' | V7_SELF=1 V7_PASS='$OUTER_PASS' $OUT /dev/null"
  else
    echo "  V7_SELF=1 V7_PASS='$OUTER_PASS' $OUT /dev/null"
  fi
else
  if [ -n "$INNER_PASS" ]; then
    echo "  echo '$INNER_PASS' | V7_SELF=1 $OUT /dev/null"
  else
    echo "  V7_SELF=1 $OUT /dev/null"
  fi
fi
