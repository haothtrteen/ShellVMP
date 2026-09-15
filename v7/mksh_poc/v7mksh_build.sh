#!/bin/bash
# SPDX-License-Identifier: MirOS
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# 本文件是 mksh 的衍生作品，许可证由上游强制继承（MirOS，宽松）。
# 义务：保留版权与许可声明即可，不要求提供完整源码。
# =============================================================================
# v7mksh_build.sh —— TShell「mksh 魔改解释器线」一键构建（路线 C / C3）
#
# 全流程：明文脚本 → ISA 四层表 + L6 令牌化（可选）→ V6 骨架（内层口令可选）
#         → scrypt+HMAC 密钥流加密 → 嵌入改版 mksh 尾部 → 输出单文件产物
#
# 用法：
#   bash v7mksh_build.sh <明文.sh> -o <输出.mksh> \
#        [--outer-pass '外层口令']       # 不给 = 离线分发模式（白盒 seed，运行无需口令）
#        [--pass '内层passkey']          # 不给则骨架无内层口令
#        [--scrypt-n N]                  # 口令模式 KDF 内存参数（默认 131072 → 16MB）
#        [--crypto aes|builtin]          # V6 数据块算法（默认 builtin，当前唯一可用档）
#        [--android-gate 0|1]            # V6 脚本侧环境门控（默认 1=生产）
#        [--unwrap-iter N] [--l1-iter N] # 内层解包裹 / 一层壳迭代
#        [--junk 0|1] [--decoy 0|1]      # 垃圾块 / 诱饵块（默认 1，全防护）
#        [--mksh <改版mksh路径>]         # 复用已构建的改版 mksh
#        [--src <mksh源码目录>]          # 首次：现场构建改版 mksh（★ C3 主路径）
#        [--target-arch aarch64|x86_64]  # 目标架构（交叉构建用）
#        [--isa 0|1]                     # ISA 四层随机化 + L6 令牌化（默认 1）
#        [--isa-seed N] [--isa-decoy N] [--isa-shadow N]
#        [--diag]                        # 排障版（编译期开 V7_DIAG，仅与 --src 同用）
#        [--keep-stage]                  # 保留中间产物（含明文语义等价物，勿分发）
#
# 运行（★ 运行契约：**必须带一个 argv 文件参数**，惯例 /dev/null）：
#   口令模式： V7_SELF=1 V7_PASS='外层口令' V7_ISA_TABLE=<out>.isa.bin ./out.mksh /dev/null
#   离线模式： V7_SELF=1                     V7_ISA_TABLE=<out>.isa.bin ./out.mksh /dev/null
#
#   ⚠ 不带参数时 mksh 进入 **stdin 模式（FSTDIN）**，main.c 的 shf_open 分支
#     根本不会被走到 —— 表现为**静默 rc=0、零输出**。这是运行契约，不是缺陷。
#   ⚠ 产物是**可执行 ELF**，直接 `./out.mksh` 执行；**不要**写成 `mksh out.mksh`
#     （那样 /proc/self/exe 会指向解释器而非产物，解密必然不触发）。
#
# ── 已知限制（2026-09 复验发现，尚未修复）─────────────────────────────────
#   ⚠ **内层口令档（--pass）当前不可用**：V6 骨架用 `IFS= read -rs -p 'Key: '`
#     读口令，而 `-p` 在两个 shell 里语义相反 —— bash 是 "prompt 字符串"，
#     mksh 是 "从 coprocess 读" ⇒ 产物报 `read: -p: no coprocess`，rc=1。
#     **外层口令（--outer-pass）与离线分发模式不受影响，正常可用。**
#     修法候选：V6 生成器侧对目标解释器消歧（改写为 printf + 无 -p 的 read）。
#     详见 docs/BUILD_MKSH.md §6.3 / §6.3b 与 docs/PITFALLS.md §8.4b。
#
# ── 与 bash 线的关键顺序差异（照抄 bash 线必死） ────────────────────────────
#   bash 线：先改写脚本（ISA）→ 再构建解释器。因为改版 bash 由调用者提供，
#             ISA 的 -n 预检用它跑。
#   mksh 线：**先构建解释器 → 再改写脚本 → 用本次构建出的改版 mksh 做 -n 预检**。
#            理由：mksh 由本脚本现场构建，预检必须用这个刚出炉的二进制。
#            照抄 bash 线顺序会得到"预检时 mksh 还不存在"的死锁。
#            顺序： [1/3] 构建 → [1.5] ISA → [2/3] V6 骨架 → [3/3] 嵌入
# =============================================================================
set -e

# 调用者目录：必须在任何 cd 之前记下 —— 本脚本会切进自身目录，
# 之后相对路径的入参（明文脚本/--mksh/--src/输出）就都指错了地方。
PWD_AT_ENTRY="$(pwd)"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
# 本脚本位于 v7/mksh_poc/；与 v7/bash_poc/ 平级。
# 共享工具（ISA 插桩器/锚点表/C 端 hook/嵌入器）都在 bash_poc 下 —— 因为
# 它们是**两线共用**的（isa_hook.py 表驱动、v7_embed.py 载荷无关）。
BASH_POC="$SELF_DIR/../bash_poc"
V6_GEN="$SELF_DIR/../../v6/shell_script_obfuscator_v6.sh"
[ -f "$V6_GEN" ] || V6_GEN="$SELF_DIR/../shell_script_obfuscator_v6.sh"

# ===== r14：统一临时目录（Termux/安卓适配）=====================================
# 安卓（含 Termux）**没有可写的 /tmp**。硬编码 /tmp 会让构建第一步就挂：
#   mktemp: failed to create file via template '/tmp/v7mksh_skel.XXXXXX': Permission denied
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

PLAIN="" OUT="" OUTER_PASS="" INNER_PASS="" MKSH_BIN="" MKSH_SRC="" SCRYPT_N=0
V6_CRYPTO="${V7_CRYPTO:-builtin}" UNWRAP_ITER="${V7_UNWRAP_ITER:-}" L1_ITER="${V7_L1_ITER:-}"
JUNK="${V7_JUNK:-1}" DECOY="${V7_DECOY:-1}" DO_DIAG=0 KEEP_STAGE="${V7_KEEP_STAGE:-0}"
TARGET_ARCH="${V7_ARCH:-}"
# ISA 开关：命令行 --isa 优先，其次环境变量 V7_ISA（与 v7_build.sh 的通用开关同名）。
#   ★ 为什么需要环境变量兜底：v7_build.sh 把 V7_ISA 翻译成 --isa 传进来，那时
#     两边一致；但**直连本脚本**（排障/CI/文档示例）时用户会自然地设 V7_ISA=0，
#     若只认 --isa 就会"设了不生效"——正是本脚本自己反复强调要避免的静默坑。
DO_ISA="${V7_ISA:-1}"; ISA_SEED="${V7_ISA_SEED:-}"
ISA_DECOY="${V7_ISA_DECOY:-24}" ISA_SHADOW="${V7_ISA_SHADOW:-8}"
# r33：安卓门控默认开（生产=仅安卓环境可跑）。注意这与 TARGET_OS=Android 是
#   **两件不同的事**：本开关是 V6 注入的【脚本侧环境门控】，与 mksh 的编译
#   平台选择无关。别把它当"编译安卓版"用。
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
    --mksh) MKSH_BIN="$2"; shift 2;;
    --src) MKSH_SRC="$2"; shift 2;;
    --target-arch) TARGET_ARCH="$2"; shift 2;;
    --isa) DO_ISA="$2"; shift 2;;
    --isa-seed) ISA_SEED="$2"; shift 2;;
    --isa-decoy) ISA_DECOY="$2"; shift 2;;
    --isa-shadow) ISA_SHADOW="$2"; shift 2;;
    --diag) DO_DIAG=1; shift;;
    --keep-stage) KEEP_STAGE=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) if [ -z "$PLAIN" ]; then PLAIN="$1"; shift; else echo "多余参数: $1" >&2; exit 2; fi;;
  esac
done

[ -n "$PLAIN" ] || { echo "缺少明文脚本参数（-h 看用法）" >&2; exit 2; }
case "$V6_CRYPTO" in aes|builtin) ;; *) echo "错误：--crypto 只能是 aes 或 builtin（当前: $V6_CRYPTO）" >&2; exit 2;; esac
case "$JUNK" in 0|1) ;; *) echo "错误：--junk 只能是 0 或 1" >&2; exit 2;; esac
case "$DECOY" in 0|1) ;; *) echo "错误：--decoy 只能是 0 或 1" >&2; exit 2;; esac
case "$DO_ISA" in 0|1) ;; *) echo "错误：--isa 只能是 0 或 1（当前: $DO_ISA）" >&2; exit 2;; esac
case "$TARGET_ARCH" in ""|aarch64|x86_64|arm64|amd64) ;;
    *) echo "错误：--target-arch 只能是 aarch64 或 x86_64（当前: $TARGET_ARCH）" >&2; exit 2;; esac
case "$TARGET_ARCH" in arm64) TARGET_ARCH="aarch64";; amd64) TARGET_ARCH="x86_64";; esac
for _v in "$UNWRAP_ITER" "$L1_ITER"; do
  [ -n "$_v" ] && { case "$_v" in *[!0-9]*) echo "错误：迭代次数须为数字（当前: $_v）" >&2; exit 2;; esac; }
done
[ -f "$PLAIN" ] || { echo "明文脚本不存在: $PLAIN" >&2; exit 2; }
[ -n "$OUT" ] || OUT="${PLAIN%.*}.mksh"

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
[ -n "$MKSH_BIN" ] || [ -n "$MKSH_SRC" ] || {
  echo "需要 --mksh <改版mksh> 或 --src <mksh源码目录>（二选一）" >&2; exit 2; }
# r13：--diag 是编译期开关，复用现成二进制时无从生效 —— 明确提示而非静默忽略。
if [ "$DO_DIAG" = 1 ] && [ -z "$MKSH_SRC" ]; then
  echo "警告：--diag 需要 --src（现场从源码构建）。诊断代码在编译期生成，" >&2
  echo "      复用的 --mksh 二进制里没有，产物设 V7_DIAG=1 不会输出任何内容。" >&2
fi

# 路径解析：本脚本开头已 cd 进自身目录，调用者给的相对路径会失效。
# 先按原始 cwd 复核一次，再退回脚本目录（兼容"从包根调用"与"cd 进来调用"）。
_INV_DIR="$PWD_AT_ENTRY"
if [ -n "$MKSH_BIN" ] && [ ! -f "$MKSH_BIN" ]; then
  for _c in "$_INV_DIR/$MKSH_BIN" "$SELF_DIR/$MKSH_BIN"; do
    [ -f "$_c" ] && MKSH_BIN="$_c" && break
  done
fi
if [ -n "$MKSH_SRC" ] && [ ! -d "$MKSH_SRC" ]; then
  for _c in "$_INV_DIR/$MKSH_SRC" "$SELF_DIR/$MKSH_SRC"; do
    [ -d "$_c" ] && MKSH_SRC="$_c" && break
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

# 宿主架构（用于判断"是否需要 qemu 才能跑目标产物"）
_host="$(uname -m)"; case "$_host" in arm64) _host="aarch64" ;; esac
[ -n "$TARGET_ARCH" ] || TARGET_ARCH="$_host"

# =========================================================================
# [1/3] 改版 mksh：给 --src 就现场构建（产物留在源码目录，可复用）
# =========================================================================
if [ -z "$MKSH_BIN" ]; then
  _MK="$MKSH_SRC"
  echo "==> [1/3] 构建改版 mksh（源码: $_MK，目标架构: $TARGET_ARCH）"

  # ---- fail-closed ①：源码树形态 ----
  [ -d "$_MK" ] || { echo "错误：mksh 源码树不存在: $_MK" >&2; exit 1; }
  [ -f "$_MK/Build.sh" ] || {
    echo "错误：$_MK 不是 mksh 源码树（缺 Build.sh）" >&2; exit 1; }

  # ---- fail-closed ②：版本前置探测（比锚点失败更早、信息更准）----
  # 锚点表 site_old 是**逐字符匹配源码**的，版本不符必然失败。与其让用户
  # 面对"锚点不匹配"这种内部措辞，不如在这里直接说清怎么取正确版本。
  # 判据直接从锚点表取 MKSH_MAIN_RCSID —— 这样版本串**永远是权威的那一份**，
  # 不会出现"脚本里写死一个版本串、anchors.py 升级后与之漂移"的隐患。
  _rcsid="$(python3 -c "
import sys; sys.path.insert(0, '$BASH_POC')
try:
    import anchors
    print(anchors.MKSH_MAIN_RCSID.strip())
except Exception:
    print('')
" 2>/dev/null)"
  if [ -z "$_rcsid" ]; then
    echo "警告：无法从 anchors.py 读取版本标识，跳过版本前置探测" >&2
    echo "      （插桩本身仍会 fail-closed，不会静默改错位置）" >&2
  elif ! grep -qF "$_rcsid" "$_MK/main.c" 2>/dev/null; then
    echo "错误：$_MK 不是 mksh R59c（锚点表逐字符匹配源码，版本不符必失败）" >&2
    echo "      期望 main.c 含：$_rcsid" >&2
    echo "      取正确版本：" >&2
    echo "        git clone https://github.com/MirBSD/mksh.git && git checkout mksh-R59c" >&2
    exit 1
  fi

  # ---- ③ 锚点插桩（幂等）----
  # MKSH_R59C 锚点集含 6 个 op：ISA 四层（lex.c/exec.c×2）+ C1（main.c×2）
  # + C2（shf.c）。即跑一次就把 ISA 插桩**和** C1/C2 挂载点全部落位。
  # ⚠ 插桩与下方"拷 C 文件"是**强耦合**的：插桩加的 extern/调用点需要
  #    v7_builtin_takeover.c / v7_shf_inject.c / v7core.c 存在，否则
  #    编译期必然 undefined reference。
  python3 "$BASH_POC/isa_hook.py" --interp mksh-R59c --srcdir "$_MK" || {
    echo "错误：mksh 锚点插桩失败（见上方输出）" >&2
    echo "      常见原因：源码版本不是 R59c（见上）" >&2
    exit 1
  }

  # ---- ④ 拷 C 层文件（★改名，对齐锚点表的 #include 与符号名）----
  # 源文件名带 _mksh 后缀（表明是 mksh 版实现），进源码树必须去掉后缀 ——
  # 因为锚点表生成的 extern 声明与 Build.sh 的 SRCS 用的都是无后缀名。
  # 漏改名的症状：cc1: fatal error: ./v7_shf_inject.c: No such file or directory
  echo "    拷入 C 层文件..."
  cp -f "$SELF_DIR/v7core_mksh.c"              "$_MK/v7core.c"
  cp -f "$SELF_DIR/v7_builtin_takeover_mksh.c" "$_MK/v7_builtin_takeover.c"
  cp -f "$SELF_DIR/v7_shf_inject_mksh.c"       "$_MK/v7_shf_inject.c"
  cp -f "$BASH_POC/isa_hook.c"                 "$_MK/isa_hook.c"
  cp -f "$BASH_POC/crypto_isa.h"               "$_MK/crypto_isa.h"
  for _f in v7core.c v7_builtin_takeover.c v7_shf_inject.c isa_hook.c crypto_isa.h; do
    [ -f "$_MK/$_f" ] || { echo "错误：C 层文件未到位: $_MK/$_f" >&2; exit 1; }
  done

  # ---- ⑤ ISA C 符号表 + 主密钥（不存在才生成）----
  # v7_isa_key.h 是**配对主密钥**：换掉它会让既有 ISA 表全部作废，
  # 所以只在缺失时生成一次（与 build_poc.sh 同策略）。
  if [ ! -f "$BASH_POC/v7_isa_syms.h" ]; then
    python3 "$SELF_DIR/../../tools/v7_isa.py" emit-c -o "$BASH_POC/v7_isa_syms.h" || {
      echo "错误：无法生成 v7_isa_syms.h" >&2; exit 1; }
  fi
  if [ ! -f "$BASH_POC/v7_isa_key.h" ]; then
    python3 "$SELF_DIR/../../tools/v7_isa.py" emit-key -o "$BASH_POC/v7_isa_key.h" || {
      echo "错误：无法生成 v7_isa_key.h" >&2; exit 1; }
    echo "    已生成新主密钥 v7_isa_key.h（既有 ISA 表将全部作废）"
  fi
  cp -f "$BASH_POC/v7_isa_syms.h" "$_MK/v7_isa_syms.h"
  cp -f "$BASH_POC/v7_isa_key.h"  "$_MK/v7_isa_key.h"

  # ---- ⑥ 改 Build.sh 的 SRCS（逐项幂等；兼容任意历史形态）----
  # mksh 没有 Makefile，构建靠自带 Build.sh 里的 SRCS 变量。实测上游形态：
  #   SRCS="$SRCS lex.c main.c misc.c shf.c syn.c tree.c var.c"
  # 而插桩/既往构建可能已把部分文件追加进去。**必须逐项判断**：
  #   曾用"含 v7_builtin_takeover.c 就整体跳过"的粗判据，结果在**局部状态**
  #   的树上翻车 —— 该树只有 v7_builtin_takeover.c，粗判据判定"已处理"，
  #   另两个文件永远加不进去 → 编译期 undefined reference。
  #   教训：幂等判据要落在**每个待加项**上，而不是"任意一项代表全部"。
  _BS="$_MK/Build.sh"
  _need=""
  for _f in v7_builtin_takeover.c v7_shf_inject.c v7core.c; do
    grep -q "$_f" "$_BS" || _need="$_need $_f"
  done

  if [ -z "$_need" ]; then
    echo "    （Build.sh SRCS 已含 v7 三件套，跳过）"
  else
    echo "    Build.sh SRCS 待补:$_need"
    # 锚点断言（fail-closed）：不匹配就打印实际行，便于对照 §七 校准
    grep -q '^SRCS="\$SRCS lex\.c main\.c misc\.c shf\.c syn\.c tree\.c var\.c' "$_BS" || {
      echo "错误：Build.sh SRCS 锚点不匹配（第 610-611 行形态已变）" >&2
      echo "      当前实测值：" >&2; sed -n '610,611p' "$_BS" >&2
      echo "      请校准 sed 锚点（见 docs/BUILD_MKSH.md §七）" >&2
      exit 1; }
    # 先把缺的逐个追加（捕获组 $1 吸收可选尾部，三种形态归一）
    for _f in $_need; do
      sed -i "s|^SRCS=\"\\\$SRCS lex\\.c main\\.c misc\\.c shf\\.c syn\\.c tree\\.c var\\.c\\(.*\\)\"\$|SRCS=\"\$SRCS lex.c main.c misc.c shf.c syn.c tree.c var.c\\1 $_f\"|" "$_BS"
    done
  fi
  # 生效断言（照抄 build_poc.sh 的做法：改完必须逐项确认，不靠"看着对"）
  for _f in isa_hook.c v7_builtin_takeover.c v7_shf_inject.c v7core.c; do
    grep -q "$_f" "$_BS" || {
      echo "错误：Build.sh SRCS 缺 $_f（sed 未生效或锚点形态不符）" >&2
      echo "      当前 SRCS 行：" >&2; grep '^SRCS="\$SRCS lex' "$_BS" >&2
      exit 1; }
  done

  # ---- ⑦ 编译 ----
  # TARGET_OS 是 mksh 的**平台**（Linux/Android），不是架构（见 --target-arch）。
  # 一律带 -r（重新配置）：跨架构切换时不 -r 可能复用旧 .o，链接出混合架构
  # 二进制（症状是 Exec format error 或更隐蔽的崩溃）。
  _MKSH_TARGET_OS="Linux"
  case "$TARGET_ARCH:$ANDROID_GATE" in
      aarch64:1) _MKSH_TARGET_OS="Android" ;;
  esac
  echo "    编译（TARGET_OS=$_MKSH_TARGET_OS）..."
  ( cd "$_MK" && TARGET_OS="$_MKSH_TARGET_OS" sh Build.sh -r ) || {
    echo "错误：mksh 编译失败（见上方 Build.sh 输出）" >&2; exit 1; }

  # ---- ⑧ 产物校验（编译成功 ≠ 插桩进去了）----
  MKSH_BIN="$_MK/mksh"
  [ -s "$MKSH_BIN" ] || {
    echo "错误：编译成功但未产出 $_MK/mksh（Build.sh 产物名已变？）" >&2; exit 1; }
  # 插桩生效性：v7 符号必须真的链进二进制（op 被跳过或符号被消除都会静默）
  if command -v nm >/dev/null 2>&1; then
    nm "$MKSH_BIN" 2>/dev/null | grep -q 'v7_shf_inject' || {
      echo "错误：改版 mksh 里找不到 v7_shf_inject —— C2 注入层未链接进去" >&2
      echo "      检查：Build.sh SRCS 是否含 v7_shf_inject.c" >&2
      echo "      检查：插桩输出里 shf.c 那条 op 是否 '已插桩'" >&2
      exit 1; }
  else
    # nm 不可用（交叉工具链场景常见）→ 降级为字符串搜索，只警告不阻断
    grep -q 'v7_shf_inject' "$MKSH_BIN" 2>/dev/null || \
      echo "警告：无法确认 v7_shf_inject 已链接（nm 不可用，字符串搜索未命中）" >&2
  fi
  echo "    改版 mksh: $MKSH_BIN（$(wc -c < "$MKSH_BIN") 字节）"
fi

# r14：**只校验存在/可读，不要求可执行位**。典型用法是"x86 宿主构建 aarch64
#   产物"，而宿主**根本无法执行**目标架构的 mksh —— 跨架构场景下 `-x` 必然为假，
#   用它会把一个完全正确的路径误报成"不可执行"并中止构建。真正需要可执行的是
#   **产物运行侧**，与构建侧无关（构建只是把它当数据读进来加密嵌入）。
#   ⚠ 注意例外：ISA 段的 -n 预检**确实要执行**它，那里的跨架构处理见下。
[ -f "$MKSH_BIN" ] || { echo "错误：改版 mksh 不存在: $MKSH_BIN" >&2; exit 1; }
[ -r "$MKSH_BIN" ] || { echo "错误：改版 mksh 不可读: $MKSH_BIN" >&2; exit 1; }
if [ ! -x "$MKSH_BIN" ]; then
  echo "提示：$MKSH_BIN 没有可执行权限。跨架构复用时这是正常的（宿主执行目标架构" >&2
  echo "      二进制会被内核/Termux seccomp 拦截）。构建只需读取它，不影响产物。" >&2
fi

# V6 环境变量（后段 [2/3] 用；先在此初始化，ISA 段可能追加）
V6_ENVS="JUNK_LEVEL=$JUNK DECOY_LEVEL=$DECOY CRYPTO_MODE=$V6_CRYPTO ANDROID_GATE=$ANDROID_GATE"
[ -n "$UNWRAP_ITER" ] && V6_ENVS="$V6_ENVS UNWRAP_ITER=$UNWRAP_ITER"
[ -n "$L1_ITER" ]     && V6_ENVS="$V6_ENVS L1_ITER=$L1_ITER"
if [ "$V6_CRYPTO" = "aes" ] && [ -z "$UNWRAP_ITER" ]; then
  # aes 档：passkey 解包裹走真 PBKDF2，成本远低于 builtin，默认拉满
  V6_ENVS="$V6_ENVS UNWRAP_ITER=600000"
  echo "    （aes 档：内层 passkey 迭代默认 600000）"
fi

# =========================================================================
# [1.5/3] ISA 四层随机化 + L6 令牌化
#
# ★★ 顺序关键：本段必须在 [1/3] **之后** —— 因为 -n 预检要用【刚构建出的】
#    改版 mksh。它不是 bash 线那样"调用者提供的现成二进制"。
#
# ISA 在 mksh 线是**功能性必需**而非增强项：[2/3] 的 V6 混淆 + [3/3] 的嵌入
# 都建立在"改写后的脚本"上。L6 的字符串令牌解密出口挂在 C1 的 builtin 接管
# （v7_builtin_takeover_mksh.c 调 v7_isa_param_decode），本线已实装。
# =========================================================================
_isa_bin=""; _isa_in=""; _isa_json=""
if [ "$DO_ISA" = "1" ]; then
  command -v python3 >/dev/null 2>&1 || { echo "错误：ISA 需要 python3" >&2; exit 1; }
  # 顺序守卫：防止将来有人"顺手"把本段挪到 [1/3] 之前 → 死锁/误判
  [ -f "$MKSH_BIN" ] || {
    echo "内部错误：ISA 段在 mksh 构建之前被调用（顺序见本脚本头部注释）" >&2; exit 1; }

  _isa_bin="$OUT.isa.bin"; _isa_json="$OUT.isa.json"; _isa_in="$OUT.isa.in.sh"
  _seed_args=""
  [ -n "$ISA_SEED" ] && _seed_args="--seed $ISA_SEED"

  echo "==> [1.5/3] ISA 四层随机化表"
  python3 "$SELF_DIR/../../tools/v7_isa.py" gen $_seed_args \
      --decoy "$ISA_DECOY" --shadow "$ISA_SHADOW" \
      -o "$_isa_bin" --json "$_isa_json" || {
    echo "错误：ISA 表生成失败" >&2
    echo "      常见原因：缺少主密钥 $BASH_POC/v7_isa_key.h" >&2
    exit 1; }

  # 表与密钥配对性校验（换了 v7_isa_key.h 会让表解不开 → ISA 静默空转，
  # 产物仍能跑但零保护 —— 这正是最难察觉的失效形态，故显式验一次）。
  python3 "$SELF_DIR/../../tools/v7_isa.py" check --table "$_isa_bin" || {
    echo "错误：ISA 表校验失败（表与主密钥不配对？）" >&2; exit 1; }

  # L1/L2 命令位置改写
  python3 "$SELF_DIR/../../tools/v7_isa.py" rewrite \
      --table "$_isa_json" --in "$PLAIN" --out "$_isa_in" || {
    echo "错误：ISA L1/L2 改写失败" >&2; exit 1; }

  # L6 字符串字面量令牌化（mksh 的 C1 出口已实装，故与本线同批启用）
  # 与 v7_build.sh 的 ISA_PARAM 段同范式：gen-param 从【明文】提取静态串
  # （字符串在 L1-L5 改写中不被触及，故对明文与改写版取值等价），
  # --with-table 把 L1-L5 表合并进来 → 一张表含 L1-L6。
  python3 "$SELF_DIR/../../tools/v7_isa.py" gen-param \
      --in "$PLAIN" --with-table "$_isa_json" -o "$_isa_bin" --json "$_isa_json" || {
    echo "错误：L6 参数令牌表生成失败" >&2; exit 1; }
  _t="$_isa_in.p$$"
  python3 "$SELF_DIR/../../tools/v7_isa.py" rewrite-param \
      --table "$_isa_json" --in "$_isa_in" --out "$_t" || {
    rm -f "$_t"; echo "错误：L6 字符串改写失败" >&2; exit 1; }
  mv -f "$_t" "$_isa_in"

  # ---- fail-closed：用【本次构建的改版 mksh】做 -n 语法预检 ----
  # 改写产物必须过语法检查，否则 [2/3] 的 V6 模拟与 [3/3] 的运行期会分叉。
  # 跨架构时宿主跑不了目标 mksh → 必须 qemu；**绝不"跳过预检继续跑"**：
  # 那等于把 fail-closed 静默拆掉，坏产物会以"构建成功"的形态流出去。
  _chk_run=""
  if [ "$TARGET_ARCH" != "$_host" ]; then
    for _q in "qemu-${TARGET_ARCH}-static" "qemu-${TARGET_ARCH}"; do
      command -v "$_q" >/dev/null 2>&1 && { _chk_run="$_q"; break; }
    done
    [ -n "$_chk_run" ] || {
      echo "错误：目标架构 $TARGET_ARCH ≠ 宿主 $_host，ISA 的 -n 预检需要 qemu-user。" >&2
      echo "      三条出路（任选）：" >&2
      echo "        1) apt-get install -y qemu-user-static" >&2
      echo "        2) V7_ISA=0 关闭 ISA —— 注意这是**明确降低保护**" >&2
      echo "        3) 改为同架构构建（宿主架构 = 目标架构）" >&2
      exit 1; }
    echo "    跨架构预检：$_chk_run（宿主 $_host → 目标 $TARGET_ARCH）"
  fi
  V7_ISA_TABLE="$_isa_bin" $_chk_run "$MKSH_BIN" -n "$_isa_in" 2>"$_isa_in.err" || {
    _prc=$?
    echo "错误：ISA 改写产物未通过改版 mksh -n 预检（rc=$_prc）" >&2
    echo "      预检解释器：$MKSH_BIN   改写产物：$_isa_in" >&2
    echo "      ---- mksh 自己的 stderr ----" >&2
    cat "$_isa_in.err" >&2
    echo "      ---- 手工复现 ----" >&2
    echo "      V7_ISA_TABLE=$_isa_bin $_chk_run $MKSH_BIN -n $_isa_in; echo rc=\$?" >&2
    rm -f "$_isa_in.err"
    exit 1; }
  rm -f "$_isa_in.err"
  echo "    ISA 表 $(wc -c < "$_isa_bin")B，改写版 $(wc -c < "$_isa_in")B"
  PLAIN="$_isa_in"     # ★ 后续 [2/3] 用改写版作为 V6 的输入

  # V6 的构建期模拟必须用"魔改解释器 + 表"跑 —— 否则构建期捕获 rc=127
  # （随机名不存在）、运行期 C hook 还原后 rc=0 → _ck 链分叉 → 产物跑到
  # 一半静默退出。变量名带 BASH 是历史命名，语义是"任意带 ISA hook 的解释器"
  # （已核 v6 生成器只做存在性/可执行性探测 + V7_ISA_TABLE 透传，无 bash 依赖）。
  V6_ENVS="$V6_ENVS V7_SIM_BASH=$MKSH_BIN V7_SIM_ISA_TABLE=$_isa_bin V7_SIM_REQUIRED=1"
  [ -n "$_chk_run" ] && V6_ENVS="$V6_ENVS V7_SIM_QEMU=$_chk_run"
fi

# =========================================================================
# [2/3] V6 骨架（内层口令可选；算法/迭代/垃圾块由参数控制）
#       本段与解释器无关 —— 与 bash 线逐字相同（V6 生成器两线共用同一份）。
# =========================================================================
SKEL="$(mktemp "$TMPDIR/v7mksh_skel.XXXXXX")" || {
    echo "错误：无法在 $TMPDIR 创建临时文件。" >&2; exit 1; }
trap 'rm -f "$SKEL"' EXIT
echo "==> [2/3] 生成 V6 骨架（内层口令: ${INNER_PASS:+已设置}${INNER_PASS:-无}；算法: $V6_CRYPTO）"
if [ -n "$INNER_PASS" ]; then
  env PASSKEY_MODE=1 PASSKEY_CUSTOM="$INNER_PASS" $V6_ENVS \
    bash "$V6_GEN" "$PLAIN" "$SKEL" >/dev/null
else
  env $V6_ENVS bash "$V6_GEN" "$PLAIN" "$SKEL" >/dev/null
fi
# 生成器可能"静默失败"（rc=0 但产物为空），必须显式验
[ -s "$SKEL" ] || { echo "错误：V6 骨架为空（生成器静默失败）" >&2; exit 1; }

# --keep-stage：额外落一份骨架（排障/对拍用；临时文件本身仍由 trap 清理）
if [ "$KEEP_STAGE" = 1 ]; then
  cp -f "$SKEL" "$OUT.v6.skel.sh" \
    && echo "    （V6 骨架副本：$OUT.v6.skel.sh —— 含明文语义等价物，勿随产物分发）" \
    || echo "警告：V6 骨架副本写入失败：$OUT.v6.skel.sh" >&2
fi

# =========================================================================
# [3/3] scrypt+HMAC 密钥流+tag 加密嵌入 → 单文件输出
#       本段与解释器无关 —— v7_embed.py 的第二参数语义就是"任意 ELF 载荷"，
#       mksh 二进制代入零改动（两线共用同一套 blob v3 布局 / V7_BLOB_OVERHEAD）。
# =========================================================================
echo "==> [3/3] 加密嵌入 → $OUT"
if [ -n "$OUTER_PASS" ]; then
  if [ "$SCRYPT_N" -gt 0 ] 2>/dev/null; then
    python3 "$BASH_POC/v7_embed.py" "$SKEL" "$MKSH_BIN" "$OUT" --pass "$OUTER_PASS" --scrypt-n "$SCRYPT_N"
  else
    python3 "$BASH_POC/v7_embed.py" "$SKEL" "$MKSH_BIN" "$OUT" --pass "$OUTER_PASS"
  fi
else
  echo "    （未给 --outer-pass → 离线分发模式：seed 随机 + 白盒编码，运行无需口令）"
  if [ "$SCRYPT_N" -gt 0 ] 2>/dev/null; then
    python3 "$BASH_POC/v7_embed.py" "$SKEL" "$MKSH_BIN" "$OUT" --scrypt-n "$SCRYPT_N"
  else
    python3 "$BASH_POC/v7_embed.py" "$SKEL" "$MKSH_BIN" "$OUT"
  fi
fi
[ -s "$OUT" ] || { echo "错误：嵌入未产出文件: $OUT" >&2; exit 1; }

# 产物可执行位（就地执行是 mksh 线的运行形态；与 bash 线一致）
chmod +x "$OUT" 2>/dev/null || true

# =========================================================================
# 收尾：运行说明（★ mksh 特有契约，必须显式打印）
# =========================================================================
echo
echo "完成。构建摘要：解释器=mksh-R59c  算法=$V6_CRYPTO  junk=$JUNK decoy=$DECOY  模式=$([ -n "$OUTER_PASS" ] && echo 口令 || echo 离线)"
echo "      改版 mksh $MKSH_BIN（$(wc -c < "$MKSH_BIN")B）+ 骨架（$(wc -c < "$SKEL")B）+ 812 = 产物 $(wc -c < "$OUT")B"
if [ -n "$ANDROID_GATE" ] && [ "$ANDROID_GATE" != "0" ]; then
  echo "注：ANDROID_GATE=$ANDROID_GATE 是【脚本侧环境门控】（V6 注入）。"
  echo "    若要交叉编译 Android 版 mksh 本身，需另设 V7_ARCH=aarch64 / V7_CC=<交叉编译器>。"
fi
echo
echo "★ 运行契约：**必须带一个 argv 文件参数**（惯例 /dev/null）。"
echo "  不带参数时 mksh 进 stdin 模式，解密分支不会被走到 —— 表现为静默 rc=0、零输出。"
echo "  产物是 ELF，直接执行；**不要**写成 'mksh $OUT'（那是错误用法）。"
if [ -n "$INNER_PASS" ]; then
  # 2026-09 复验：内层口令档撞上 read -p 语义分叉（见 .md §6.3 / PITFALLS §8.4b）。
  # 这里不静默给出一条跑不通的示例 —— 那等于把已知缺陷藏起来。
  echo
  echo "⚠  警告：本次构建用了【内层口令档】（V7_PASS / --pass）。"
  echo "    该档在 mksh 线【当前不可用】：V6 骨架用 'IFS= read -rs -p ...' 读口令，"
  echo "    而 '-p' 在 bash 里是 prompt、在 mksh 里是【从 coprocess 读】"
  echo "    ⇒ 运行时报 'read: -p: no coprocess'，rc=1。"
  echo "    请改用【外层口令】重建（去掉 V7_PASS，保留 V7_OUTER_PASS），"
  echo "    或去掉 V7_OUTER_PASS 走离线分发模式。"
  echo "    参考：docs/BUILD_MKSH.md §6.3 / §6.3b，docs/PITFALLS.md §8.4b"
fi
if [ -n "$OUTER_PASS" ]; then
  echo "  V7_SELF=1 V7_PASS='$OUTER_PASS' $OUT /dev/null"
else
  echo "  V7_SELF=1 $OUT /dev/null"
fi
if [ -n "$_isa_bin" ]; then
  echo "  注：本产物带 ISA 表，运行时需 export V7_ISA_TABLE=$_isa_bin"
  echo "      （否则 L1-L6 令牌不解，输出假名而非明文）"
  [ "$KEEP_STAGE" = 1 ] || echo "      （表文件已保留：$_isa_bin）"
fi
if [ "$KEEP_STAGE" = 1 ]; then
  [ -f "$_isa_in" ] && echo "  保留中间产物：$_isa_in —— 令牌化版（V6 混淆的输入，含明文语义等价物，勿分发）"
  [ -f "$_isa_json" ] && echo "  保留中间产物：$_isa_json —— ISA 表 JSON"
else
  rm -f "$_isa_json" "$_isa_in"
fi
