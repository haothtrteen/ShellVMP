#!/bin/bash
# build_poc.sh —— 在 bash-5.2 源码目录内执行，产出魔改 bash 二进制（r11）。
#
# 用法：
#   bash build_poc.sh <bash-5.2源码目录> [--static] [--aarch64] [--vmp] [--diag]
#
#   --static    静态链接（Termux 本机/沙箱静态验证建议）
#   --aarch64   交叉编译 aarch64（需 aarch64-linux-gnu-gcc；qemu-aarch64-static 可验证）
#   --vmp       构建后用 VMPacker 保护 v7core 三个纯叶子函数
#               （仅 aarch64；需 VMPACKER 环境变量或默认路径可执行）
#   --no-anti-disasm   跳过「抹除节区视图」步骤（排错/对比分析时用）
#   --keep-diag        保留 `v7: ` 诊断串（排错时用；默认剔除）
#   --diag      r13：构建**排障版** —— 定义 V7_DIAG，产物运行时设 V7_DIAG=1
#               即向 stderr 输出阶段进度与拒绝原因（透明解密激活/分发模式/
#               KDF 进度/HMAC 验签/时间窗耗时/反调试拦截点）。生产构建不定义，
#               诊断代码与 V7DIAG 串整体不生成，strings 零残留。
#               注：与 --keep-diag 不同——后者只是**保留**既有 `v7: ` 提示串，
#               本项才提供阶段级进度（"卡在哪一步"）。
#
# r11.1 变更：
#   - 新增 anti-disassembly：ELF 节区层视图抹除（elf_anti_disasm.py），与
#     路线 A 的 v7_build.sh 步骤 5b 同源同效果。
#     实测：readelf -S → no sections；objdump -d 由 149533 条降到 0 条。
#     边界：Ghidra/IDA/radare2 等基于 Program Header 反汇编的工具不受影响。
#   - 新增诊断串剔除（diag_strip.py）：抹掉 9 条 `v7: xxx` 泄漏。
#     `TracerPid`/`frida` 是运行时必需读取的目标串，刻意保留。
#     剔除后错误路径仍返回原退出码（114 等），但 stderr 无明文，排错看退出码表。
#
# r11 变更：
#   - 密码学核心拆分 lib/sh/v7core.c（VMP 目标编译单元，纯叶子零外部调用）
#   - zread.c 内嵌运行时对抗（anti_frida/TracerPid/冻结心跳线程）→ 链接 -lpthread
#   - VMP 流程：-func 一次调用保护三函数（产物自动去符号+节区头重组，跳过 strip）
set -e
SRC="$1"; shift || { echo "用法: bash build_poc.sh <bash-5.2源码目录> [--static] [--aarch64] [--musl] [--vmp] [--keep-xtrace]" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
STATIC=0 AARCH64=0 DO_VMP=0 DO_ANTIDISASM=1 KEEP_DIAG=0 DO_DIAG=0 KEEP_XTRACE=0 MUSL=0 BIONIC=0
# r28（T1.6）：L6 参数密文令牌 + work/ 中间产物保留
DO_L6=1                 # 有业务脚本即令牌化（默认开）
L6_SCRIPT=""            # 业务脚本路径（--l6-script=... 或第 2 位置参数）
L6_SEED=""              # 复现种子（--l6-seed=...）
DO_KEEPWORK=1           # 保留 work/ 各阶段快照（--no-keep-work 关闭）
for a in "$@"; do
  case "$a" in
    --static) STATIC=1;;
    --aarch64) AARCH64=1;;
    # r18：musl 静态线（安卓 app 域可跑，见 R10_CHANGES G.8）。
    #   glibc 静态 bash 在 Termux/应用进程里死于 SIGSYS(31)（rc=159）——
    #   Android O 起 zygote 装 seccomp 白名单，以 bionic SYSCALLS.TXT 为界；
    #   glibc 2.35+ 静态启动会打 rseq（arm64 #293），bionic 不用 → 被拦。
    #   musl 不调 rseq，静态产物在 app 域正常。
    --musl) AARCH64=1; MUSL=1; STATIC=1;;
    # r18：bionic 静态线（安卓真 libc，Termux/app 域天然可跑）。
    #   与 musl 线的区别：musl 只是"不打 rseq"，但若还有别的 syscall 落在
    #   bionic 白名单外照样 SIGSYS；bionic 产物用的就是白名单内那套，根治。
    #   工具链：clang + Android target + NDK sysroot（见脚本注释）。
    --bionic) AARCH64=1; BIONIC=1; STATIC=1;;
    --vmp) DO_VMP=1;;
    --no-anti-disasm) DO_ANTIDISASM=0;;
    --keep-diag) KEEP_DIAG=1;;
    --diag) DO_DIAG=1;;
    --keep-xtrace) KEEP_XTRACE=1;;
    # r28（T1.6）：L6 参数令牌
    --l6-script=*) L6_SCRIPT="${a#--l6-script=}"; DO_L6=1;;
    --l6-seed=*)   L6_SEED="${a#--l6-seed=}";;
    --no-l6)       DO_L6=0;;
    # r28：不保留中间产物（默认保留）
    --no-keep-work) DO_KEEPWORK=0;;
  esac
done
# 便捷写法：第 2 位置参数是文件 → 视作业务脚本
if [ -z "$L6_SCRIPT" ] && [ -n "$1" ] && [ -f "$1" ]; then
  L6_SCRIPT="$1"; shift
fi

# ============================================================================
# r28（T1.6）：work/ 中间产物目录 —— 全链路留档，便于事后排查
#
# 用户要求（原话）：
#   "构建的时候单独在当前目录下创个 work 临时目录，然后把源码→令牌化产物
#    →v6混淆产物→elf产物→最终产物，就是中间的产物全都保留一份，日后好排查错误"
#
# 目录布局（$HERE/work/）：
#   0-meta/      构建参数、工具版本、种子（复现所需的一切）
#   1-source/    上游源码补丁后的关键文件快照（我们动过的那些）
#   2-token/     令牌化产物：L6 表（json/bin）+ 令牌化后的脚本
#   3-v6/        v6 混淆产物（若走 v6 线；由调用方填充）
#   4-elf/       bash.unstripped / .map / 符号快照
#   5-final/     最终产物 + 每步哈希链（sha256），便于定位"哪一步变了"
#
# 设计原则：
#   - **只增不改**：每次构建写同一个 work/，但每阶段覆盖同名文件并追加哈希
#     日志；需要历史时看 5-final/HASHES.txt 的逐行追加即可。
#   - **失败也保留**：脚本用 set -e，但 work/ 已在最早期创建 —— 任何阶段
#     炸掉，此前阶段的产物都在，能直接比对。
#   - 可用 --no-keep-work 关闭（产物大时省空间；默认保留）。
# ============================================================================
WORK="$HERE/work"
if [ "$DO_KEEPWORK" = 1 ]; then
  mkdir -p "$WORK"/{0-meta,1-source,2-token,3-v6,4-elf,5-final}
  _wlog() { echo "[$(date '+%F %T')] $*" >> "$WORK/0-meta/BUILD.log"; }
  _wlog "==================== 新构建 ===================="
  _wlog "ARGS: $*  SRC=$SRC"
  _wlog "FLAGS: STATIC=$STATIC AARCH64=$AARCH64 MUSL=$MUSL BIONIC=$BIONIC DO_VMP=$DO_VMP"
  _wlog "FLAGS: DO_ANTIDISASM=$DO_ANTIDISASM DO_DIAG=$DO_DIAG KEEP_XTRACE=$KEEP_XTRACE"
  _wlog "L6: DO_L6=$DO_L6 SCRIPT=$L6_SCRIPT SEED=$L6_SEED"
  _wlog "HOST: $(uname -a)"
  # 构建参数存档（机器可读，便于复现）
  {
    echo "src=$SRC"
    echo "static=$STATIC aarch64=$AARCH64 musl=$MUSL bionic=$BIONIC"
    echo "vmp=$DO_VMP anti_disasm=$DO_ANTIDISASM diag=$DO_DIAG keep_xtrace=$KEEP_XTRACE"
    echo "l6_enabled=$DO_L6 l6_script=$L6_SCRIPT l6_seed=$L6_SEED"
    echo "date=$(date -Iseconds)"
    echo "host=$(uname -m)"
  } > "$WORK/0-meta/params.txt"
  # 工具指纹（换工具 = 换产物，排查第一件事就是对齐这个）
  {
    echo "## compiler"
    ${V7_CC:-gcc} --version 2>/dev/null | head -1 || echo "(n/a)"
    echo "## python3"
    python3 --version 2>&1
    echo "## 关键脚本 sha256"
    for f in "$HERE"/isa_hook.py "$HERE"/isa_hook.c "$HERE"/v7_builtin_takeover.c \
             "$HERE"/zread.c.v7poc "$HERE"/v7core.c "$HERE"/../../tools/v7_isa.py; do
      [ -f "$f" ] && sha256sum "$f"
    done
  } > "$WORK/0-meta/toolchain.txt" 2>&1
  _wlog "工具指纹 → 0-meta/toolchain.txt"
  # 哈希链日志（每阶段追加）
  HASHLOG="$WORK/5-final/HASHES.txt"
  _hash_step() {   # _hash_step <阶段名> <文件...>
    local tag="$1"; shift
    {
      echo "---- [$tag] $(date '+%F %T') ----"
      for f in "$@"; do
        # 容错：沙箱 overlay 在高频写后有偶发 EIO，不能让它把构建打断。
        # 失败只是这一步没记上哈希，产物本身不受影响。
        [ -f "$f" ] && sha256sum "$f" 2>/dev/null || true
      done
    } >> "$HASHLOG" 2>/dev/null || true
  }
else
  _wlog() { :; }
  _hash_step() { :; }
fi

# r28：容错拷贝 —— 沙箱 overlay 在高频写入后偶发 EIO；留档失败不该中断构建
# （产物在 $SRC 侧，与 work/ 无关）。失败时记一行日志，继续。
_wcp() {   # _wcp <源> <目标目录>
  [ -f "$1" ] || return 0
  cp "$1" "$2/" 2>/dev/null || { _wlog "WARN: 拷贝失败 $1 → $2（I/O）"; return 0; }
  return 0
}

# r18：目标架构是否为 aarch64（交叉目标 或 宿主本身就是 arm64，如 Termux）。
# VMP 的 V7CORE_FLAGS（禁 NEON / 禁尾跳 / 禁块重排）对两者都需要。
case "$(uname -m)" in aarch64|arm64) _vmarm=1 ;; *) _vmarm=0 ;; esac
[ "$AARCH64" = 1 ] && _vmarm=1

[ -d "$SRC" ] || { echo "源码目录不存在: $SRC" >&2; exit 1; }
[ -f "$SRC/lib/sh/zread.c" ] || { echo "不是 bash 源码目录（缺 lib/sh/zread.c）" >&2; exit 1; }

if [ "$DO_VMP" = 1 ]; then
  # r18：VMP 需要 aarch64 —— 交叉目标或**宿主本身**是 aarch64 都算
  # （Termux 本机就是 arm64，本机构建同样可以上 VMP）。
  case "$(uname -m)" in aarch64|arm64) _vmarm=1 ;; *) _vmarm=0 ;; esac
  [ "$AARCH64" = 1 ] && _vmarm=1
  [ "$_vmarm" = 1 ] || { echo "错误：--vmp 仅支持 aarch64（VMPacker 限制）" >&2; exit 1; }
  VMPACKER_BIN="${VMPACKER:-/tmp/vmp/VMPacker-master/build/vmpacker}"
  [ -x "$VMPACKER_BIN" ] || { echo "错误：VMPacker 不可执行: $VMPACKER_BIN" >&2; exit 1; }
  # 对齐路线 A：VMP 构建定义 V7_VMP_BUILD=1 → zread.c 关闭反调试④
  # 启动时间窗（VM 解释慢与调试停顿不可区分，见 zread.c.v7poc 顶部说明）
  VMP_DEFS="-DV7_VMP_BUILD=1"
else
  VMP_DEFS=""
fi

# 诊断版（--diag）：定义 V7_DIAG → zread 内输出阶段进度与拒绝原因。
# 生产构建不定义 → 诊断代码与 V7DIAG 串整体不生成（strings 零残留）。
if [ "$DO_DIAG" = 1 ]; then
  VMP_DEFS="$VMP_DEFS -DV7_DIAG"
fi

# r15：xtrace 能力移除（默认开）。--keep-xtrace 时定义 V7_KEEP_XTRACE，
# 让 xtrace_kill.py 插进去的 return 失效 —— 供依赖 `set -x` 做日志的脚本使用。
if [ "$KEEP_XTRACE" = 1 ]; then
  VMP_DEFS="$VMP_DEFS -DV7_KEEP_XTRACE"
fi

echo ">> 替换 zread.c / v7core.c / crypto_core.h"
cp "$HERE/zread.c.v7poc" "$SRC/lib/sh/zread.c"
cp "$HERE/v7core.c"      "$SRC/lib/sh/v7core.c"
cp "$HERE/isa_hook.c"    "$SRC/lib/sh/isa_hook.c"
# r27（ShellVMP T1）：自定义 builtin 接管。劫持 shell_builtins[].function，
# 让输出型命令走我们的 C 实现（参数解密 + 直写 fd）。fail-closed，无 L6
# 表时零接管。它依赖 isa_hook.c 的 v7_isa_param_decode / _has_param_table。
cp "$HERE/v7_builtin_takeover.c" "$SRC/lib/sh/v7_builtin_takeover.c"
# r29（ShellVMP T2）：抗 dump 加固（PR_SET_DUMPABLE + seccomp-BPF + 页锁）。
# 独立编译单元：不链 libseccomp（安卓 NDK 无此库），手写 BPF 字节码。
# 由 shell.c 在 shell_initialize() 之后调用（见 isa_hook.py 的 SC_NEW）。
cp "$HERE/v7_harden.c" "$SRC/lib/sh/v7_harden.c"
# r20：第二层符号表（sym id → 真名）。isa_hook.c 用 #include "v7_isa_syms.h"，
# 必须与它同目录。缺失时现场从 tools/v7_isa.py 生成，保证顺序与生成器一致。
if [ ! -f "$HERE/v7_isa_syms.h" ]; then
    python3 "$HERE/../../tools/v7_isa.py" emit-c -o "$HERE/v7_isa_syms.h" \
        || { echo "错误：无法生成 v7_isa_syms.h" >&2; exit 1; }
fi
cp "$HERE/v7_isa_syms.h" "$SRC/lib/sh/v7_isa_syms.h"
# r21：表加密主密钥。与 v7_isa_syms.h 同批：不存在才生成，之后固定 ——
# 换掉它 = 换密钥 = 既有表全部作废（解密失败 → ISA 静默空转，产物仍可跑）。
if [ ! -f "$HERE/v7_isa_key.h" ]; then
    python3 "$HERE/../../tools/v7_isa.py" emit-key -o "$HERE/v7_isa_key.h" \
        || { echo "错误：无法生成 v7_isa_key.h" >&2; exit 1; }
    echo "信息：已生成新主密钥 v7_isa_key.h（既有 ISA 表将全部作废，需重新 gen）"
fi
cp "$HERE/v7_isa_key.h" "$SRC/lib/sh/v7_isa_key.h"
cp "$HERE/../crypto_core.h" "$SRC/lib/sh/crypto_core.h"
# VMP 定位需求：crypto_core.h 里 5 个目标函数是 static（local 符号），
# VMPacker -func 找不到。仅对【副本】去掉这 5 处 static（A 的原始头不动）。
# r21：isa_hook.c 需要 HMAC/流密码，但它**不能**用上面这份去掉 static 的
# crypto_core.h —— 那 5 个函数会被 sed 改成全局符号，v7core.o 与 isa_hook.o
# 各导出一份 → ld.lld "duplicate symbol"（实测报 5 条，链接直接失败）。
# 故另存一份**保留 static** 的副本 crypto_isa.h 专供 isa_hook.c：两份代码
# 各自编译成 local 符号，互不撞车；改动也互不影响（表解密链独立于载荷解密链）。
# 落在 $HERE（bash_poc/）而非只落 $SRC：这样 tools/isa_v3_selftest.c 这类
# 独立自检也能直接 -I bash_poc 编译，不必先跑一遍完整构建。
sed 's/CRYPTO_CORE_H/CRYPTO_CORE_ISA_H/' "$HERE/../crypto_core.h" \
    > "$HERE/crypto_isa.h"
cp "$HERE/crypto_isa.h" "$SRC/lib/sh/crypto_isa.h"
sed -i -e 's/^V7_NOINLINE_ATTR static void v7_keys(/V7_NOINLINE_ATTR void v7_keys(/' \
       -e 's/^V7_NOINLINE_ATTR static void v7_keystream(/V7_NOINLINE_ATTR void v7_keystream(/' \
       -e 's/^V7_NOINLINE_ATTR static int v7_scrypt_kdf(/V7_NOINLINE_ATTR int v7_scrypt_kdf(/' \
       -e 's/^V7_NOINLINE_ATTR static void v7_tag(/V7_NOINLINE_ATTR void v7_tag(/' \
       -e 's/^V7_NOINLINE_ATTR static void v7_wb_decode(/V7_NOINLINE_ATTR void v7_wb_decode(/' \
       "$SRC/lib/sh/crypto_core.h"

# ---- r15：patch bash 上游源码（必须早于 configure/make）------------------
# 两处改的都是【源码树副本】且脚本幂等，重复构建不会叠加。
# 失败即中止：宁可构建失败，也不要产出「以为保护了其实没保护」的产物。
echo ">> r15：patch 上游源码（xtrace/verbose 输出能力 / BASH_ENV 注入点 / getcwd 报错）"
if [ "$KEEP_XTRACE" = 1 ]; then
  echo "   已按 --keep-xtrace 保留全部调试回显与 BASH_ENV（跳过 patch）"
else
  python3 "$HERE/xtrace_kill.py" \
    "$SRC/print_cmd.c" "$SRC/y.tab.c" "$SRC/make_cmd.c" "$SRC/shell.c" \
    || { echo "错误：调试通道剥离失败（bash 源码结构不符预期？）" >&2; exit 1; }
fi
python3 "$HERE/getcwd_quiet.py" "$SRC/builtins/common.c" \
  || { echo "错误：getcwd 静默失败（builtins/common.c 结构不符预期？）" >&2; exit 1; }

# ---- r16：ISA 表 hook 插桩（命令词/保留字/位置参数翻译，见 isa_hook.c/py）----
# r17：恢复启用（此前被临时注释 → 从**干净源树**构建出的 bash 根本没有
# v7_isa_translate_* 调用点，isa_hook.c 白编译、四层随机化静默失效）。
# isa_hook.py 自身幂等（新形态已在文中即跳过），故重复构建安全。
echo ">> r16：patch 上游源码（ISA 命令词 / 保留字 / 位置参数翻译 hook）"
python3 "$HERE/isa_hook.py" "$SRC/execute_cmd.c" "$SRC/y.tab.c" "$SRC/variables.c" \
  "$SRC/shell.c" \
  || { echo "错误：ISA hook 插桩失败（bash 源码结构不符预期？）" >&2; exit 1; }

# ---- r28（T1.6）：1-source 快照（补丁后的关键文件）------------------------
# 这里存的是**我们自己动过的**源文件（不是整棵树，那太大且无信息量）。
# 排查时最常问"插桩到底进去了没" —— 直接看这里，比翻 $SRC 快。
if [ "$DO_KEEPWORK" = 1 ]; then
  for f in execute_cmd.c y.tab.c variables.c shell.c; do
    _wcp "$SRC/$f" "$WORK/1-source"
  done
  for f in zread.c v7core.c isa_hook.c v7_builtin_takeover.c v7_harden.c \
           crypto_core.h crypto_isa.h v7_isa_syms.h v7_isa_key.h; do
    _wcp "$SRC/lib/sh/$f" "$WORK/1-source"
  done
  _hash_step "1-source" "$WORK"/1-source/*
  _wlog "1-source 快照完成（$(ls -1 "$WORK/1-source" | wc -l) 个文件）"
fi

# ---- r28（T1.6）：2-token 阶段 —— L6 参数密文令牌 -------------------------
# 流程：业务脚本 → 提取静态字符串 → 生成 L6 表（加密 .bin + 明文 .json）
#       → 改写器把脚本里的字面量换成令牌 → 令牌化脚本。
# 令牌化脚本的用法（两种，均可）：
#   a) 嵌入：python3 v7_embed.py <令牌化脚本> <bash产物> <输出> --pass 口令
#   b) 直跑：V7_ISA_TABLE=<L6表.bin> <bash产物> <令牌化脚本>
# 注意：L6 表路径通过环境变量 V7_ISA_TABLE 传给产物（isa_hook.c 读取）。
if [ "$DO_L6" = 1 ] && [ -n "$L6_SCRIPT" ]; then
  echo ">> r28：L6 参数令牌化（业务脚本: $L6_SCRIPT）"
  [ -f "$L6_SCRIPT" ] || { echo "错误：业务脚本不存在: $L6_SCRIPT" >&2; exit 1; }
  L6_BIN="$HERE/v7_l6_param.bin"
  L6_JSON="$HERE/v7_l6_param.json"
  L6_OUT="${L6_SCRIPT%.sh}.masked.sh"
  _gen_args=(gen-param --in "$L6_SCRIPT" -o "$L6_BIN" --json "$L6_JSON")
  [ -n "$L6_SEED" ] && _gen_args+=(--seed "$L6_SEED")
  python3 "$HERE/../../tools/v7_isa.py" "${_gen_args[@]}" \
    || { echo "错误：L6 表生成失败" >&2; exit 1; }
  python3 "$HERE/../../tools/v7_isa.py" rewrite-param \
      --table "$L6_JSON" --in "$L6_SCRIPT" --out "$L6_OUT" \
    || { echo "错误：L6 脚本改写失败" >&2; exit 1; }
  echo "   令牌化脚本: $L6_OUT"
  echo "   L6 表:      $L6_BIN（环境变量 V7_ISA_TABLE 指向它）"
  if [ "$DO_KEEPWORK" = 1 ]; then
    _wcp "$L6_BIN"  "$WORK/2-token"
    _wcp "$L6_JSON" "$WORK/2-token"
    _wcp "$L6_OUT"  "$WORK/2-token"
    _wcp "$L6_SCRIPT" "$WORK/2-token"
    [ -f "$WORK/2-token/$(basename "$L6_SCRIPT")" ] && \
      mv "$WORK/2-token/$(basename "$L6_SCRIPT")" "$WORK/2-token/source.sh" 2>/dev/null || true
    _hash_step "2-token" "$WORK"/2-token/*
    _wlog "2-token 完成（令牌 $(python3 -c "import json,sys;d=json.load(open('$L6_JSON'));print(len(d.get('table',[])))" 2>/dev/null || echo '?') 条）"
  fi
elif [ "$DO_L6" = 1 ]; then
  echo ">> r28：未指定业务脚本（--l6-script=...），跳过 L6 令牌化"
  echo "   产物仍可用，但 echo 等命令不会被接管（行为同普通魔改 bash）"
fi

# 记录 ISA 基础表（L1-L5）状态 —— 与 L6 是两张独立的表，别混

cd "$SRC"
echo ">> configure"
CONF_FLAGS="--disable-readline --disable-nls --without-bash-malloc"
# gcc>=10 默认 -fno-common：signames.o(support/signames.c) 与 trap.o(生成的
# signames.h 内定义) 的 signal_names 会报 multiple definition，静态链接必挂。
# 追加 -fcommon 恢复 common 符号合并（见 README「构建」一节）。
# r18：CC_BIN 可用 V7_CC 覆盖 —— Termux 本机构建时 cc 是 clang（没有 gcc），
# 且本机构建不需要 --host（宿主即目标），产物链接 bionic，在 app 域不会被
# seccomp 拦（bionic 只用白名单内的 syscall）。
CC_BIN="${V7_CC:-gcc}"
if [ "$STATIC" = 1 ]; then CONF_FLAGS="--enable-static-link $CONF_FLAGS"; fi
if [ "$MUSL" = 1 ]; then
  # musl 交叉线：工具链来自 musl.cc（aarch64-linux-musl-cross）；可用
  # MUSL_CC 覆盖路径。host triplet 带 -musl，且强制静态（musl 静态产物
  # 才能在安卓 app 域跑；动态 musl 需要目标机有 ld-musl-aarch64.so.1）。
  CC_BIN="${MUSL_CC:-aarch64-linux-musl-gcc}"
  command -v "$CC_BIN" >/dev/null 2>&1 || [ -x "$CC_BIN" ] \
    || { echo "错误：找不到 musl 交叉编译器: $CC_BIN（用 MUSL_CC=路径 指定）" >&2; exit 1; }
  CONF_FLAGS="--host=aarch64-linux-musl $CONF_FLAGS"
elif [ "$BIONIC" = 1 ]; then
  # bionic 线：Android NDK sysroot（bionic 头 + libc.a）。环境搭建见
  # R10_CHANGES G.9；编译器是 wrapper（clang + --target + --sysroot + lld）。
  CC_BIN="${BIONIC_CC:-aarch64-linux-android-clang}"
  command -v "$CC_BIN" >/dev/null 2>&1 || [ -x "$CC_BIN" ] \
    || { echo "错误：找不到 bionic 交叉编译器: $CC_BIN（用 BIONIC_CC=路径 指定）" >&2; exit 1; }
  CONF_FLAGS="--host=aarch64-linux-android $CONF_FLAGS"
elif [ "$AARCH64" = 1 ]; then
  CC_BIN="aarch64-linux-gnu-gcc"
  CONF_FLAGS="--host=aarch64-linux-gnu $CONF_FLAGS"
fi

# r14 修复：configure 若发现源码树里已有 config.status，且命令行参数与
# 记录的一致，会**直接复用、跳过重新配置**。后果：在已配置过的树里追加
# `--aarch64` 会被静默忽略 —— 实测 `file` 仍报 x86-64、`CC = gcc`、
# `config.status` 里 host 仍是 x86_64-pc-linux-gnu，即"以为交叉编译了，
# 实际产出的是宿主架构产物"（比报错更危险：产物架构错却不报错）。
# 处置：每次构建前清掉 configure 产物，强制按本次参数重新配置。
# 注意只删 configure 生成物，源码/补丁/上次编译的 .o 不受影响（.o 会被 make 覆盖）。
rm -f config.status config.log config.cache
CC="$CC_BIN" ./configure $CONF_FLAGS CFLAGS="-g -O2 -fcommon $VMP_DEFS"

# r14 断言：交叉编译标志必须真的生效 —— 防止上面那类"静默降级"再次溜过。
if [ "$AARCH64" = 1 ]; then
  if ! grep -q 'aarch64' config.status 2>/dev/null; then
    echo "错误：--aarch64 未生效（config.status 中无 aarch64）—— 中止以免产出宿主架构产物" >&2
    exit 1
  fi
fi

# r14 修复：原生（非交叉）x86_64 构建下 configure 的 cross_compiling=no，
# 于是 `SIGNAMES_O` 为空 —— 但 signames.h 生成的 lsignames.h 只**声明**
# `signal_names` / `initialize_signames`，定义在 support/signames.c 里。
# 空 SIGNAMES_O 会让 trap.o 的两个符号在链接期未定义（回归发现：
# x86_64 原生路径从未被端到端跑过，一直只走 aarch64 交叉）。交叉编译时
# configure 会自己设 SIGNAMES_O='signames.o'，故 aarch64 路径无症状。
# 这里无条件补齐（signames.o 对两种路径都正确；-fcommon 已处理 its.o 等
# 自带 signal_names 定义时的 multiple definition）。
if ! grep -q '^SIGNAMES_O = signames.o' Makefile; then
    echo ">> 修复 SIGNAMES_O（原生构建链接缺口：initialize_signames / signal_names）"
    sed -i 's|^SIGNAMES_O = *$|SIGNAMES_O = signames.o|' Makefile
    grep -q '^SIGNAMES_O = signames.o' Makefile \
      || { echo "错误：SIGNAMES_O 修复失败（Makefile 形态已变，请检查）" >&2; exit 1; }
fi

# r18：musl 静态链接去重。
#   交叉编译时 configure 无法运行测试程序，保守启用 REPLACE_STRTOIMAX 等，
#   把 bash 自带的 strtoimax.o 编进 libsh.a；动态链接时与 libc 同名符号
#   相安无事（glibc 交叉线一直这么过），**静态**链接 musl 的 libc.a 则
#   直接撞 multiple definition。这些 .o 提供的都是标准 C 函数，musl 自身
#   实现完备，用系统实现即可 —— 从 LIBOBJS 摘掉冲突项。
if [ "$MUSL" = 1 ] || [ "$BIONIC" = 1 ]; then
  if [ "$MUSL" = 1 ]; then _lname="musl"; else _lname="bionic"; fi
  echo ">> $_lname 静态：摘除与 libc.a 重名的 libsh 替换实现"
  sed -i 's/ \${LIBOBJDIR}strtoimax\$U\.o//' lib/sh/Makefile
  grep -q 'strtoimax\$U.o' lib/sh/Makefile && \
    { echo "错误：LIBOBJS 摘除失败（lib/sh/Makefile 形态已变）" >&2; exit 1; }
  # r18：musl 的 crt/链接脚本不产生任何 .note.* 节 → ELF 里**没有 PT_NOTE 段**，
  # 而 VMPacker 以 PT_NOTE 为注入锚点（实测报 `injection failed: PT_NOTE
  # segment not found`）。加 --build-id 让链接器生成 .note.gnu.build-id，
  # 从而带出一个 PT_NOTE（内容无意义，只作锚点）。
  sed -i 's/^LDFLAGS = \(.*\)$/LDFLAGS = \1 -Wl,--build-id=sha1/' Makefile
  grep -q -- '--build-id=sha1' Makefile || \
    { echo "错误：PT_NOTE 锚点注入失败（Makefile 形态已变）" >&2; exit 1; }
fi

# r18：bionic 专用 —— 补 __getauxval shim。
#   沙箱没有 Android 版 compiler-rt，链接时借用 glibc 交叉工具链的 libgcc.a
#   （架构相同、与 libc 无关），但其中的 lse-init.o 引用 __getauxval，而
#   bionic 只提供不带下划线的 getauxval。补一个转发实现即可。
if [ "$BIONIC" = 1 ]; then
  # shim 已合并进 libgcc 副本，wrapper 的 -L/opt/bionic-shim 会优先命中它，
  # 因此链接顺序无关，configure 的裸编译测试也能过（显式加 .o 反而过不了）。
  # r33e.3：真机 Termux 本机构建（BIONIC_CC=clang）无 /opt 且本机 clang 自带
  #   android 版 compiler-rt（无 __getauxval 缺口）—— /opt 不存在时跳过检查，
  #   shim 仅沙箱 x86 交叉线（wrapper -L 引用方）需要。
  if [ -f /opt/bionic-shim/libgcc.a ]; then
    echo ">> bionic：libgcc shim 校验通过（/opt/bionic-shim/libgcc.a）"
  elif [ -d /opt ]; then
    echo "错误：缺 /opt/bionic-shim/libgcc.a（含 __getauxval shim，见 R10_CHANGES G.9）" >&2
    exit 1
  else
    echo ">> bionic：无 /opt（Termux 本机线），跳过 shim（本机 compiler-rt 自足）"
  fi
fi

echo ">> 注入 v7core 构建规则（VMP 目标单元 + pthread 链接）"
# VMP 目标单元专用 flags：全 GPR（VM 无 NEON 寄存器文件）+ 禁尾跳（函数区间闭合）
if [ "$AARCH64" = 1 ] || [ "$_vmarm" = 1 ]; then
  # 对齐路线 A 的 NOFP_WANT 三件套（v7_build.sh:76）：
  #   -mgeneral-regs-only            : 禁 NEON/FP（VMPacker 的 VM 只有 GPR）
  #   -fno-optimize-sibling-calls    : 禁尾调用（尾跳会跳出函数区间，VMPacker 拒）
  #   -fno-reorder-blocks-and-partition : 禁块重排（热点/冷块分裂会产生
  #                                      跨区间分支，VMPacker 报"分支目标未找到"）
  # 前两项 r12 已有；第三项 r13 补，用于把 v7_scrypt_kdf 等函数也纳入可保护面。
  #   r18：clang 不认 GCC 专有的 -fno-reorder-blocks-and-partition 与
  #   -fno-ipa-cp-clone（bionic 线用 clang，会直接报 unknown argument 编译失败），
  #   故按编译器分流，clang 侧用其支持的等价项。
  case "$CC_BIN" in
    *clang*)
      _v7f="-mgeneral-regs-only -fno-optimize-sibling-calls -fno-reorder-blocks"
      # r33：V7CORE_FLAGS 补 -fno-inline —— 【V7_SELF 口令模式在 VMP 下静默算错】
      #   的根因修复。crypto_core.h 由 v7core.c include，v7_scrypt_kdf 落在这个
      #   TU；此前 V7CORE_FLAGS 唯独缺 -fno-inline，clang -O2 便把
      #   scrypt_romix / scrypt_blockmix / hmac_sha256 全部内联进来，函数体膨胀。
      #   后果分两种，取决于是否同时开了 -mgeneral-regs-only：
      #     ① 开了（本脚本现状）→ 无 SIMD 指令，VMPacker 不报错、顺利产出，
      #        但翻译后语义错误 → scrypt 算出错误 seed → tag 校验失败
      #        → exit(114)，且**日志无任何告警**（最难排查的一类）；
      #     ② 不开 → 内联进来的 memcpy/hmac 让 clang 用上 NEON 寄存器对
      #        （stp qN，指令字 0xAD...）→ VMPacker 明确报
      #        "60 unsupported instruction(s) ... cannot produce safe output"。
      #   判据：离线模式（走 wb_decode、不调 scrypt）VMP 前后完全一致，
      #        口令模式 VMP 后必 114 ⇒ 唯一变量就是 v7_scrypt_kdf。
      #   这与 r32 修 V7_BT_FLAGS 是**同一个坑的第二次发生**：那次是符号被内联
      #   消失（能被符号断言抓到），这次是算错（断言抓不到，只能靠端到端）。
      V7CORE_FLAGS="$_v7f -fno-inline"
      ISA_HOOK_FLAGS="$_v7f -fno-inline"
      # r32：V7_BT_FLAGS 补 -fno-inline。实测 aarch64-bionic/clang 会把
      #   v7_harden.c 里的 static v7_seccomp_deny_readers 内联进
      #   v7_harden_install → 符号表消失 → VMP 断言失败（保护面静默缺项）。
      #   v7_builtin_takeover.c 同用此 flags，一并受益。
      V7_BT_FLAGS="$_v7f -fno-inline"
      ;;
    *)
      V7CORE_FLAGS="-mgeneral-regs-only -fno-optimize-sibling-calls -fno-reorder-blocks-and-partition -fno-inline"
      ISA_HOOK_FLAGS="$V7CORE_FLAGS -fno-ipa-cp-clone"
      V7_BT_FLAGS="$V7CORE_FLAGS -fno-ipa-cp-clone"
      ;;
  esac
else
  V7CORE_FLAGS=""   # x86_64 开发路径不做 VMP，flags 留空
  ISA_HOOK_FLAGS=""
  V7_BT_FLAGS=""
fi
# 1) 对象列表挂 v7core.o（r16 追加 isa_hook.o；r28 追加 v7_builtin_takeover.o；
#    r29 追加 v7_harden.o）
sed -i 's|itos.o zread.o zwrite.o shtty.o shmatch.o eaccess.o \\|itos.o zread.o zwrite.o shtty.o shmatch.o eaccess.o v7core.o isa_hook.o v7_builtin_takeover.o v7_harden.o \\|' lib/sh/Makefile
# 2) 编译规则（target-specific flags 经占位注入）
sed -i "s|^zread.o: zread.c\$|zread.o: zread.c v7core.c\nv7core.o: v7core.c\n\t\$(CC) \$(CCFLAGS) ${V7CORE_FLAGS} -c \$(srcdir)/v7core.c\nisa_hook.o: isa_hook.c\n\t\$(CC) \$(CCFLAGS) ${ISA_HOOK_FLAGS} -c \$(srcdir)/isa_hook.c\nv7_builtin_takeover.o: v7_builtin_takeover.c\n\t\$(CC) \$(CCFLAGS) ${V7_BT_FLAGS} -c \$(srcdir)/v7_builtin_takeover.c\nv7_harden.o: v7_harden.c\n\t\$(CC) \$(CCFLAGS) ${V7_BT_FLAGS} -c \$(srcdir)/v7_harden.c|" lib/sh/Makefile
# 2b) r28/r29 兜底：老树（已被手工挂过）重跑时，上面的 sed 锚点已不匹配
#     （对象列表里已有该项）→ 缺编译规则会报 "no rule to make target"。
#     显式断言三条规则都在，缺则补。
grep -q '^isa_hook.o: isa_hook.c' lib/sh/Makefile \
  || { echo "错误：isa_hook.o 编译规则缺失（lib/sh/Makefile 形态已变）" >&2; exit 1; }
grep -q '^v7_builtin_takeover.o: v7_builtin_takeover.c' lib/sh/Makefile \
  || { echo "错误：v7_builtin_takeover.o 编译规则缺失" >&2; exit 1; }
grep -q '^v7_harden.o: v7_harden.c' lib/sh/Makefile \
  || { echo "错误：v7_harden.o 编译规则缺失" >&2; exit 1; }
# 3) 链接 -lpthread（心跳线程；bionic 下为无害 no-op）
#    r17：原生构建追加 -lcrypto —— v6openssl builtin 用 OpenSSL EVP/PBKDF2，
#    其目标文件在 libbuiltins.a 里、链接顺序早于 LIBS，故 -lcrypto 必须在末尾。
#    交叉构建不加：该 builtin 被跳过（见下方 r17 说明），且 aarch64 无 libcrypto
#    可用（`cannot find -lcrypto`）—— 硬加会直接把交叉线拦在链接期。
if [ "$AARCH64" = 1 ]; then
  sed -i 's|^LIBS = .*@LIBS@.*|LIBS = $(BUILTINS_LIB) $(LIBRARIES) @LIBS@ -lpthread|' Makefile
  grep -q "^LIBS = .*-lpthread" Makefile || sed -i 's|^LIBS = \(.*\)$|LIBS = \1 -lpthread|' Makefile
else
  sed -i 's|^LIBS = .*@LIBS@.*|LIBS = $(BUILTINS_LIB) $(LIBRARIES) @LIBS@ -lpthread -lcrypto|' Makefile
  grep -q "^LIBS = .*-lpthread" Makefile || sed -i 's|^LIBS = \(.*\)$|LIBS = \1 -lpthread -lcrypto|' Makefile
  # 已存在但缺 -lcrypto 的树（或手工改过的树）：补上，幂等
  grep -q -- "-lcrypto" Makefile || sed -i 's|^LIBS = \(.*\)$|LIBS = \1 -lcrypto|' Makefile
fi

# r17：v6openssl builtin 的取舍。
#   【现状】`builtins/v6openssl.def` 把 OpenSSL EVP/PBKDF2 内建化，但经核查
#   **V6 混淆器从未调用它** —— `shell_script_obfuscator_v6.sh` 的 aes 线走的是
#   外部 `openssl` 命令（`OPENSSL_BIN=$(command -v openssl)`，见其 L1444）。
#   即该 builtin 目前是**死代码**。
#   【阻塞】它 `#include <openssl/evp.h>`，而 `opensslconf.h` 是**架构专属**头
#   （宿主在 /usr/include/x86_64-linux-gnu/openssl/）。交叉到 aarch64 时没有
#   对应的 libssl-dev:arm64 包 ⇒ 编译期 fatal error，整条 aarch64 线卡死。
#   【处置】仅在原生（非交叉）构建时注入，保证 x86 行为与既有验收完全一致；
#   交叉构建跳过（省一个死代码，且免装 arm64 openssl 开发包）。
#   如需在 aarch64 上恢复，装 `libssl-dev:arm64` 后把条件去掉即可。
if [ "$AARCH64" = 1 ]; then
  echo ">> 跳过 v6openssl builtin（交叉构建；该 builtin 未被 V6 使用，见脚本注释）"
else
  echo ">> 注入 v6openssl builtin（r12 步骤 6：V6 层 AES-256-CTR + PBKDF2-HMAC-SHA512）"
  cp "$HERE/v6openssl.def" builtins/v6openssl.def
  # DEFSRC：mkbuiltins 扫描注册 builtin（builtin 名 openssl，V6 产物运行期自动路由）
  sed -i 's|complete\.def \$(srcdir)/mapfile\.def|complete.def $(srcdir)/mapfile.def $(srcdir)/v6openssl.def|' builtins/Makefile
  grep -q "v6openssl.def" builtins/Makefile || { echo "错误：DEFSRC 注入失败" >&2; exit 1; }
  # OFILES：编译进 libbuiltins.a
  sed -i 's|bashgetopt\.o complete\.o|bashgetopt.o complete.o v6openssl.o|' builtins/Makefile
  grep -q "v6openssl.o" builtins/Makefile || { echo "错误：OFILES 注入失败" >&2; exit 1; }
fi

echo ">> make"
make -j"$(nproc 2>/dev/null || echo 4)"

cp bash bash.unstripped

# r13：导出符号表快照（.map），供 vmp_apply.py --verify 逐函数裁剪使用。
# 与 A 线同格式（"0x地址 名字"），由 tools/vmp_apply.py 读取定位候选函数。
# 本地排障/加固用，勿随发行版分发。
echo ">> 导出符号表快照（供 vmp_apply.py --verify 使用）"
if command -v readelf >/dev/null 2>&1; then
  readelf -sW bash.unstripped 2>/dev/null \
    | awk '$4=="FUNC" && $8!="" {print "0x" $2, $8}' > bash.unstripped.map 2>/dev/null
elif command -v nm >/dev/null 2>&1; then
  nm -S --defined-only bash.unstripped 2>/dev/null \
    | awk '$2=="T"||$2=="t"{print "0x"$1, $2, $4}' > bash.unstripped.map 2>/dev/null
fi
if [ -s bash.unstripped.map ]; then
  echo ">> 符号表快照: $SRC/bash.unstripped.map（$(wc -l < bash.unstripped.map) 条）"
  echo "   VMP 逐函数裁剪: python3 <包>/tools/vmp_apply.py <产物> --verify --map $SRC/bash.unstripped.map -o <输出>"
else
  rm -f bash.unstripped.map
  echo ">> 提示：未能导出符号表（无 readelf/nm），--verify 将不可用" >&2
fi

if [ "$DO_VMP" = 1 ]; then
  # ===== VMP 保护面（单一真源）=====
  # 逐个函数列在下面，注释给出"为什么它必须被保护"——便于评审时不漏项。
  # 原则：凡是【持有密钥 / 持有明文 / 执行翻译 / 判定接管 / 阻断读内存】的函数
  #       都必须在保护面内；其余（如 v7_harden_disabled 这类纯开关读数、
  #       v7_bt_wipe 这类无密钥的擦除工具）风险等级低，不进保护面以免
  #       目标膨胀拖慢构建。
  VMP_FUNCS=""
  _vmp_add() {   # $1=函数名 $2=理由（仅注释用）
    if [ -z "$VMP_FUNCS" ]; then VMP_FUNCS="$1"; else VMP_FUNCS="$VMP_FUNCS,$1"; fi
  }
  # --- r12：白盒密码核心（5）---
  _vmp_add v7_scrypt_kdf   "KDF"
  _vmp_add v7_keys         "主密钥派生"
  _vmp_add v7_keystream    "流密钥"
  _vmp_add v7_tag          "完整性标签"
  _vmp_add v7_wb_decode    "白盒解码"
  # --- r16：ISA 表翻译中枢（3）---
  _vmp_add v7_isa_init          "表装载"
  _vmp_add v7_isa_translate_cmd "L1 命令名翻译"
  _vmp_add v7_isa_translate_kw  "L2 关键字翻译"
  # --- r21：表主密钥链（2）---
  _vmp_add v7_isa_master "表主密钥"
  _vmp_add v7_isa_derive "表派生"
  # --- r28（T1.6）：L6 参数解密（1）—— 【r32 暂禁，见下】---
  # ⚠️ 已知缺陷（r32）：v7_isa_param_decode 保护后在 aarch64 下输出多 1 字节
  #   （每行尾多 0xA4），无 VMP 时完全正常 ⇒ VMPacker 翻译语义错误。
  #   ② 局部数组取地址传参 —— 把解密循环拆成外部 v7_isa_param_crypt()；
  #   ③ 函数体过大 —— 392B(98 指令) → 240B(60) → **140B(35 指令)** 仍复现，
  #      而同样手法瘦到 192B(48 指令) 的 translate_paths 已修复 ⇒ **大小不是
  #      根因**，不要再往这个方向投入。
  #   ⇒ 根因仍在 VMPacker 译码器内部。当前按"剔除"处理。
  #   注意 x86 路径从不走 VMP，故此缺陷只在 aarch64 产物暴露。
  #   _vmp_add v7_isa_param_decode "L6 参数解密【暂禁：VMP 翻译缺陷】"
  # --- r29（T2）：抗 dump 唯一确定性手段（1）---
  _vmp_add v7_seccomp_deny_readers "seccomp 断读（patch 掉即整层失效）"
  # --- r32：保护面补全（4）---
  # v7_echo_builtin 是 L6 令牌的【实际执行者】：它调 v7_isa_param_decode、
  #   在栈上持有明文、并负责擦除。此前只保护了 decode 而漏了调用者——
  #   patch 掉 v7_echo_builtin 直接 return 原串，即可让 L6 全线旁路。
  _vmp_add v7_echo_builtin        "L6 令牌解密执行者（持有栈上明文）"
  # L4/L5 翻译此前漏保护，而 L1/L2/L3 的 _cmd/_kw 已保护 → 保护面不一致。
  #   变量名与路径的翻译同样是"令牌→真名"的映射，拿到即等于明文。
  _vmp_add v7_isa_translate_var   "L4 变量名翻译"
  # r32 修复：把串构造拆成外部函数 v7_isa_path_step()（不在保护面内），
  #   本函数从 388B/97 指令瘦到 192B/48 指令后 VMP 保护正常
  #   （此前 388B 时必 SIGSEGV）。见 isa_hook.c 中该函数的注释。
  _vmp_add v7_isa_translate_paths "L5 路径翻译（r32 已瘦身修复）"
  # builtin 接管的唯一判据：patch 成恒 0 → 整套命令接管被关闭 → L6 失效。
  _vmp_add v7_isa_has_param_table "builtin 接管判据（patch 成 0 即关接管）"

  echo ">> VMPacker 保护面（r12 起累积，本版 $(awk -F, '{print NF}' <<<"$VMP_FUNCS") 个函数）："
  echo "   r12 白盒密码核心 5 / r16 ISA 翻译中枢 3 / r21 表主密钥链 2 / r32 暂禁 1（param_decode）"
  echo "   r28 L6 参数解密 0（暂禁）/ r29 seccomp 断读 1 / r32 补全 4（含 paths 瘦身修复）"
  echo "   实测 -O2 会把 static isa_load 内联拆分致拒保，各 *_FLAGS 的"
  echo "   -fno-inline 已解。"

  # ===== 断言：每个待保护函数必须真实存在于 unstripped 符号表 =====
  # 防两类静默失败：①拼错函数名；②编译期被内联/优化掉（-func 找不到时
  # VMPacker 可能只警告不报错）→ 保护面悄悄缺项。
  if [ -s bash.unstripped.map ]; then
    _vmp_missing=""
    for _f in $(tr ',' ' ' <<<"$VMP_FUNCS"); do
      grep -q "[[:space:]]$_f\$" bash.unstripped.map || _vmp_missing="$_vmp_missing $_f"
    done
    if [ -n "$_vmp_missing" ]; then
      echo "错误：以下待 VMP 保护的函数在符号表中不存在：$_vmp_missing" >&2
      echo "      原因通常是函数名拼写错误，或被优化（内联/常量折叠）掉。" >&2
      echo "      对应编译单元需加 -fno-inline（见 ISA_HOOK_FLAGS / V7_BT_FLAGS）。" >&2
      exit 1
    fi
    echo ">> VMP 符号断言通过：全 $(awk -F, '{print NF}' <<<"$VMP_FUNCS") 个函数均在符号表中"
  else
    echo ">> 警告：无符号表快照，跳过 VMP 函数存在性断言" >&2
  fi

  "$VMPACKER_BIN" -func "$VMP_FUNCS" -o bash.vmp.tmp bash.unstripped
  cp bash.vmp.tmp bash
  rm -f bash.vmp.tmp
  echo ">> VMP 保护完成（产物已去符号且节区头重组，勿再 strip）"
else
  # 交叉编译时宿主 strip 认不出目标架构（"Unable to recognise the format"），
  # 必须用带前缀的 strip（aarch64-linux-gnu-strip）；失败则退回
  # llvm-strip（Termux/NDK 环境常见），仍失败则保留未 strip 产物并提示。
  if [ "$MUSL" = 1 ]; then
    # musl 工具链自带带前缀的 binutils；取不到则退回 llvm-strip
    _mcc="$(command -v "${MUSL_CC:-aarch64-linux-musl-gcc}" 2>/dev/null)"
    _mstrip="$(dirname "${_mcc:-/usr/bin/aarch64-linux-musl-gcc}")/aarch64-linux-musl-strip"
    if [ -x "$_mstrip" ]; then STRIP_BIN="$_mstrip"; else STRIP_BIN="llvm-strip"; fi
  elif [ "$AARCH64" = 1 ]; then
    STRIP_BIN="aarch64-linux-gnu-strip"
    command -v "$STRIP_BIN" >/dev/null 2>&1 || STRIP_BIN="llvm-strip"
  else
    STRIP_BIN="strip"
  fi
  if command -v "$STRIP_BIN" >/dev/null 2>&1; then
    "$STRIP_BIN" --strip-all bash 2>/dev/null \
      && echo ">> strip 完成（$STRIP_BIN；未 strip 副本: $SRC/bash.unstripped，调试用）" \
      || { echo ">> 警告：$STRIP_BIN 失败，保留未 strip 产物（符号可见，建议自行 strip）" >&2; }
  else
    echo ">> 警告：找不到可用的 strip 工具（试过 $STRIP_BIN），保留未 strip 产物" >&2
  fi
fi

# ============================================================================
# r28（T1.6）：4-elf / 5-final 快照 —— 收尾留档
#   ！必须在 anti-disasm / diag_strip **之前**存 4-elf 的完整可分析副本，
#     否则节区头已抹，readelf/nm 都读不出东西，等于没留。
#   5-final 存"最终交付形态"+ 哈希链。
# ============================================================================
if [ "$DO_KEEPWORK" = 1 ]; then
  # --- 4-elf：链接后、保护前的可分析产物（排查反汇编/符号问题的唯一凭据）---
  [ -f bash.unstripped ] && _wcp bash.unstripped "$WORK/4-elf"
  [ -f bash.unstripped.map ] && _wcp bash.unstripped.map "$WORK/4-elf"
  _hash_step "4-elf" "$WORK"/4-elf/* 2>/dev/null || true
  _wlog "4-elf 快照完成"
fi

# anti-disassembly：抹除「节区视图」（执行视图 Program Header 保持完好，不影响加载）
# 说明：仅在链接/调试时有用的 Section Header Table 整表抹零，运行时不需要。
# 效果：readelf -S 报 no sections；objdump -d 无法线性反汇编；nm 无符号。
# 边界：基于 Program Header 的 Ghidra/IDA/radare2 不受影响——抬高门槛，非消除能力。
if [ "$DO_ANTIDISASM" = 1 ]; then
  echo ">> anti-disassembly：抹除节区层视图"
  python3 "$HERE/elf_anti_disasm.py" bash \
    || { echo "错误：节区抹除失败" >&2; exit 1; }
else
  echo ">> 已按 --no-anti-disasm 跳过节区抹除"
fi

if [ "$KEEP_DIAG" = 1 ]; then
  echo ">> 已按 --keep-diag 保留 v7: 诊断串"
else
  echo ">> 剔除 v7: 诊断串（TracerPid/frida 为运行时必需，保留）"
  python3 "$HERE/diag_strip.py" bash \
    || { echo "错误：诊断串剔除失败" >&2; exit 1; }
fi

# --- 5-final：最终产物 + 哈希链 -------------------------------------------
if [ "$DO_KEEPWORK" = 1 ]; then
  mkdir -p "$WORK/5-final"
  _wcp bash "$WORK/5-final"
  # L6 表是"运行期外部依赖"，最终形态必须一起留档，否则产物跑不起来
  [ -n "$L6_SCRIPT" ] && _wcp "$HERE/v7_l6_param.bin" "$WORK/5-final"
  [ -n "$L6_SCRIPT" ] && _wcp "${L6_SCRIPT%.sh}.masked.sh" "$WORK/5-final"
  _hash_step "5-final" "$WORK"/5-final/*
  _wlog "5-final 完成"
  _wlog "构建结束（成功）"
  echo ">> 中间产物已留档：$WORK"
  echo "   ├─ 0-meta/   构建参数与工具指纹（复现所需）"
  echo "   ├─ 1-source/ 补丁后源文件快照"
  echo "   ├─ 2-token/  L6 表 + 令牌化脚本"
  echo "   ├─ 3-v6/     （v6 混淆产物，由外部流程填充）"
  echo "   ├─ 4-elf/    保护前可分析 ELF（readelf/objdump 可用）"
  echo "   ├─ 5-final/  最终产物 + HASHES.txt 哈希链"
  echo "   └─ 0-meta/BUILD.log 逐阶段时间线"
fi

echo ">> 完成：产物 $SRC/bash"
echo ">> 嵌入脚本："
echo "   python3 $HERE/v7_embed.py <明文脚本> $SRC/bash <输出> --pass 口令"
echo ">> 运行："
echo "   V7_SELF=1 V7_PASS='外层口令' <输出> /dev/null"
echo ">> L6 令牌化脚本直跑："
echo "   V7_ISA_TABLE=$HERE/v7_l6_param.bin $SRC/bash <令牌化脚本>"
