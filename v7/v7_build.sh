#!/usr/bin/env bash
# v7_build.sh —— TShell 统一构建入口（r13：A/B 合一，开关分流）
#
# 用法：
#   bash v7_build.sh <input.sh> <output> [选项]
#
# ★ r13 变更：本脚本现在是【唯一入口】，三条保护线用 V7_MODE 开关选择，
#   不再需要使用者区分"该用哪个脚本"：
#
#   V7_MODE=bash（默认） 单进程形态：改版 bash 自解密（安全模型最强）
#                        产物为可执行 bash 二进制（内含 blob）
#   V7_MODE=mksh（r35）  单进程形态：改版 mksh 自解密
#                        产物为可执行 mksh 二进制（内含 blob）
#                        ★ 运行契约：必须带一个 argv 文件参数，惯例 /dev/null
#                          （不带时 mksh 进 stdin 模式，解密分支不走 → 静默零输出）
#                        ★ 直接执行 ./out.mksh，不要写成 `mksh out.mksh`
#   V7_MODE=elf          ELF 双进程形态：elfrun + bash（工具链最全）
#                        产物为 .so/.elf，可再走 vmp_apply.py --verify
#   不给 V7_MODE 时按输出后缀自动判断：*.bash→bash 线、*.mksh→mksh 线、其余→elf 线
#
# 常用组合：
#   # 单进程最强档（r33：aes 档当前不可用，V6_CRYPTO 固定 builtin）
#   V7_MODE=bash V7_BASH_BIN=<VMP版bash> V7_OUTER_PASS='外层口令' V7_PASS='内层key' \
#       bash v7/v7_build.sh in.sh out.bash
#   # mksh 线一键（r35：从 mksh 源码现场构建改版解释器，无需预先准备）
#   V7_MODE=mksh V7_MKSH_SRC=./mksh-src V7_OUTER_PASS='外层口令' V7_PASS='内层key' \
#       bash v7/v7_build.sh in.sh out.mksh
#   # ELF 全防护 + VMP（跨架构需 V7_CC）
#   V7_MODE=elf V7_WB=1 V7_VMP=1 V7_SELF=1 V7_RAND_LABEL=1 V7_LABEL_OBF=1 \
#       ANDROID_GATE=1 V7_CC=aarch64-linux-gnu-gcc \
#       bash v7/v7_build.sh in.sh out.so
#
# ---------------------------------------------------------------- 通用开关
#   V7_MODE    bash|mksh|elf（默认 bash；也可由输出后缀推断）
#   V7_PASS    内层 passkey（V6 密钥分离，三条线通用）
#   V7_CRYPTO  aes|builtin（V6 数据块算法，通用；默认 builtin）
#   V7_JUNK / V7_DECOY    垃圾块/诱饵块（默认 1，通用）
#   V7_DIAG=1  排障版构建
#   V7_WRAP_KEEP=1  保留裸产物
#   V7_KEEP_STAGE=1 保留构建中间产物（令牌化版/V6 骨架/表 JSON）
#   ANDROID_GATE=1  注入安卓环境门控（脚本侧；与目标架构无关）
# ---------------------------------------------------------------- mksh 线专有
#   V7_MKSH_SRC     mksh R59c 源码目录（现场构建改版解释器，一键主路径）
#   V7_MKSH_BIN     复用已构建的改版 mksh（跳过构建，秒级重打包）
#   V7_ARCH/V7_CC   目标架构（交叉编译 aarch64 等）
#   （其余同 bash 线：V7_OUTER_PASS/V7_SCRYPT_N/V7_ISA/V7_ISA_SEED …）
#   ⚠ 已知限制：mksh 线的【内层口令档】（V7_PASS）当前不可用 ——
#      V6 骨架的 `read -rs -p` 在 mksh 里 -p 是"从 coprocess 读" ⇒ rc=1。
#      【外层口令 V7_OUTER_PASS 与离线分发模式不受影响】。详见
#      docs/BUILD_MKSH.md §6.3 / docs/PITFALLS.md §8.4b
# ---------------------------------------------------------------- bash 线专有
#   V7_OUTER_PASS  外层口令（不给 = 离线分发模式，白盒 seed）
#   V7_SCRYPT_N    外层 scrypt 内存参数（默认 131072）
#   V7_UNWRAP_ITER 内层解包裹迭代（aes 档默认自动 600000）
#   V7_L1_ITER     一层壳迭代（默认 600000）
#   V7_BASH_BIN    复用已构建的改版 bash；V7_SRC 现场构建
# ---------------------------------------------------------------- elf 线专有
#   V7_CC      编译器（默认 cc；安卓 arm64 用 aarch64-linux-gnu-gcc）
#   V7_OBF     V6 混淆器路径（默认自动查找）
#   V7_V6OPTS  传给 V6 的选项（默认 "JUNK_LEVEL=1 DECOY_LEVEL=1"）
#   V7_SELF=1  全内置模式：内嵌静态 bash，产物可在 adb shell 裸环境运行
#   V7_WB=1    白盒密钥编码   V7_VMP=1  开启 VMP 所需编译开关
#   V7_RAND_LABEL=1 / V7_LABEL_OBF=1  per-build 常量随机化
#   V7_WRAP=1  再包一层自释放 POSIX shell（单 .sh 交付）
#   V7_ISA=1   （r16-6，默认 1，仅 bash 线）四层随机化表接入：gen→rewrite→
#              魔改 bash -n 预检（fail-closed）→ 表随 WRAP 载荷嵌入；裸产物
#              旁生成 <out>.isa.bin，运行需 export V7_ISA_TABLE=<out>.isa.bin。
#              V7_ISA=0 关闭；V7_ISA_SEED=N 固定表种子（复现用）
#   V7_ISA_PARAM=1  （r33d，默认 1）L6 字符串字面量令牌化：静态字符串 → 密文
#              令牌，运行期 builtin 接管在 C 层解密（r27 全链路）；=0 关闭
#   V7_LINT=1  （r33d，默认 1）构建前 V6 兼容性检查（v6_lint：errexit 陷阱/
#              反调试指纹误触，默认警告式）；V7_LINT_STRICT=1 时 err 阻断；=0 关闭
#   V7_ARGV_SCAN=1  （r16-6，默认 1）构建前扫明文脚本的 argv 泄漏点
#              （tools/argv_leak_scan.py，报告不阻断；仅退出码 2 时阻断）
#   V7_BASH / V7_STATIC / V7_DIAG 等 见下方 elf 线原有说明
#
# ---------------------------------------------------------------- elf 线流程
#   1. V6 混淆 → 骨架 .sh（密钥链/完整性/MAC 全套，已是自保护产物）
#   2. /dev/urandom 出 32 字节 seed
#   3. blobgen：骨架 → 密文 + HMAC 标签（全内置：bash 再来一组，独立密钥）
#   4. 模板替换 → elfrun_gen.c（seed/tag/密文内嵌）
#   5. 静态编译 → ELF（无动态依赖，strace 也看不到 libc 调用明文参数以外的信息）
set -u
# 调用者目录必须在头部 cd 之前取：相对路径的 IN/OUT 按调用者所在目录解析
_inv_dir="$(pwd)"
cd "$(cd "$(dirname "$0")" && pwd)" || exit 1
_self_dir="$(pwd)"

# ============================================================ r13 分流
# 在解析 A 线参数之前先把 bash 线摘出去，避免两套参数互相污染。
# r35 修复：-h/--help 必须在这里先拦下来。此前 `[ "$#" -lt 2 ]` 会先命中
#   单个 -h 参数（$#=1）→ 只打印两行用法就 exit 2，下方 case 里的
#   `-h|--help|help)` 分支永远走不到（文件头注释里承诺的完整开关表出不来）。
#   注意必须用 $_self_dir 下的绝对路径取自身：本脚本在上面已经 cd 进自身
#   目录，调用者传进来的相对 $0（如 v7/v7_build.sh）此时**解析不到**。
case "${1:-}" in
  -h|--help|help) grep '^#' "$_self_dir/$(basename "$0")" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac
if [ "$#" -lt 2 ]; then
    echo "用法: bash v7_build.sh <input.sh> <output> [选项]" >&2
    echo "      V7_MODE=bash（默认，单进程）| mksh（单进程 mksh）| elf（双进程 ELF）；-h 看完整开关" >&2
    exit 2
fi
_in="$1"; _out="$2"
# r14 修复：先把相对路径**按调用者目录**转成绝对路径。
# 否则下面两条线都会把相对路径交给各自的子脚本，而子脚本开头会 `cd`
# 进自己目录、以"自身目录"为基准解析 —— 于是 `bash v7/v7_build.sh app.sh app.bash`
# 会把产物落到 v7/app.bash（而非你敲命令的目录），B 线更会报
# "改版 bash 不可执行/找不到" 这类误导性错误。构建输出应落在你所在的地方。
case "$_in"  in /*) ;; *) _in="$_inv_dir/$_in"  ;; esac
case "$_out" in /*) ;; *) _out="$_inv_dir/$_out" ;; esac
V7_MODE="${V7_MODE:-}"
if [ -z "$V7_MODE" ]; then
    # 按输出后缀推断：*.bash → 单进程 bash 线；*.mksh → mksh 线；其余 → ELF 线。
    # 特例：*.sh 本身三条线都可能产出（B 线 V7_WRAP=1 的产物也是 .sh），
    # 无法只靠后缀区分 —— 这时看专用输入变量：
    #   V7_MKSH_BIN / V7_MKSH_SRC → mksh 线
    #   V7_BASH_BIN / V7_SRC      → bash 线
    #   都没有                     → ELF 线（保持旧行为）
    # mksh 判定放在前面：同时给了两组（罕见但合法）时，显式指定 mksh 输入的
    # 意图更强 —— mksh 是后加入的线，用户不会无意中设它的变量。
    case "$_out" in
        *.bash|*.sh.bash) V7_MODE="bash" ;;
        *.mksh|*.sh.mksh) V7_MODE="mksh" ;;
        *.sh)
            if [ -n "${V7_MKSH_BIN:-}" ] || [ -n "${V7_MKSH_SRC:-}" ]; then
                V7_MODE="mksh"
            elif [ -n "${V7_BASH_BIN:-}" ] || [ -n "${V7_SRC:-}" ]; then
                V7_MODE="bash"
            else
                V7_MODE="elf"
            fi
            ;;
        *)                V7_MODE="elf" ;;
    esac
fi

# r14：目标架构（两线共用判定）。交叉编译器名最权威，其次 V7_ARCH，最后宿主。
case "$(uname -m)" in aarch64|arm64) _V7_ARCH="aarch64" ;; *) _V7_ARCH="$(uname -m)" ;; esac
[ -n "${V7_ARCH:-}" ] && _V7_ARCH="$V7_ARCH"

case "$V7_MODE" in
  bash)
    BASH_SIDE="$_self_dir/bash_poc/v7bash_build.sh"
    [ -f "$BASH_SIDE" ] || { echo "错误：找不到单进程构建器 $BASH_SIDE" >&2; exit 1; }
    # r33c：V7_KEEP_STAGE=1 —— 保留构建中间产物（排障/对拍/研究用）。此前
    # 两个关键中间态默认全删：V6 骨架是 mktemp 临时文件（trap EXIT 无条件
    # 删，从未见过天日），令牌化改写版 .isa.in.sh 在加密成功后即删（仅预检
    # 失败时留下供排查）。开此开关后按产物名落盘三件：.isa.in.sh（令牌化版
    # = V6 混淆的实际输入）、.isa.json（表 JSON，令牌化与预检依据）、
    # .v6.skel.sh（V6 混淆骨架）。中间产物含明文语义等价物，勿随产物分发。
    if [ "${V7_KEEP_STAGE:-0}" = "1" ]; then
        export V7_SKEL_KEEP="$_out.v6.skel.sh"   # 由 v7bash_build.sh 落盘
    fi
    # 把通用开关翻译成 bash 线参数（只在显式设置时传递，保持其默认值生效）
    _argv=("$_in" -o "$_out")
    [ -n "${V7_OUTER_PASS:-}"  ] && _argv+=(--outer-pass "$V7_OUTER_PASS")
    [ -n "${V7_PASS:-}"        ] && _argv+=(--pass "$V7_PASS")
    [ -n "${V7_CRYPTO:-}"      ] && _argv+=(--crypto "$V7_CRYPTO")
    [ -n "${V7_SCRYPT_N:-}"    ] && _argv+=(--scrypt-n "$V7_SCRYPT_N")
    [ -n "${V7_UNWRAP_ITER:-}" ] && _argv+=(--unwrap-iter "$V7_UNWRAP_ITER")
    [ -n "${V7_L1_ITER:-}"     ] && _argv+=(--l1-iter "$V7_L1_ITER")
    [ -n "${V7_JUNK:-}"        ] && _argv+=(--junk "$V7_JUNK")
    [ -n "${V7_DECOY:-}"       ] && _argv+=(--decoy "$V7_DECOY")
    # r33：安卓门控透传。此前 bash 线不透传、子脚本硬编码 0 → 一键产物
    #   静默缺环境门控。默认 1=生产；沙箱/桌面联调时 ANDROID_GATE=0。
    [ -n "${ANDROID_GATE:-}"   ] && _argv+=(--android-gate "$ANDROID_GATE")
    # r14：目标架构在 bash 线是**编译期**决定的，必须显式传导 —— 否则现场
    # 构建出的改版 bash 是宿主架构（x86_64），内嵌进产物后拿到 aarch64
    # 设备上直接 "Invalid ELF image for this architecture"。
    # 判定与 ELF 线一致：交叉编译器名优先，否则看 V7_ARCH，再看宿主。
    case "${V7_CC:-}" in
        *aarch64*|*arm64*) [ "$_V7_ARCH" = "x86_64" ] && _V7_ARCH="aarch64" ;;
    esac
    case "${V7_ARCH:-$_V7_ARCH}" in
        aarch64|arm64) _argv+=(--aarch64) ;;
    esac
    # r13：BASH_BIN/SRC 是 B 线入参，调用者常给相对包根的路径，而下面的
    # 子脚本会在自己的目录里解析 —— 这里先转成绝对路径，否则相对路径
    # 必然解析失败。依次按调用者 cwd → 包根（v7/ 的上一级，即
    # `bash v7/v7_build.sh` 时的所见）→ v7/ 自身解析。
    # r14 修复：判据从 `-x`（可执行）改为 `-f`（是普通文件）。跨架构复用时
    # 宿主**本来就无法执行**目标架构的 bash（Termux 被 seccomp 拦截），
    # 用 `-x` 会让所有候选分支落空，最终退回字面相对路径 → 子脚本里解析到
    # 不存在的文件，报出误导性的"改版 bash 不可执行"。
    if [ -n "${V7_BASH_BIN:-}" ]; then
        if [ -f "$V7_BASH_BIN" ]; then _bb="$V7_BASH_BIN"
        elif [ -f "$_inv_dir/$V7_BASH_BIN" ]; then _bb="$_inv_dir/$V7_BASH_BIN"
        elif [ -f "$_self_dir/../$V7_BASH_BIN" ]; then _bb="$_self_dir/../$V7_BASH_BIN"
        elif [ -f "$_self_dir/$V7_BASH_BIN" ]; then _bb="$_self_dir/$V7_BASH_BIN"
        else _bb="$V7_BASH_BIN"; fi
        _argv+=(--bash "$_bb")
    fi
    if [ -n "${V7_SRC:-}" ]; then
        if [ -d "$V7_SRC" ]; then _sr="$V7_SRC"
        elif [ -d "$_inv_dir/$V7_SRC" ]; then _sr="$_inv_dir/$V7_SRC"
        elif [ -d "$_self_dir/../$V7_SRC" ]; then _sr="$_self_dir/../$V7_SRC"
        elif [ -d "$_self_dir/$V7_SRC" ]; then _sr="$_self_dir/$V7_SRC"
        else _sr="$V7_SRC"; fi
        _argv+=(--src "$_sr")
    fi
    # r13：V7_DIAG=1 排障版（B 线）。构建期 -DV7_DIAG → 产物运行时再设
    # V7_DIAG=1 才输出阶段进度与拒绝原因；生产构建诊断代码与串整体不生成。
    # 注意：诊断能力是**编译期**决定的，必须现场从源码构建（V7_SRC=...）。
    # 复用现成二进制（V7_BASH_BIN=...）时 --diag 无意义 —— 那里给明确提示，
    # 否则用户会拿到一个"设了 V7_DIAG=1 却毫无输出"的产物而不知所措。
    # r16-6：argv 泄漏扫描（构建前 lint）。退出码 0=干净 1=有命中（报告已由
    # 工具打印，脱敏输出）2=用法/IO 错。仅 2 阻断；命中只提示不阻断。
    if [ "${V7_ARGV_SCAN:-1}" = "1" ] && command -v python3 >/dev/null 2>&1; then
        python3 "$_self_dir/../tools/argv_leak_scan.py" "$_in" || {
            _arc=$?
            if [ "$_arc" = "1" ]; then
                echo "提示：存在 argv 泄漏点（报告见上，已脱敏）。构建继续 ——" >&2
                echo "      机密建议改走环境变量/fd；运行期可开 V7_WRAP 自释放+反调试缓解。" >&2
            else
                echo "错误：argv_leak_scan 运行失败（rc=$_arc）" >&2
                exit 1
            fi
        }
    fi
    # r33d：V6 兼容性 lint（v6_lint.py）——把"环境问题包装成加密器坏了"的
    # 两类静默坑拦在混淆前：① errexit 陷阱（裸 false 等，宿主与产物一致失败
    # 但零提示）② set -x/改 PS4/重定义 builtin 触发 V6 反调试指纹 → 密钥污染
    # → 静默退出。默认警告式（发现问题打印但放行）；V7_LINT_STRICT=1 时
    # err 阻断；V7_LINT=0 关闭。
    if [ "${V7_LINT:-1}" = "1" ] && command -v python3 >/dev/null 2>&1; then
        _lint_args=""
        [ "${V7_LINT_STRICT:-0}" = "1" ] && _lint_args="--strict"
        python3 "$_self_dir/../tools/v6_lint.py" "$_in" $_lint_args || {
            echo "错误：v6_lint 发现兼容性问题（V7_LINT_STRICT=1 阻断；V7_LINT=0 可关闭检查）" >&2
            exit 1
        }
    fi
    # r16-6：ISA 四层随机化表接入（G.1.5 首批工具链，MVP 形态=环境变量+表旁文件/
    # WRAP 嵌入）。仅 bash 线 —— elf 线的骨架交给无 hook 的普通 bash，改写必死。
    # L1/L2 改写"宁缺勿滥"+未改写位置原名照跑（hook 只拦表内随机名），兼容性 100%；
    # L3/L4 改写器属后续迭代，此处暂不启用（表生成已含四层，运行端 hook 已支持）。
    # r34 修复：_isa_json 也必须预初始化 —— V7_ISA=0 时不进分支，
    # 而下方 V7_KEEP_STAGE/清理段无条件引用它，set -u 下必崩
    # （实测：产物正常生成，脚本在收尾处 "line 412: _isa_json: unbound
    #  variable" 退出 1，被误读为"构建失败"）。
    _isa_bin=""; _isa_in=""; _isa_json=""
    if [ "${V7_ISA:-1}" = "1" ]; then
        command -v python3 >/dev/null 2>&1 || { echo "错误：V7_ISA 需要 python3" >&2; exit 1; }
        # r33b：_bb 仅在 V7_BASH_BIN 非空时赋值；set -u 下必须用 ${_bb:-}
        # 兜底（实测：V7_BASH_BIN=`路径` 的反引号写法会触发命令替换——二进制
        # 被当命令执行、替换结果为空 → V7_BASH_BIN 空串 → 此处 unbound variable
        # 直接崩，报错比"未提供魔改 bash"更误导）。
        [ -n "${_bb:-}" ] || {
            echo "错误：V7_ISA 需要 -n 预检，但未提供魔改 bash（V7_BASH_BIN/V7_SRC）" >&2
            echo "      示例：V7_BASH_BIN=./workspace/v7_aarch64_bionic/bash-vmp-aarch64-bionic-r33" >&2
            echo "      注意：路径直接写，不要用反引号 —— \`...\` 是命令替换，" >&2
            echo "            会把二进制当命令执行、把空输出赋给变量。" >&2
            exit 1
        }
        _isa_bin="$_out.isa.bin"; _isa_json="$_out.isa.json"; _isa_in="$_out.isa.in.sh"
        _seed_args=""; [ -n "${V7_ISA_SEED:-}" ] && _seed_args="--seed $V7_ISA_SEED"
        # r21：掺假强度可调（0 = 关闭）。默认 24 幻影 + 8 影子。
        _decoy_args="--decoy ${V7_ISA_DECOY:-24} --shadow ${V7_ISA_SHADOW:-8}"
        python3 "$_self_dir/../tools/v7_isa.py" gen $_seed_args $_decoy_args -o "$_isa_bin" --json "$_isa_json" \
            || { echo "错误：ISA 表生成失败" >&2
                 echo "      常见原因：缺少主密钥 v7/bash_poc/v7_isa_key.h（表已加密，r21 起" >&2
                 echo "      生成表需要它）。补生成：python3 tools/v7_isa.py emit-key \\" >&2
                 echo "      -o v7/bash_poc/v7_isa_key.h —— 注意换密钥会让既有表作废。" >&2
                 exit 1; }
        python3 "$_self_dir/../tools/v7_isa.py" rewrite --table "$_isa_json" --in "$_in" --out "$_isa_in" \
            || { echo "错误：ISA L1/L2 改写失败" >&2; exit 1; }
        # r33d：L6 字符串字面量令牌化接入（r27/T1 全链路，默认开）。
        # gen-param 从【明文】提取静态字符串（字符串在 rewrite 中不被 L1-L5
        # 触碰，两侧一致），--with-table 合并进既有 JSON 表后重加密 .bin
        # （一张表含 L1-L6）；rewrite-param 把改写版文本里引号内的静态串
        # 换成 v7p_* 密文令牌。运行期 v7_echo_builtin 在 C 层解密（r27 端
        # 到端已验证）。已知妥协：v7_isa_param_decode 暂禁出 VMP 保护面
        # （F7：VMPacker 翻译缺陷 0xA4，见 §15.4），以原生 C 运行——功能
        # 正确，保护面缺口待 F7 闭环。
        if [ "${V7_ISA_PARAM:-1}" = "1" ]; then
            python3 "$_self_dir/../tools/v7_isa.py" gen-param --in "$_in" \
                --with-table "$_isa_json" -o "$_isa_bin" --json "$_isa_json" \
                || { echo "错误：L6 参数表生成失败（gen-param）" >&2; exit 1; }
            _isa_tmp="$_isa_in.p$$"
            python3 "$_self_dir/../tools/v7_isa.py" rewrite-param \
                --table "$_isa_json" --in "$_isa_in" --out "$_isa_tmp" \
                || { echo "错误：L6 字符串改写失败（rewrite-param）" >&2
                     rm -f "$_isa_tmp"; exit 1; }
            mv -f "$_isa_tmp" "$_isa_in"
            echo "==> V7_ISA_PARAM=1：L6 字符串令牌化已接入（表含 L1-L6，运行期 C 层解密）"
        fi
        # fail-closed：改写产物必须过魔改 bash 的 -n 语法预检。
        # r17：跨架构构建时宿主**跑不了**目标架构的 bash（Exec format error）。
        # 按目标架构自动套 qemu-user-static 执行器；找不到 qemu 就明确报错，
        # 绝不"跳过预检继续跑"—— 那等于把 A4 的 fail-closed 静默拆掉。
        _bb_run=""
        _tgt_arch=""
        case "${V7_CC:-}" in
            *aarch64*|*arm64*) _tgt_arch="aarch64" ;;
        esac
        # r33：复用现成改版 bash（不给 V7_CC）时，读其 ELF e_machine 判目标
        # 架构 —— 否则 _tgt_arch 落到宿主架构 → 预检不套 qemu → 直接执行
        # aarch64 bash 报 "Exec format error"（rc=126），一键流程断在预检。
        # 与下游 v7bash_build.sh 的同款探测保持一致（aarch64=183 x86_64=62，
        # e_machine 在偏移 18，2 字节 LE）。
        if [ -z "$_tgt_arch" ] && [ -n "${V7_ARCH:-}" ]; then
            case "$V7_ARCH" in aarch64|arm64) _tgt_arch="aarch64" ;; esac
        fi
        # r33c：探测用 fallback 解析后的 _bb（line 140-145），不再用原始
        # $V7_BASH_BIN —— 相对路径在脚本目录 CWD 下多半解析不到，探测落空
        # → 架构落到宿主 → 跨架构预检不套 qemu → 直接 Exec format error。
        if [ -z "$_tgt_arch" ] && [ -n "${_bb:-}" ] && [ -f "${_bb:-}" ]; then
            _mach=$(od -An -tu1 -j18 -N2 "$_bb" 2>/dev/null | awk '{print $1}')
            case "$_mach" in
                183) _tgt_arch="aarch64" ;;
                 62) _tgt_arch="x86_64" ;;
            esac
        fi
        if [ -z "$_tgt_arch" ]; then
            case "$(uname -m)" in aarch64|arm64) _tgt_arch="aarch64" ;; *) _tgt_arch="$(uname -m)" ;; esac
        fi
        _host_arch="$(uname -m)"
        case "$_host_arch" in arm64) _host_arch="aarch64" ;; esac
        if [ "$_tgt_arch" != "$_host_arch" ]; then
            for _q in "qemu-${_tgt_arch}-static" "qemu-${_tgt_arch}"; do
                command -v "$_q" >/dev/null 2>&1 && { _bb_run="$_q"; break; }
            done
            [ -n "$_bb_run" ] || {
                echo "错误：目标架构 $_tgt_arch 与宿主 $_host_arch 不同，需要 qemu-user 才能做" >&2
                echo "      ISA 改写的 -n 预检（魔改 bash 无法在宿主直接执行）。" >&2
                echo "      请安装 qemu-user-static，或改用同架构构建（V7_CC 不交叉）。" >&2
                exit 1
            }
            echo "==> 跨架构预检：$_bb_run $_bb（宿主 $_host_arch → 目标 $_tgt_arch）"
        fi
        # r19：预检用的 bash 可与内嵌的分离（V7_ISA_BASH）。
        # 场景：内嵌 VMP 版启动慢、易撞反调试时间窗(113)，预检改用轻量非 VMP 版。
        _isa_chk_bb="${V7_ISA_BASH:-$_bb}"
        if [ "${V7_ISA_CHECK:-1}" = "0" ]; then
            echo "警告：V7_ISA_CHECK=0 —— 已跳过 -n 预检（fail-closed 被绕过）" >&2
            echo "      ISA 改写若有语法错误会直接进产物，运行时才暴露。仅建议排查时用。" >&2
        else
            # r19：预检前先验可执行性 —— 否则 "未通过预检" 会掩盖真实原因
            # （Permission denied / No such file / Exec format error 全被吞掉）
            if [ ! -f "$_isa_chk_bb" ]; then
                echo "错误：预检用的魔改 bash 不存在：$_isa_chk_bb" >&2
                echo "      该文件未随发行包分发、或路径写错。" >&2
                echo "      可用替代：V7_BASH_BIN=v7/static/bash-aarch64-vmp" >&2
                exit 1
            fi
            if [ ! -x "$_isa_chk_bb" ]; then
                echo "提示：$_isa_chk_bb 缺执行位（-n 预检需执行它），自动 chmod +x" >&2
                chmod +x "$_isa_chk_bb" 2>/dev/null || {
                    echo "错误：无法赋予执行位（只读文件系统？）：$_isa_chk_bb" >&2
                    echo "      手动执行：chmod +x $_isa_chk_bb" >&2
                    exit 1
                }
            fi
            # r33：预检必须带上本次生成的 ISA 表（V7_ISA_TABLE）。魔改 bash 的
            # 令牌还原在读取/词法层，-n 语义检查同样要靠表把 v7p_* 令牌还原成
            # case/esac 等关键字——漏传表时 for/if 的改写产物恰好是"合法简单命令
            # 序列"会假通过，而 case 的 pattern `NN)` 会误报 syntax error（实测
            # line 15 报 `33)' unexpected）。判据失效双向都是坑：假通过放进真语法
            # 错误，假失败拦住好产物。
            V7_ISA_TABLE="$_isa_bin" $_bb_run "$_isa_chk_bb" -n "$_isa_in" 2>"$_isa_in.err"
            _prc=$?
            if [ "$_prc" -ne 0 ]; then
                echo "错误：ISA 改写产物未通过魔改 bash -n 预检（退出码 $_prc）" >&2
                echo "      预检 bash：$_isa_chk_bb（$(wc -c < "$_isa_chk_bb" 2>/dev/null) 字节）" >&2
                echo "      宿主架构：$(uname -m)  改写产物：$_isa_in" >&2
                echo "      ---- 退出码速查 ----" >&2
                echo "      113 = 反调试启动时间窗（VMP 版启动慢 >3000ms 自杀）→ 设 V7_ISA_BASH=<轻量bash>" >&2
                echo "      126 = 不可执行 / 架构不匹配        127 = 文件不存在" >&2
                echo "      159 / Unknown signal 31 = SIGSYS（seccomp 拦 syscall）" >&2
                echo "          → glibc/musl 静态 bash 在 Android 上的死穴，无解，只能换 bionic 版：" >&2
                echo "            V7_BASH_BIN=v7/static/bash-aarch64-bionic-vmp" >&2
                echo "      1   = 真语法错误（下面应有 line N 提示）" >&2
                echo "      排查：V7_ISA_CHECK=0 可跳过预检（降保护）" >&2
                echo "      ---- bash 自身的 stderr ----" >&2
                cat "$_isa_in.err" >&2
                echo "      ---- 手工复现 ----" >&2
                echo "      V7_ISA_TABLE=$_isa_bin $_bb_run $_isa_chk_bb -n $_isa_in; echo rc=\$?" >&2
                rm -f "$_isa_in.err"
                exit 1
            fi
            rm -f "$_isa_in.err"
        fi
        echo "==> V7_ISA=1：四层随机化已接入（表 $(wc -c < "$_isa_bin")B，改写版 $(wc -c < "$_isa_in")B）"
        _argv[0]="$_isa_in"     # 后续 V6 骨架/blob 嵌入全部用改写版
        # r16-7（A3）：把表交给 bash 线子脚本 → 其再用 V7_SIM_* 透传给 V6 的
        # simulate_execution（构建期模拟必须与运行期同语义，见 G.5）
        _argv+=(--isa-table "$_isa_bin")
    fi
    # r13：V7_DIAG=1 排障版（B 线）。构建期 -DV7_DIAG → 产物运行时再设
    # V7_DIAG=1 才输出阶段进度与拒绝原因；生产构建诊断代码与串整体不生成。
    # 注意：诊断能力是**编译期**决定的，必须现场从源码构建（V7_SRC=...）。
    # 复用现成二进制（V7_BASH_BIN=...）时 --diag 无意义 —— 那里给明确提示，
    # 否则用户会拿到一个"设了 V7_DIAG=1 却毫无输出"的产物而不知所措。
    if [ "${V7_DIAG:-0}" = "1" ]; then
        if [ -n "${V7_SRC:-}" ]; then
            _argv+=(--diag)
        else
            echo "警告：V7_DIAG=1 需要现场从源码构建（V7_SRC=<bash源码目录>）。" >&2
            echo "      当前走的是复用二进制路径（V7_BASH_BIN），诊断能力在编译期" >&2
            echo "      决定，无法事后开启 —— 该产物设 V7_DIAG=1 不会有任何输出。" >&2
        fi
    fi
    [ "${V7_MODE_QUIET:-0}" = "1" ] || echo "==> V7_MODE=bash（单进程：改版 bash 自解密）"
    # r13：单进程线也支持自释放 POSIX shell 包装（与 ELF 线同一套 v7_wrap.sh，
    # 该工具无架构硬编码，B 线产物同为 ELF 故可直接复用）。
    if [ "${V7_WRAP:-0}" = "1" ]; then
        _raw="$_out.raw.bash"          # 包装前的裸产物（默认包装后删除）
        _argv+=(-o "$_raw")
        bash "$BASH_SIDE" "${_argv[@]}"
        echo "==> V7_WRAP=1：生成自释放 POSIX shell"
        if [ -n "$_isa_bin" ]; then
            # r16-6：表随载荷嵌入（受加载器自校验保护），运行期零外部依赖
            # r19：占位符需求来自 zread「劫持脚本读取」机制，与构建期 V7_SELF
            # （ELF 线才有、控制是否内嵌 bash）无关 —— 别拿 V7_SELF 当判据。
            # bash 线产物就是改版 bash 本身，运行时须带一个脚本参数才会触发
            # 劫持，故恒为 1；运行时所需的 V7_SELF=1 由加载器自己设。
            V7_SELF_MODE=1 bash "$_self_dir/v7_wrap.sh" "$_raw" "$_out" "$_isa_bin" || { echo "错误：包装失败" >&2; exit 1; }
        else
            V7_SELF_MODE=1 bash "$_self_dir/v7_wrap.sh" "$_raw" "$_out" || { echo "错误：包装失败" >&2; exit 1; }
        fi
        if [ "${V7_WRAP_KEEP:-0}" != "1" ]; then
            rm -f "$_raw"
        else
            echo "    （V7_WRAP_KEEP=1：裸产物保留于 $_raw）"
        fi
        # r33c：V7_KEEP_STAGE=1 时中间产物保留（.isa.bin 本来就留着）
        if [ "${V7_KEEP_STAGE:-0}" = "1" ]; then
            [ -f "$_isa_in" ] && echo "    （保留中间产物：$_isa_in —— 令牌化版，V6 混淆的输入）"
            [ -f "$_isa_json" ] && echo "    （保留中间产物：$_isa_json —— ISA 表 JSON）"
        else
            rm -f "$_isa_json" "$_isa_in"
        fi
        [ -n "${V7_ISA_KEEP:-}" ] || { [ -z "$_isa_bin" ] || echo "    （ISA 表旁文件：$_isa_bin，供 isa_itest/复现）"; }
        exit 0
    fi
    bash "$BASH_SIDE" "${_argv[@]}" || exit $?
    # r16-6：裸产物（非 WRAP）运行时表外置 —— 按文档 MVP 形态走环境变量
    if [ -n "$_isa_bin" ]; then
        echo "提示：ISA 表旁文件 $_isa_bin —— 运行本裸产物需 export V7_ISA_TABLE=$_isa_bin"
        echo "      （要单文件零依赖分发请加 V7_WRAP=1，表会随载荷嵌入）"
    fi
    # r33c：V7_KEEP_STAGE=1 时中间产物保留（.isa.bin 本来就留着）
    if [ "${V7_KEEP_STAGE:-0}" = "1" ]; then
        [ -f "$_isa_in" ] && echo "保留中间产物：$_isa_in —— 令牌化版（V6 混淆的输入）"
        [ -f "$_isa_json" ] && echo "保留中间产物：$_isa_json —— ISA 表 JSON"
    else
        rm -f "$_isa_json" "$_isa_in"
    fi
    # r13：单进程线也支持 VMP 逐函数裁剪（V7_VMP_VERIFY=1）。
    # 需要构建时产出的 .map；若用 --bash 复用产物的方式构建，
    # 则由 V7_BASH_MAP 显式指定符号表路径。
    if [ "${V7_VMP_VERIFY:-0}" = "1" ]; then
        _map="${V7_BASH_MAP:-}"
        if [ -z "$_map" ]; then
            echo "提示：V7_VMP_VERIFY=1 需要符号表（.map）。" >&2
            echo "      请用 V7_SRC=<bash源码目录> 现场构建（会自动产出 .map），" >&2
            echo "      或用 V7_BASH_MAP=<path.map> 指定已有符号表。" >&2
            exit 2
        fi
        [ -f "$_map" ] || { echo "错误：符号表不存在: $_map" >&2; exit 2; }
        echo "==> V7_VMP_VERIFY=1：VMP 逐函数保护 + 自动验证"
        # 断点续跑：V7_VMP_INCLUDE 给幸存清单时跳过逐函数试错
        _inc=""
        [ -n "${V7_VMP_INCLUDE:-}" ] && _inc="--include $V7_VMP_INCLUDE"
        # 运行契约透传：内层 passkey 走 stdin、外层口令走 V7_PASS，
        # 否则基线跑的是"缺口令"分支，逐函数验证全部失真。
        _pk=""
        [ -n "${V7_PASS:-}" ] && _pk="--passkey $V7_PASS"
        _op=""
        [ -n "${V7_OUTER_PASS:-}" ] && _op="--outer-pass $V7_OUTER_PASS"
        _qemu=""; [ -n "${V7_QEMU:-}" ] && _qemu="--qemu $V7_QEMU"
        python3 "$_self_dir/../tools/vmp_apply.py" "$_out" --verify --map "$_map" \
            -o "${V7_VMP_OUT:-$_out.vmp}" $_qemu $_pk $_op $_inc \
            ${V7_VMP_RUN_ARGS:+--run-args "$V7_VMP_RUN_ARGS"} || exit $?
        echo
        echo "提示：B 线产物已把 VMP 保护面固化进二进制；此后每次打包脚本"
        echo "      只需重跑 V6 骨架 + blob 嵌入（秒级），无需重复 VMP 流程。"
    fi
    exit 0
    ;;
  elf)
    : # 继续走下方原有 ELF 流程
    # r16-6：ISA 四层随机化仅 bash 线 —— elf 线骨架交给无 hook 的普通 bash，
    # 改写后的脚本无法执行。此处自动降级并显式告知（不静默、不产出坏产物）。
    if [ "${V7_ISA:-1}" = "1" ]; then
        echo "提示：V7_ISA=1（默认）仅支持 bash 线，elf 线自动关闭（骨架由普通 bash" >&2
        echo "      解释，无随机名还原 hook）。ISA 保护请走 bash 线（V7_BASH_BIN/V7_SRC）。" >&2
    fi
    ;;
  mksh)
    # ==================================================== r35：mksh 魔改解释器线
    # 产物形态：**改版 mksh 二进制 + 尾部内嵌加密骨架**（与 bash 线同为 ELF，
    # 但运行契约不同 —— 见下方运行示例，必须带一个 argv 文件参数）。
    #
    # ★ 与 bash 线的**顺序差异**（本分支刻意不同，照抄 bash 分支会死锁）：
    #   bash 线在本脚本里先做 ISA 改写（用调用者提供的 V7_BASH_BIN 做 -n 预检），
    #   再交给 v7bash_build.sh 构建。
    #   mksh 线的改版 mksh 是**现场构建**出来的，-n 预检必须用这个刚出炉的
    #   二进制 ⇒ ISA 段整体**下移到子脚本**（构建之后再做）。
    #   故本分支不做 ISA 改写，只翻译参数 + 复用与解释器无关的 sanity 检查。
    MKSH_SIDE="$_self_dir/mksh_poc/v7mksh_build.sh"
    [ -f "$MKSH_SIDE" ] || { echo "错误：找不到 mksh 线构建器 $MKSH_SIDE" >&2; exit 1; }

    # r34：_isa_* 预初始化（set -u）。本分支虽不做 ISA 改写，但收尾段无条件
    # 引用 → 不预初始化会在 set -u 下崩为 unbound variable（bash 线踩过）。
    _isa_bin=""; _isa_in=""; _isa_json=""

    if [ "${V7_KEEP_STAGE:-0}" = "1" ]; then
        export V7_KEEP_STAGE=1
    fi

    # 把通用开关翻译成 mksh 线参数（只在显式设置时传递，保持其默认值生效）
    _margv=("$_in" -o "$_out")
    [ -n "${V7_OUTER_PASS:-}"  ] && _margv+=(--outer-pass "$V7_OUTER_PASS")
    [ -n "${V7_PASS:-}"        ] && _margv+=(--pass "$V7_PASS")
    [ -n "${V7_CRYPTO:-}"      ] && _margv+=(--crypto "$V7_CRYPTO")
    [ -n "${V7_SCRYPT_N:-}"    ] && _margv+=(--scrypt-n "$V7_SCRYPT_N")
    [ -n "${V7_UNWRAP_ITER:-}" ] && _margv+=(--unwrap-iter "$V7_UNWRAP_ITER")
    [ -n "${V7_L1_ITER:-}"     ] && _margv+=(--l1-iter "$V7_L1_ITER")
    [ -n "${V7_JUNK:-}"        ] && _margv+=(--junk "$V7_JUNK")
    [ -n "${V7_DECOY:-}"       ] && _margv+=(--decoy "$V7_DECOY")
    [ -n "${ANDROID_GATE:-}"   ] && _margv+=(--android-gate "$ANDROID_GATE")
    # ISA 开关（mksh 线在子脚本里做，这里只透传）
    [ -n "${V7_ISA:-}"         ] && _margv+=(--isa "$V7_ISA")
    [ -n "${V7_ISA_SEED:-}"    ] && _margv+=(--isa-seed "$V7_ISA_SEED")
    [ -n "${V7_ISA_DECOY:-}"   ] && _margv+=(--isa-decoy "$V7_ISA_DECOY")
    [ -n "${V7_ISA_SHADOW:-}"  ] && _margv+=(--isa-shadow "$V7_ISA_SHADOW")

    # r14：目标架构是**编译期**决定的，必须显式传导 —— 否则现场构建出的
    # mksh 是宿主架构，内嵌进产物后拿到 aarch64 设备上跑不了。
    case "${V7_CC:-}" in
        *aarch64*|*arm64*) _V7_ARCH="aarch64" ;;
    esac
    case "${V7_ARCH:-$_V7_ARCH}" in
        aarch64|arm64) _margv+=(--target-arch aarch64) ;;
        x86_64|amd64)  _margv+=(--target-arch x86_64)  ;;
    esac

    # ANDROID_GATE 与 TARGET_OS 的语义区分（用户极易混淆，故显式提示）
    if [ "${ANDROID_GATE:-1}" = "1" ]; then
        echo "提示：ANDROID_GATE=1 是【脚本侧环境门控】（V6 注入，产物仅安卓可跑）。" >&2
        echo "      若要交叉编译 aarch64/Android 版 mksh **本身**，另设 V7_ARCH=aarch64" >&2
        echo "      或 V7_CC=aarch64-linux-gnu-gcc —— 两者不是一回事。" >&2
    fi

    # V7_MKSH_BIN / V7_MKSH_SRC 是 mksh 线入参，调用者常给相对包根的路径，而
    # 子脚本会在自己的目录里解析 —— 这里先按三级（调用者 cwd → 包根 → v7/）
    # 转成绝对路径。判据用 `-f`/`-d` 而非 `-x`：跨架构复用时宿主**本来就无法
    # 执行**目标架构的 mksh，用 `-x` 会让所有候选分支落空（bash 线踩过此坑）。
    if [ -n "${V7_MKSH_BIN:-}" ]; then
        if [ -f "$V7_MKSH_BIN" ]; then _mb="$V7_MKSH_BIN"
        elif [ -f "$_inv_dir/$V7_MKSH_BIN" ]; then _mb="$_inv_dir/$V7_MKSH_BIN"
        elif [ -f "$_self_dir/../$V7_MKSH_BIN" ]; then _mb="$_self_dir/../$V7_MKSH_BIN"
        elif [ -f "$_self_dir/$V7_MKSH_BIN" ]; then _mb="$_self_dir/$V7_MKSH_BIN"
        else _mb="$V7_MKSH_BIN"; fi
        _margv+=(--mksh "$_mb")
    fi
    if [ -n "${V7_MKSH_SRC:-}" ]; then
        if [ -d "$V7_MKSH_SRC" ]; then _ms="$V7_MKSH_SRC"
        elif [ -d "$_inv_dir/$V7_MKSH_SRC" ]; then _ms="$_inv_dir/$V7_MKSH_SRC"
        elif [ -d "$_self_dir/../$V7_MKSH_SRC" ]; then _ms="$_self_dir/../$V7_MKSH_SRC"
        elif [ -d "$_self_dir/$V7_MKSH_SRC" ]; then _ms="$_self_dir/$V7_MKSH_SRC"
        else _ms="$V7_MKSH_SRC"; fi
        _margv+=(--src "$_ms")
    fi
    # 二选一强校验（照抄 bash 分支的 V7_BASH_BIN/V7_SRC 判据）
    [ -n "${V7_MKSH_BIN:-}" ] || [ -n "${V7_MKSH_SRC:-}" ] || {
        echo "错误：mksh 线需要 V7_MKSH_BIN=<改版mksh> 或 V7_MKSH_SRC=<mksh源码目录>（二选一）" >&2
        echo "      示例：V7_MODE=mksh V7_MKSH_SRC=./mksh-src V7_PASS='...' bash v7/v7_build.sh in.sh out.mksh" >&2
        exit 2
    }

    # r16-6：argv 泄漏扫描（构建前 lint）。扫的是**明文脚本**，与目标解释器
    # 无关 ⇒ 原样复用 bash 分支的逻辑（仅 rc=2 阻断，命中只提示）。
    if [ "${V7_ARGV_SCAN:-1}" = "1" ] && command -v python3 >/dev/null 2>&1; then
        python3 "$_self_dir/../tools/argv_leak_scan.py" "$_in" || {
            _arc=$?
            if [ "$_arc" = "1" ]; then
                echo "提示：存在 argv 泄漏点（报告见上，已脱敏）。构建继续 ——" >&2
                echo "      机密建议改走环境变量/fd；运行期可开 V7_WRAP 自释放+反调试缓解。" >&2
            else
                echo "错误：argv_leak_scan 运行失败（rc=$_arc）" >&2
                exit 1
            fi
        }
    fi
    # r33d：V6 兼容性 lint。检查的是 V6 混淆器兼容性（errexit 陷阱 /
    # set -x 反调试指纹），**V6 生成器两线共用同一份** ⇒ 结论同样适用。
    if [ "${V7_LINT:-1}" = "1" ] && command -v python3 >/dev/null 2>&1; then
        _lint_args=""
        [ "${V7_LINT_STRICT:-0}" = "1" ] && _lint_args="--strict"
        python3 "$_self_dir/../tools/v6_lint.py" "$_in" $_lint_args || {
            echo "错误：v6_lint 发现兼容性问题（V7_LINT_STRICT=1 阻断；V7_LINT=0 可关闭检查）" >&2
            exit 1
        }
    fi

    # V7_DIAG=1 排障版：诊断能力是**编译期**决定的（-DV7_DIAG），复用现成
    # 二进制时无从开启 —— 给明确提示，否则用户会拿到"设了 V7_DIAG=1 却无输出"
    # 的产物而不知所措。
    if [ "${V7_DIAG:-0}" = "1" ]; then
        if [ -n "${V7_MKSH_SRC:-}" ]; then
            _margv+=(--diag)
        else
            echo "警告：V7_DIAG=1 需要现场从源码构建（V7_MKSH_SRC=<mksh源码目录>）。" >&2
            echo "      当前走的是复用二进制路径（V7_MKSH_BIN），诊断能力在编译期" >&2
            echo "      决定，无法事后开启 —— 该产物设 V7_DIAG=1 不会有任何输出。" >&2
        fi
    fi

    [ "${V7_MODE_QUIET:-0}" = "1" ] || echo "==> V7_MODE=mksh（单进程：改版 mksh 自解密）"
    bash "$MKSH_SIDE" "${_margv[@]}" || exit $?
    exit 0
    ;;
  -h|--help|help)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0
    ;;
  *)
    echo "错误：V7_MODE 只能是 bash、mksh 或 elf（当前: $V7_MODE）" >&2; exit 2
    ;;
esac
# ======================================================== r13 分流结束

IN="$1"
OUT="$2"
V7_CC="${V7_CC:-cc}"
V7_V6OPTS="${V7_V6OPTS-JUNK_LEVEL=1 DECOY_LEVEL=1}"
V7_SELF="${V7_SELF:-0}"
# 相对路径解析：IN 先按调用者目录、再按脚本目录（兼容"从包根 bash v7/v7_build.sh
# v6/xxx.sh"与"cd v7 后 bash v7_build.sh ../v6/xxx.sh"两种用法）；
# OUT 一律按调用者目录（产物落在你敲命令的地方，符合直觉）
case "$IN" in /*) ;;
    *) [ -e "$_inv_dir/$IN" ] && IN="$_inv_dir/$IN" || IN="$_self_dir/$IN" ;;
esac
case "$OUT" in /*) ;; *) OUT="$_inv_dir/$OUT" ;; esac
DIAG_CFLAGS=""
[ "${V7_DIAG:-0}" = "1" ] && DIAG_CFLAGS="-DV7_DIAG"
# ---- V7_VMP=1：一次开启"可被 VMP 保护"所需的全部编译开关 ----
#   = V7_NOINLINE=1（关键函数独立存在，不被 -O2 内联进 main）
#     + -mgeneral-regs-only（编译器完全不碰 NEON/FP 寄存器）
#     + 强制导出符号表（VMPacker 需要按地址定位函数）
# 为什么必须禁 NEON：VMPacker 的 VM 只实现了通用寄存器（GPR），
# 遇到 q/d/v/s 类 NEON 指令一律标 UNKNOWN 并 abort（宁可不动也不产崩产物）。
# 实测：-O2 下 v7_keys（cmeq v0.16b 16B 常量比较）、traced（序言 stp q8-q15）
# 全被拒；加 -mgeneral-regs-only 后运行时代码零 NEON，可全部保护。
# 代价：失去编译器自动向量化，体积/性能略有损失；VMPacker 仅支持 aarch64，
# 故本模式应配合 aarch64 工具链（V7_CC=aarch64-linux-gnu-gcc）使用。
NOFP_CFLAGS=""
if [ "${V7_VMP:-0}" = "1" ]; then
    V7_NOINLINE=1
    V7_SYMMAP=1
    # -mgeneral-regs-only          : 禁 NEON/FP（VMPacker 的 VM 只有 GPR）
    # -fno-optimize-sibling-calls  : 禁尾调用优化。
    #   否则编译器会把 `bl f; ret` 优化成 `b f`（尾跳），而 VMPacker 要求所有
    #   无条件 B 的目标必须落在函数区间内 —— 尾跳跳出函数会直接被判不支持。
    #   实测 v7_keys 就卡在这条：加此开关后变回 bl（OpCallNative 原生调用，支持）。
    # -fno-reorder-blocks-and-partition : 禁 hot/cold 块分割。
    #   否则 gcc 会把冷路径拆到 .text.unlikely 放在函数体之后，函数物理上不连续：
    #   主函数体有分支跳到冷块（超出"函数区间"→ VMPacker 判不支持），
    #   而按"下一个符号"取边界又会把冷块之后的邻居函数一起圈进去（→ SIGILL）。
    #   加了它函数才连续，边界才能算准。
    #
    # flag 可用性探测：这些是 GCC 选项，Termux 的 cc 是 clang，不认识其中
    # 部分（实测 clang 报 error: unknown argument: '-fno-reorder-blocks-and-
    # partition'）。clang 本来就不做 hot/cold 分割（那是 GCC 的优化），所以
    # 缺这条在 clang 下无损。逐个试编空程序，编译器不支持的自动剔除并提示。
    NOFP_WANT="-mgeneral-regs-only -fno-optimize-sibling-calls -fno-reorder-blocks-and-partition"
    NOFP_CFLAGS=""
    for f in $NOFP_WANT; do
        if echo 'int main(void){return 0;}' | "$V7_CC" -x c $f -o /dev/null - >/dev/null 2>&1; then
            NOFP_CFLAGS="$NOFP_CFLAGS $f"
        else
            echo "信息：$V7_CC 不支持 $f（clang 无此选项/等价行为默认开启），自动跳过" >&2
        fi
    done
    [ -n "$NOFP_CFLAGS" ] || echo "警告：V7_VMP=1 的全部 -mgeneral-regs 类选项被编译器拒绝，产物可能含 NEON" >&2
    # V7_VMP_BUILD：关闭反调试④时间窗（3000ms）—— VM 解释执行天然慢，
    # 9 函数批量 VMP 后解密超 3s 会被自己的时间侧信道检测误杀（r10.2 实测）
    NOFP_CFLAGS="$NOFP_CFLAGS -DV7_VMP_BUILD"
fi
# V7_NOINLINE=1：让关键 crypto/校验函数不被 -O2 内联（配合 VMP 逐函数保护）
NI_CFLAGS=""
[ "${V7_NOINLINE:-0}" = "1" ] && NI_CFLAGS="-DV7_NOINLINE"

# ---- per-build 常量随机化 ----
# V7_RAND_LABEL=1 ：每次构建换一组域分离标签（V7ENC/V7MAC）与落盘文件前缀，
#                   → `strings x.elf | grep V7` 这类通用检测直接失效
# V7_LABEL_OBF=1  ：标签进一步以 XOR 混淆的字节数组存放、运行时解开，
#                   → rodata 里连可打印串都没有，单样本 strings 也搜不到
# 两者可叠加。标签参与密钥派生，所以不同标签的产物互不兼容（特性）。
# 需要锁定标签时：V7_LABEL_ENC=xxx V7_LABEL_MAC=yyy（不指定则随机生成）
LABEL_CFLAGS=""
if [ "${V7_RAND_LABEL:-0}" = "1" ] || [ "${V7_LABEL_OBF:-0}" = "1" ] \
   || [ -n "${V7_LABEL_ENC:-}" ] || [ -n "${V7_LABEL_MAC:-}" ]; then
    LABEL_CFLAGS="$(python3 - "${V7_RAND_LABEL:-0}" "${V7_LABEL_OBF:-0}" \
                             "${V7_LABEL_ENC:-}" "${V7_LABEL_MAC:-}" <<'PYLABEL'
import os, sys
rand, obf, e_fix, m_fix = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
AL = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
def tok(n):
    b = os.urandom(n * 4)
    return ''.join(AL[x % len(AL)] for x in b[:n])
# 允许调用方锁定标签（回归测试/多产物互操作用），否则每次随机
enc = e_fix or (tok(int(9 + os.urandom(1)[0] % 6)) if rand == '1' else 'V7ENC')
mac = m_fix or (tok(int(9 + os.urandom(1)[0] % 6)) if rand == '1' else 'V7MAC')
while mac == enc:
    mac = tok(11)
pre = '.' + tok(7) + '.' if rand == '1' else '.v7x.'
if obf == '1' and rand != '1' and not e_fix:
    enc, mac = 'V7ENC', 'V7MAC'          # 只混淆、不换值
x = os.urandom(1)[0] or 0x5a
def arr(s):
    return '{' + ','.join('0x%02x' % (ord(c) ^ x) for c in s) + '}'
out = []
# 诱饵哨兵的 env 名：非口令模式下无功能意义，随机化掉以免泄露工具身份。
# 口令模式真正在用的 V7_PASSFD 保持原样（用户要拿它传口令，不能随机）。
if rand == '1':
    out += ['-DV7_SENTRY_FD="%s"' % ('_' + tok(12)),
            '-DV7_SENTRY_PASS="%s"' % ('_' + tok(12))]
if obf == '1':
    out += ['-DV7_LABEL_OBF',
            '-DV7_LB_ENC_OBF=' + arr(enc), '-DV7_LB_ENC_LEN=%d' % len(enc),
            '-DV7_LB_MAC_OBF=' + arr(mac), '-DV7_LB_MAC_LEN=%d' % len(mac),
            '-DV7_LB_XOR=0x%02x' % x]
    shown = '<obfuscated len=%d/%d xor=0x%02x>' % (len(enc), len(mac), x)
else:
    out += ['-DV7_LABEL_ENC="%s"' % enc, '-DV7_LABEL_MAC="%s"' % mac]
    shown = '"%s" / "%s"' % (enc, mac)
out += ['-DV7_TMP_PREFIX="%s"' % pre]
sys.stderr.write('信息：per-build 常量随机化 —— 标签 %s，落盘前缀 "%s"\n' % (shown, pre))
print(' '.join(out))
PYLABEL
)" || { echo "错误：标签随机化失败（需要 python3）" >&2; exit 1; }
fi

# ---- Termux 环境识别（三重信号任一命中；上移供冒烟测试/链接策略共用）----
IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]; then
    IS_TERMUX=1
elif [ -n "${PREFIX:-}" ] && [ "${PREFIX#*com.termux}" != "$PREFIX" ]; then
    IS_TERMUX=1
fi

# ---- 定位 V6 混淆器（多路径查找，杜绝硬编码）----
# 顺序：V7_OBF 环境变量 → 包内 ../v6/（zip 解压布局）→ 同目录 → 开发沙箱路径
if [ -z "${V7_OBF:-}" ]; then
    # 注意：脚本头部已 cd 进自身目录，_self_dir 即脚本目录（第 35 行已取）。
    # 切勿再用相对 $0 二次推导 —— 头部 cd 之后 $0 的相对路径已失效，
    # "bash v7/v7_build.sh"（从包根调用）会把 _self_dir 推导成空串。
    for _cand in "$_self_dir/../v6/shell_script_obfuscator_v6.sh" \
                 "$_self_dir/shell_script_obfuscator_v6.sh" \
                 /workspace/shell_script_obfuscator_v6.sh; do
        if [ -f "$_cand" ]; then
            V7_OBF="$_cand"
            break
        fi
    done
fi
command -v "$V7_CC" >/dev/null 2>&1 || { echo "错误：编译器 $V7_CC 不可用" >&2; exit 1; }
[ -n "${V7_OBF:-}" ] && [ -f "$V7_OBF" ] || {
    echo "错误：找不到 V6 混淆器 shell_script_obfuscator_v6.sh" >&2
    echo "  已查找：V7_OBF 环境变量、\$(脚本目录)/../v6/、脚本目录本身" >&2
    echo "  解法：确认解压了完整 zip（v6/ 与 v7/ 同级），或显式指定：" >&2
    echo "        V7_OBF=路径/shell_script_obfuscator_v6.sh bash v7_build.sh ..." >&2
    exit 1
}

# ---- 自动编译加密器 blobgen（免手动 cc -o blobgen blobgen.c）----
# blobgen 也 include crypto_core.h 并调用 v7_keys —— 它必须和运行端用同一组
# 标签，否则加解密两侧公式分叉。所以标签/内联开关一变就强制重编译。
# 注意：blobgen 是【构建主机】上跑的工具（用来预加密骨架），必须用主机 C 编译器，
# 与 V7_CC（目标产物编译器，可能交叉到 aarch64）无关。否则用 V7_CC=aarch64-...
# 时 blobgen 会被交叉编译成 aarch64 二进制，主机执行直接 /lib/ld 报错。
_bg_stamp=".blobgen.stamp"
_bg_want="cc|$NI_CFLAGS|$LABEL_CFLAGS"
if [ ! -x ./blobgen ] || [ "$(cat "$_bg_stamp" 2>/dev/null)" != "$_bg_want" ]; then
    [ -f ./blobgen.c ] || { echo "错误：./blobgen 不存在且找不到 blobgen.c" >&2; exit 1; }
    [ -x ./blobgen ] || echo "信息：首次运行，编译加密器 blobgen（主机 cc）..."
    cc -O2 $NI_CFLAGS $LABEL_CFLAGS -o blobgen blobgen.c || {
        echo "错误：blobgen 编译失败" >&2
        exit 1
    }
    printf '%s' "$_bg_want" > "$_bg_stamp"
fi

# ---- 全内置模式：定位静态 bash ----
BASHBIN=""; BASH_TGT=""
if [ "$V7_SELF" = "1" ]; then
    # 目标架构：交叉编译器名优先，否则本机架构
    case "$V7_CC" in
        *aarch64*) BASH_TGT="aarch64" ;;
        *) case "$(uname -m)" in
               aarch64|arm64) BASH_TGT="aarch64" ;;
               *)             BASH_TGT="$(uname -m)" ;;
           esac ;;
    esac
    if [ -n "${V7_BASH:-}" ]; then
        BASHBIN="$V7_BASH"
    else
        for _b in "$_self_dir/static/bash-$BASH_TGT" "$_self_dir/static/bash"; do
            [ -f "$_b" ] && BASHBIN="$_b" && break
        done
    fi
    if [ -z "$BASHBIN" ] || [ ! -f "$BASHBIN" ]; then
        echo "错误：全内置模式需要静态 bash 二进制" >&2
        echo "  已查找：V7_BASH 环境变量、v7/static/bash-$BASH_TGT" >&2
        echo "  解法一：用包内预置（v7/static/bash-aarch64 / bash-x86_64）" >&2
        echo "  解法二：自备静态 bash 后 V7_BASH=路径 bash v7_build.sh ...（构建方法见 README）" >&2
        exit 1
    fi
    # 冒烟（仅同架构可本机运行；交叉目标靠 qemu/真机验证）
    # 术语：app 域 = Termux 进程（untrusted_app）；shell 域 = adb shell。
    # glibc 静态二进制在 app 域会被 seccomp 拦截（SIGSYS，shell 显示
    # "Unknown signal 31"），但 shell 域白名单更宽、同一二进制可正常跑 ——
    # 在 Termux 里冒烟失败≠二进制坏了，降级为警告继续；桌面 Linux 上失败
    # 才是真坏。V7_SMOKE=0 可整体跳过（如已确认目标的运行环境）。
    #
    # r10.2 修正：rc=126（"found but not executable"）之前被一刀切判
    # "架构不符"直接终止 —— 但 126 在 Termux 上最常见成因只是 zip/网盘
    # 搬运丢了执行权限位。改为三段式：
    #   ① 缺 x 位自动 chmod（最常见，自愈）
    #   ② ELF 头校验魔数 + e_machine 架构（无需执行文件，判"真坏"更可靠）
    #   ③ 冒烟失败：Termux 一律警告继续（159/126 皆然）；桌面才终止
    _host_arch="$(uname -m)"
    [ "$_host_arch" = "arm64" ] && _host_arch="aarch64"
    if [ "${V7_SMOKE:-1}" = "0" ]; then
        echo "警告：V7_SMOKE=0 跳过内嵌 bash 冒烟测试（自担风险）" >&2
    elif [ "$BASH_TGT" = "$_host_arch" ]; then
        if [ ! -x "$BASHBIN" ]; then
            chmod +x "$BASHBIN" 2>/dev/null || true
            echo "信息：内嵌 bash 缺执行权限位，已自动 chmod +x（zip 搬运常见）" >&2
        fi
        # ELF 头：魔数 7f 45 4c 46；e_machine @ 偏移 18（2 字节小端）
        # aarch64=183(0xB7) x86_64=62(0x3E) —— 架构不符/损坏在这里拦住
        _magic=$(od -An -tx1 -N4 "$BASHBIN" 2>/dev/null | tr -d ' \n')
        if [ "$_magic" != "7f454c46" ]; then
            echo "错误：$BASHBIN 不是有效的 ELF 文件（魔数 $_magic，文件损坏？）" >&2
            exit 1
        fi
        _raw=$(od -An -tx1 -j18 -N2 "$BASHBIN" 2>/dev/null | tr -d ' \n')
        _em=$((16#${_raw:2:2}${_raw:0:2}))
        _want=183; [ "$BASH_TGT" = "x86_64" ] && _want=62
        if [ "$_em" != "$_want" ]; then
            echo "错误：$BASHBIN 架构不符（e_machine=$_em，期望 $_want）" >&2
            echo "       目标 $BASH_TGT 需要对应的静态 bash，见 README 构建方法" >&2
            exit 1
        fi
        "$BASHBIN" -c 'printf ok' >/dev/null 2>&1
        _sm_rc=$?
        if [ "$_sm_rc" != "0" ]; then
            if [ "$IS_TERMUX" = "1" ]; then
                echo "警告：内嵌 bash 在 Termux 内冒烟失败（rc=$_sm_rc）—— 构建继续。" >&2
                echo "       典型为 glibc 静态二进制被 app 域 seccomp 拦截（SIGSYS /" >&2
                echo "       Unknown signal 31）；ELF 头已校验架构无误，运行期以此为准。" >&2
                echo "       adb shell（shell 域）不受此限制；产物要在 Termux 内跑请换" >&2
                echo "       musl 静态 bash（见 README）。" >&2
            else
                echo "错误：$BASHBIN 冒烟测试失败（rc=$_sm_rc，架构不符或文件损坏）" >&2
                exit 1
            fi
        fi
    fi
    # 内嵌 bash 主版本 → V6 TARGET_BASH_MAJOR（密钥掺 BASH_VERSINFO[0]，
    # 构建机 bash 与内嵌 bash 主版本不一致时运行期必静默死）。从二进制内的
    # 版本串提取、无需执行 —— Termux 里 glibc 静态 bash 可能被 seccomp
    # 拦截根本跑不了 --version。grep -a 免 binutils（strings）依赖。
    _bm=$(grep -aoE 'Bash version [0-9]+\.' "$BASHBIN" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    if [ -n "$_bm" ]; then
        if [ "$_bm" != "${BASH_VERSINFO[0]}" ]; then
            echo "信息：内嵌 bash 主版本 $_bm ≠ 构建机 bash ${BASH_VERSINFO[0]}，密钥按内嵌版本派生"
        fi
        export TARGET_BASH_MAJOR="$_bm"
    fi
    echo "信息：全内置模式 —— 内嵌 bash：$BASHBIN（$(wc -c < "$BASHBIN") 字节，目标 $BASH_TGT）"
fi

# ---- 密码学模式：全内置默认 builtin（裸环境无 openssl）----
if [ -n "${CRYPTO_MODE:-}" ]; then
    V6_MODE="$CRYPTO_MODE"
elif [ "$V7_SELF" = "1" ]; then
    V6_MODE="builtin"
else
    V6_MODE="aes"
fi
if [ "$V7_SELF" = "1" ] && [ "$V6_MODE" != "builtin" ]; then
    echo "警告：全内置模式 + $V6_MODE —— 裸环境无 openssl 时骨架会在运行期失败；" >&2
    echo "       建议 unset CRYPTO_MODE（自动 builtin）" >&2
fi

# ---- 1. V6 混淆 ----
# ANDROID_GATE 显式透传（默认 1=生产：仅安卓环境可跑；沙箱/桌面测试设 0）
SKEL="v7_skel_$$.sh"
if ! env $V7_V6OPTS CRYPTO_MODE="$V6_MODE" ANDROID_GATE="${ANDROID_GATE:-1}" \
        bash "$V7_OBF" "$IN" "$SKEL" > "v7_compile_$$.log" 2>&1; then
    echo "错误：V6 混淆失败（详见 v7_compile_$$.log）" >&2
    tail -5 "v7_compile_$$.log" >&2
    exit 1
fi
echo "信息：V6 骨架完成（$(wc -c < "$SKEL") 字节，crypto=$V6_MODE）"

# ---- 1b. r19：V7_SELF 模式骨架参数偏移修正 ----
# 成因：zread 只接管「脚本输入 fd」，bash 必须先打开一个文件当脚本才会触发
#   劫持 → 加载器强制补 /dev/null 占位（见 v7_wrap.sh）；该占位符会占据
#   骨架的 $1，用户参数被整体挤到 $2 起（$0 显示为 /proc/self/fd/4）。
# 修法：骨架最前面插入一次条件 shift（仅 V7_SELF 模式、且确实被注入时生效）。
#   普通模式 / 未走 wrap 的手工执行均不受影响。
# 关闭：V7_SKEL_SHIFT=0 保留旧契约（参数从 $2 读）。
#
# r34 跨解释器修复（mksh 全链路冒烟实测）：原写法 `[ -n "$V7_SELF" ] && shift`
#   在【位置参数为空】时有致命差异 ——
#     bash：shift 失败 → 语句返回非零 → 脚本**继续**执行（顶层非 set -e）；
#     mksh：`shift: nothing to shift` → **当场终止脚本**，rc=1，全程零输出。
#   ELF 全内置形态正是"无用户参数"（argv = [bash, /proc/self/fd/N, /dev/null]，
#   占位符已被 V7 逻辑吞掉）⇒ 一旦内嵌解释器换成 mksh，骨架第一行即死，
#   症状与"解密失败"完全一样（静默 rc，极易误判）。
#   加 `[ "$#" -gt 0 ]` 守卫后两侧行为一致；bash 侧语义不变（原本也是空参
#   时 shift 失败、无实际操作）。
if [ "$V7_SELF" = "1" ] && [ "${V7_SKEL_SHIFT:-1}" = "1" ]; then
    _skel_tmp="${SKEL}.shift.$$"
    _skel_shift_line='[ -n "$V7_SELF" ] && [ "$#" -gt 0 ] && shift'
    if head -n 1 "$SKEL" | grep -q '^#!'; then
        { head -n 1 "$SKEL"; printf '%s\n' "$_skel_shift_line"; tail -n +2 "$SKEL"; } > "$_skel_tmp"
    else
        { printf '%s\n' "$_skel_shift_line"; cat "$SKEL"; } > "$_skel_tmp"
    fi
    mv -f "$_skel_tmp" "$SKEL"
    echo "信息：已注入骨架参数修正（V7_SELF 模式 shift，V7_SKEL_SHIFT=0 可关闭）"
fi

# ---- 2/3. seed + 加密 ----
# 口令模式（r10 P0）：V7_PASSKEY=1 时 seed 从口令 + salt 经 scrypt-like KDF 派生
# 口令永不落盘——文件在手无口令时静态分析物理解不开
# V7_PASS 环境变量传口令（构建端）；运行端经 stdin/V7_PASSFD 读入
# V7_PASS_N 可覆盖 scrypt N 参数（默认 131072=16MB；测试用小值如 1024）
V7_PASSKEY="${V7_PASSKEY:-0}"
PASS_SALT=""; PASS_N="0"
if [ "$V7_PASSKEY" = "1" ]; then
    # 生成随机 salt（16 字节，内嵌非机密——每次构建不同）
    PASS_SALT=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    [ ${#PASS_SALT} -eq 32 ] || { echo "错误：pass salt 生成失败" >&2; exit 1; }
    PASS_N="${V7_PASS_N:-0}"
    # 获取口令：V7_PASS 环境变量优先，否则交互输入
    if [ -z "${V7_PASS:-}" ]; then
        printf "请输入口令（不回显）: " >&2
        read -rs V7_PASS </dev/tty
        printf "\n" >&2
    fi
    [ -n "$V7_PASS" ] || { echo "错误：口令为空" >&2; exit 1; }
    # 用 blobgen passkdf 派生 seed（scrypt-like KDF，与 elfrun 运行期同算法）
    SEED=$(printf '%s' "$V7_PASS" | ./blobgen passkdf "$PASS_SALT" "$PASS_N")
    [ ${#SEED} -eq 64 ] || { echo "错误：口令 KDF 派生失败" >&2; exit 1; }
    echo "信息：口令模式 —— seed 已从口令派生（scrypt-like KDF，salt $PASS_SALT，N=${PASS_N:-默认}）"
    # 抹口令变量
    V7_PASS="${V7_PASS//?/x}"
elif [ -n "${V7_SEED_HEX:-}" ]; then
    # V7_SEED_HEX 可注入固定 seed（测试用：篡改测试需定位内嵌密文区）
    SEED="$V7_SEED_HEX"
else
    SEED=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
fi
[ ${#SEED} -eq 64 ] || { echo "错误：seed 生成失败" >&2; exit 1; }

# 白盒密钥编码（r10）：V7_WB=1 且非口令模式时，seed 不以明文嵌入，
# 改为通过 per-build 随机化查找表编码。攻击者不能 grep 出 seed。
# 口令模式不需要白盒（seed 不在文件里）。
V7_WB="${V7_WB:-0}"
WB_TABLE=""; WB_PERM=""; WB_MASK=""
if [ "$V7_WB" = "1" ] && [ "$V7_PASSKEY" != "1" ]; then
    # 用 blobgen wbenc 生成白盒表
    WB_OUT=$(./blobgen wbenc "$SEED")
    WB_TABLE=$(echo "$WB_OUT" | sed -n '1p')
    WB_PERM=$(echo "$WB_OUT" | sed -n '2p')
    WB_MASK=$(echo "$WB_OUT" | sed -n '3p')
    [ ${#WB_TABLE} -eq 512 ] && [ ${#WB_PERM} -eq 512 ] && [ ${#WB_MASK} -eq 512 ] || {
        echo "错误：白盒表生成失败" >&2; exit 1
    }
    echo "信息：白盒模式 —— seed 已编码为查找表（256+256+256 字节，per-build 随机化）"
fi

CT="v7_ct_$$.bin"; TAG="v7_tag_$$.txt"
if [ -n "${V7_SEED_HEX:-}" ]; then
    # 测试模式：固定文件名，供篡改测试读取密文
    CT="v7_ct.bin"; TAG="v7_tag.txt"
    rm -f "$CT" "$TAG"
fi
if ! ./blobgen enc "$SEED" "$SKEL" "$CT" "$TAG"; then
    echo "错误：blob 加密失败" >&2; exit 1
fi
TAGV=$(cat "$TAG")
[ ${#TAGV} -eq 32 ] || { echo "错误：tag 异常" >&2; exit 1; }
echo "信息：blob 加密完成（密文 $(wc -c < "$CT") 字节，tag $TAGV）"

# ---- 3b. 全内置：bash blob 加密（独立 seed，与骨架互不牵连）----
BSEED=""; BCT=""; BTAG=""; BTAGV=""
if [ "$V7_SELF" = "1" ]; then
    if [ -n "${V7_BASH_SEED_HEX:-}" ]; then
        BSEED="$V7_BASH_SEED_HEX"
    else
        BSEED=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    fi
    [ ${#BSEED} -eq 64 ] || { echo "错误：bash seed 生成失败" >&2; exit 1; }
    BCT="v7_bash_ct_$$.bin"; BTAG="v7_bash_tag_$$.txt"
    if [ -n "${V7_SEED_HEX:-}" ]; then
        # 测试模式：固定文件名，供篡改测试定位 bash 密文区
        BCT="v7_bash_ct.bin"; BTAG="v7_bash_tag.txt"
        rm -f "$BCT" "$BTAG"
    fi
    if ! ./blobgen enc "$BSEED" "$BASHBIN" "$BCT" "$BTAG"; then
        echo "错误：bash blob 加密失败" >&2; exit 1
    fi
    BTAGV=$(cat "$BTAG")
    [ ${#BTAGV} -eq 32 ] || { echo "错误：bash tag 异常" >&2; exit 1; }
    echo "信息：内嵌 bash 加密完成（密文 $(wc -c < "$BCT") 字节，tag $BTAGV）"
fi

# ---- 4. 生成 C 源 ----
GEN="v7_gen_$$.c"
python3 - "$SEED" "$TAGV" "$CT" "elfrun.c" "$GEN" \
         "$V7_SELF" "$BSEED" "$BTAGV" "$BCT" \
         "$V7_PASSKEY" "$PASS_SALT" "$PASS_N" \
         "$V7_WB" "$WB_TABLE" "$WB_PERM" "$WB_MASK" <<'PYEOF'
import sys
import re

seed_hex, tag_hex, ct_path, tpl_path, out_path = sys.argv[1:6]
self_mode, bseed_hex, btag_hex, bct_path = sys.argv[6:10]
pass_mode, pass_salt_hex, pass_n = sys.argv[10:13]
wb_mode, wb_table_hex, wb_perm_hex, wb_mask_hex = sys.argv[13:17]

seed = bytes.fromhex(seed_hex)
tag = bytes.fromhex(tag_hex)
ct = open(ct_path, 'rb').read()

tpl = open(tpl_path, encoding='utf-8').read()

def c_array(name, data, per_line=16):
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        lines.append('    ' + ','.join('0x%02x' % b for b in chunk) + (',' if i + per_line < len(data) else ''))
    return 'static const unsigned char %s[] = {\n%s\n};' % (name, '\n'.join(lines))

# 替换 seed 数组（模板里是 V7_SEED[32] = { ... } 16 字节×2 行占位）
new_seed = c_array('V7_SEED', seed)
tpl, n1 = re.subn(r'static const unsigned char V7_SEED\[32\] = \{.*?\};', new_seed, tpl, count=1, flags=re.S)
assert n1 == 1, 'seed 模板未匹配'

# 替换 tag 数组
new_tag = c_array('V7_TAG', tag)
tpl, n2 = re.subn(r'static const unsigned char V7_TAG\[16\] = \{.*?\};', new_tag, tpl, count=1, flags=re.S)
assert n2 == 1, 'tag 模板未匹配'

# 替换密文数组（模板里 V7_CT[] = { 0x00 } 占位）
new_ct = c_array('V7_CT', ct)
tpl, n3 = re.subn(r'static const unsigned char V7_CT\[\] = \{.*?\};', new_ct, tpl, count=1, flags=re.S)
assert n3 == 1, 'ct 模板未匹配'

# 口令模式：填入 V7_PASS_SALT + 置 V7_PASS_MODE=1 + V7_PASS_N
pass_extra = ''
if pass_mode == '1':
    salt = bytes.fromhex(pass_salt_hex)
    tpl, np1 = re.subn(r'static const unsigned char V7_PASS_SALT\[16\] = \{.*?\};',
                       c_array('V7_PASS_SALT', salt), tpl, count=1, flags=re.S)
    assert np1 == 1, 'V7_PASS_SALT 模板未匹配'
    tpl, np2 = re.subn(r'#define V7_PASS_MODE 0', '#define V7_PASS_MODE 1', tpl, count=1)
    assert np2 == 1, 'V7_PASS_MODE 模板未匹配'
    # V7_PASS_N：非零时替换
    n_val = int(pass_n) if pass_n else 0
    if n_val > 0:
        tpl = re.sub(r'static const unsigned int V7_PASS_N = 0;',
                     'static const unsigned int V7_PASS_N = %d;' % n_val, tpl)
    pass_extra = '，口令模式（scrypt-like KDF，salt %d 字节）' % len(salt)

# 白盒模式：填入 WB_TABLE/PERM/MASK + 置 V7_WB_MODE=1
wb_extra = ''
if wb_mode == '1' and pass_mode != '1':
    wb_table = bytes.fromhex(wb_table_hex)
    wb_perm = bytes.fromhex(wb_perm_hex)
    wb_mask = bytes.fromhex(wb_mask_hex)
    tpl, nw1 = re.subn(r'static const unsigned char V7_WB_TABLE\[V7_WB_TABLE_SIZE\] = \{.*?\};',
                       c_array('V7_WB_TABLE', wb_table), tpl, count=1, flags=re.S)
    assert nw1 == 1, 'V7_WB_TABLE 模板未匹配'
    tpl, nw2 = re.subn(r'static const unsigned char V7_WB_PERM\[V7_WB_TABLE_SIZE\] = \{.*?\};',
                       c_array('V7_WB_PERM', wb_perm), tpl, count=1, flags=re.S)
    assert nw2 == 1, 'V7_WB_PERM 模板未匹配'
    tpl, nw3 = re.subn(r'static const unsigned char V7_WB_MASK\[V7_WB_TABLE_SIZE\] = \{.*?\};',
                       c_array('V7_WB_MASK', wb_mask), tpl, count=1, flags=re.S)
    assert nw3 == 1, 'V7_WB_MASK 模板未匹配'
    tpl, nw4 = re.subn(r'#define V7_WB_MODE 0', '#define V7_WB_MODE 1', tpl, count=1)
    assert nw4 == 1, 'V7_WB_MODE 模板未匹配'
    wb_extra = '，白盒密钥编码（256B×3 表）'

extra = ''
if self_mode == '1':
    bseed = bytes.fromhex(bseed_hex)
    btag = bytes.fromhex(btag_hex)
    bct = open(bct_path, 'rb').read()
    tpl, n4 = re.subn(r'#define V7_HAVE_BASH 0', '#define V7_HAVE_BASH 1', tpl, count=1)
    assert n4 == 1, 'V7_HAVE_BASH 模板未匹配'
    tpl, n5 = re.subn(r'static const unsigned char BASH_SEED\[32\] = \{.*?\};',
                      c_array('BASH_SEED', bseed), tpl, count=1, flags=re.S)
    assert n5 == 1, 'bash seed 模板未匹配'
    tpl, n6 = re.subn(r'static const unsigned char BASH_TAG\[16\] = \{.*?\};',
                      c_array('BASH_TAG', btag), tpl, count=1, flags=re.S)
    assert n6 == 1, 'bash tag 模板未匹配'
    tpl, n7 = re.subn(r'static const unsigned char BASH_CT\[\] = \{.*?\};',
                      c_array('BASH_CT', bct), tpl, count=1, flags=re.S)
    assert n7 == 1, 'bash ct 模板未匹配'
    extra = '，内嵌 bash %d 字节' % len(bct)

open(out_path, 'w', encoding='utf-8').write(tpl)
print('信息：elfrun_gen.c 生成（密文 %d 字节%s%s%s）' % (len(ct), extra, pass_extra, wb_extra))
PYEOF
[ -f "$GEN" ] || { echo "错误：C 源生成失败" >&2; exit 1; }

# ---- 5. 编译 ELF ----
# 链接策略（V7_STATIC 环境变量）：
#   auto（默认）：先静态（零依赖，可脱离 Termux 在 adb shell 裸环境跑），
#                失败按 Termux ndk-multilib 布局补 -L 重试，仍失败自动回退动态
#   1：强制静态 —— Termux 必须先 pkg install ndk-multilib（Bionic 静态库
#      libc.a/libm.a/libdl.a 在这个包里；Termux 没有 libc-static 包，
#      缺库时报 "ld.lld: error: unable to find library -lc"）
#   0：直接动态（体积小 ~40%，但依赖目标机系统库）
STATIC_MODE="${V7_STATIC:-auto}"
# IS_TERMUX 已在脚本头部识别（上移，冒烟测试也要用）
# 本机 ABI 对应的 ndk-multilib 目录名（uname -m → NDK triple）
ML_TRIPLE=""
case "$(uname -m)" in
    aarch64|arm64) ML_TRIPLE="aarch64-linux-android" ;;
    armv7*|armv8l|arm) ML_TRIPLE="arm-linux-androideabi" ;;
    x86_64) ML_TRIPLE="x86_64-linux-android" ;;
    i686|i386) ML_TRIPLE="i686-linux-android" ;;
esac
cc_link() {  # $1=额外链接参数
    # DIAG_CFLAGS：V7_DIAG=1 时 -DV7_DIAG（含诊断的排障版）；
    # 默认为空 = 生产模式（诊断代码与提示串编译期剔除）
    # V7_CFLAGS_EXTRA：额外编译开关（测试钩子，如 -DV7_TEST_FORCE_DISKEXEC
    # 强制走落盘兜底链，用于模拟 Android SELinux 拒绝匿名 exec 的场景）
    # NI_CFLAGS：V7_NOINLINE=1 时 -DV7_NOINLINE，禁止 -O2 把 v7_keys/v7_crypt/
    # v7_tag/v7_wb_decode/blob_verify 等内联进 main。这些函数会各自保留为独立
    # 的 sub_xxxxxx，交给 VMP/代码虚拟化工具逐个体保护时能精确勾选。
    # 代价：多几次函数调用 + 边界更清晰（也更容易被静态定位），
    # 所以只在"确实要上 VMP"时才开，默认关闭。
    # 注意：这里**故意不加 -s**（-s 会让链接器直接 strip，符号表还没来得及
    # 导出就没了）。strip 统一放到 5b 的 anti-disassembly 步骤做，
    # 中间经过 5a-b 的符号表快照，产物最终结果不变。
    # NOFP_CFLAGS：V7_VMP=1 时的 -mgeneral-regs-only（目标架构禁用 NEON）。
    # 只作用于目标产物，不加到 blobgen（主机工具、架构可能不支持该标志）。
    "$V7_CC" -O2 $DIAG_CFLAGS $NI_CFLAGS $NOFP_CFLAGS $LABEL_CFLAGS ${V7_CFLAGS_EXTRA:-} $1 -o "$OUT" "$GEN" 2> "v7_cc_$$.log"
}
cc_fail() {
    echo "错误：ELF 编译失败（详见 v7_cc_$$.log）" >&2
    cat "v7_cc_$$.log" >&2
    exit 1
}
# 静态链接重试链：裸 -static → lld → ndk-multilib 两级 -L
# （clang 通常能自动解析 ndk-multilib 的库；异常时按包实际布局补路径）
try_static() {
    cc_link "-static" && return 0
    if [ "$IS_TERMUX" = "1" ]; then
        cc_link "-static -fuse-ld=lld" && return 0
        if [ -n "$ML_TRIPLE" ]; then
            for _ml in "$PREFIX/$ML_TRIPLE/lib" \
                       "$PREFIX/opt/ndk-multilib/$ML_TRIPLE/lib"; do
                if [ -f "$_ml/libc.a" ]; then
                    cc_link "-static -L$_ml" && return 0
                fi
            done
        fi
    fi
    return 1
}
case "$STATIC_MODE" in
    1)
        try_static || {
            echo "错误：静态链接失败（Termux 需先 pkg install ndk-multilib；" >&2
            echo "       或设 V7_STATIC=0 用动态链接）" >&2
            cat "v7_cc_$$.log" >&2
            exit 1
        }
        ;;
    0)
        cc_link "" || cc_fail
        ;;
    *)
        if ! try_static; then
            echo "警告：静态链接不可用，回退动态链接（Termux 装静态库：pkg install ndk-multilib）" >&2
            cc_link "" || cc_fail
        fi
        ;;
esac

# ---- 5a-b. 导出符号表快照（必须在 strip 之前！）----
# strip 之后 IDA / Ghidra / VMP 工具只看到 sub_xxxxxx，没法把地址和函数名对上。
# 这里在抹掉符号之前先把"<地址> <大小> <名字>"存成 .map，之后用
#   tools/vmp_targets.py <elf> --map <elf>.map
# 就能直接得到 "v7_keys -> sub_423130" 这样的对照表。
# map 文件是本地排障/加固用的，**不要随发行版一起发出去**。
if [ "${V7_SYMMAP:-1}" = "1" ] && [ -f "$OUT" ]; then
    if command -v readelf >/dev/null 2>&1; then
        # 只用 awk 的可移植子集（mawk 没有 strtonum）：地址 + 名字两列就够
        readelf -sW "$OUT" 2>/dev/null \
          | awk '$4=="FUNC" && $8!="" {print "0x" $2, $8}' > "$OUT.map" 2>/dev/null
    elif command -v nm >/dev/null 2>&1; then
        nm -S --defined-only "$OUT" 2>/dev/null \
          | awk '$2=="T"||$2=="t"{print "0x"$1, $2, $4}' > "$OUT.map" 2>/dev/null
    fi
    if [ -s "$OUT.map" ]; then
        echo "符号表快照   : $OUT.map（$(wc -l < "$OUT.map") 条，本地保留，勿随发行版分发）"
    else
        rm -f "$OUT.map"
        [ "${V7_SYMMAP:-1}" = "1" ] && \
            echo "提示：未能导出符号表（无 readelf/nm），VMP 定位将退化为启发式" >&2
    fi
fi

# ---- 5b. anti-disassembly ELF 后处理 ----
# strip section headers + 删除符号表/notes → readelf -S / objdump 线性反汇编
# 在入口处断掉。不改变程序行为，只让自动化逆向工具链失去路标。
# objcopy 可用时执行；不可用时降级为 strip --strip-all（仍有部分效果）
# V7_NO_ANTIDISASM=1 可跳过（排障/特殊工具链兼容）—— 但此时产物**保留完整
# 符号表**，只用于本地排障，切勿分发。
if [ "${V7_NO_ANTIDISASM:-0}" != "1" ] && [ -f "$OUT" ]; then
    if command -v objcopy >/dev/null 2>&1; then
        # 删除符号表、字符串表、note 段、comment 段
        objcopy -R .symtab -R .strtab -R .note -R .comment -R .note.gnu.build-id \
                "$OUT" "$OUT.anti" 2>/dev/null && mv "$OUT.anti" "$OUT"
        strip --strip-all "$OUT" 2>/dev/null || true
    elif command -v strip >/dev/null 2>&1; then
        strip --strip-all "$OUT" 2>/dev/null || true
    fi
    # 清零 ELF section header table：让 readelf -S / objdump -h 报
    # "no section headers"——反汇编器只能靠字节模式分析，无节区路标。
    # Python3 跨平台，不改程序加载行为（program headers 不受影响）
    python3 - "$OUT" <<'PYSH_STRIP'
import sys, struct
path = sys.argv[1]
data = bytearray(open(path, 'rb').read())
if len(data) < 64 or data[:4] != b'\x7fELF':
    sys.exit(0)  # 非 ELF，跳过
ei_class = data[4]  # 1=32bit, 2=64bit
if ei_class == 2:
    # 64-bit ELF header: e_shoff at offset 40 (8 bytes), e_shnum at 60 (2 bytes),
    # e_shstrndx at 62 (2 bytes)
    e_shoff = struct.unpack_from('<Q', data, 40)[0]
    e_shnum = struct.unpack_from('<H', data, 60)[0]
    if e_shoff == 0 or e_shnum == 0:
        sys.exit(0)  # 已经无 section headers
    # 清零 section header table 区域
    shdr_size = 64 * e_shnum  # Elf64_Shdr = 64 bytes
    if e_shoff + shdr_size <= len(data):
        for i in range(e_shoff, e_shoff + shdr_size):
            data[i] = 0
    # 清零 ELF header 中的 e_shoff, e_shnum, e_shstrndx
    struct.pack_into('<Q', data, 40, 0)  # e_shoff = 0
    struct.pack_into('<H', data, 60, 0)  # e_shnum = 0
    struct.pack_into('<H', data, 62, 0)  # e_shstrndx = 0
elif ei_class == 1:
    # 32-bit ELF header: e_shoff at offset 32 (4 bytes), e_shnum at 48 (2 bytes),
    # e_shstrndx at 50 (2 bytes)
    e_shoff = struct.unpack_from('<I', data, 32)[0]
    e_shnum = struct.unpack_from('<H', data, 48)[0]
    if e_shoff == 0 or e_shnum == 0:
        sys.exit(0)
    shdr_size = 40 * e_shnum  # Elf32_Shdr = 40 bytes
    if e_shoff + shdr_size <= len(data):
        for i in range(e_shoff, e_shoff + shdr_size):
            data[i] = 0
    struct.pack_into('<I', data, 32, 0)
    struct.pack_into('<H', data, 48, 0)
    struct.pack_into('<H', data, 50, 0)
open(path, 'wb').write(data)
PYSH_STRIP
else
    echo "警告：V7_NO_ANTIDISASM=1 —— 产物保留完整符号表与节区头，" >&2
    echo "       仅供本地排障，切勿随发行版分发" >&2
fi

# ---- 收尾 ----
# 固定 seed 模式（测试）保留 ct/tag 文件供篡改测试精确定位密文区
if [ -z "${V7_SEED_HEX:-}" ]; then
    rm -f "$SKEL" "$CT" "$TAG" "$BCT" "$BTAG"
fi
rm -f "$GEN" "v7_compile_$$.log" "v7_cc_$$.log"
if [ "$V7_SELF" = "1" ]; then
    echo "成功：V7 ELF 已生成 '$OUT'（$(wc -c < "$OUT") 字节，全内置：内嵌 bash + builtin 密码学，可裸环境运行）"
else
    echo "成功：V7 ELF 已生成 '$OUT'（$(wc -c < "$OUT") 字节）"
    echo "提示：普通模式产物运行需目标机有 bash（Termux 天然满足；adb shell" >&2
    echo "      裸环境无 bash —— 需裸环境运行请加 V7_SELF=1 重新构建）" >&2
fi

# ---- 构建期环境风险预警（这些环境里运行产物会被反调试层自拒）----
_tp=$(awk '/^TracerPid:/{print $2}' /proc/self/status 2>/dev/null)
if [ "${_tp:-0}" != "0" ]; then
    echo "警告：当前构建环境 TracerPid=$_tp（proot 容器/被挂靠）。" >&2
    echo "       在此环境运行产物会触发反调试退出码 113（静默无输出）。" >&2
    echo "       解法：在原生 Termux 环境（非 proot-distro）构建并运行。" >&2
fi
if [ -n "${LD_PRELOAD:-}" ]; then
    echo "警告：当前环境 LD_PRELOAD=$LD_PRELOAD（termux-exec 等）。" >&2
    echo "       带此变量运行【裸 ELF】会触发反调试退出码 113（静默无输出）。" >&2
    echo "       解法：运行前 unset LD_PRELOAD，或用 V7_WRAP=1 出的自释放" >&2
    echo "       .sh（加载器自动剥离该变量）。" >&2
fi
echo "提示：产物运行若\"无任何效果\"，先看退出码 ——" >&2
echo "      ./$(basename "$OUT"); echo \$?   （113=反调试 114=完整性 1=骨架/环境）" >&2
if [ -n "$DIAG_CFLAGS" ]; then
    echo "      本产物含诊断：V7_DIAG=1 ./$(basename "$OUT") 打印各阶段进度与拒绝原因" >&2
else
    echo "      本产物为生产模式（诊断已编译剔除，设环境变量无效）；" >&2
    echo "      排障请重建：V7_DIAG=1 bash v7_build.sh <in> <out>" >&2
fi

# ---- 6. 可选 V7_WRAP=1：再包一层自释放 POSIX shell（单 .sh 交付）----
# 产物用 sh 执行：当前目录可写可执行 → 原地释放运行；否则回退
# /data/local/tmp → $TMPDIR → /tmp → $HOME（安卓 sdcard noexec 场景）
# V7_WRAP_KEEP=1 时同时保留 ELF；默认只留 .sh
if [ "${V7_WRAP:-0}" = "1" ]; then
    # 输出命名：*.elf → *.sh；*.sh → 原名（ELF 会被删，最终只剩 .sh）；其他 → 追加 .sh
    case "$OUT" in
        *.elf) WRAP_OUT="${OUT%.elf}.sh" ;;
        *.sh)  WRAP_OUT="$OUT" ;;
        *)     WRAP_OUT="$OUT.sh" ;;
    esac
    if V7_SELF_MODE="$V7_SELF" bash "$_self_dir/v7_wrap.sh" "$OUT" "$WRAP_OUT"; then
        # WRAP_OUT==OUT（无 .elf 后缀输入）时产物已就位，不能 rm；否则删裸 ELF
        if [ "${V7_WRAP_KEEP:-0}" != "1" ] && [ "$WRAP_OUT" != "$OUT" ]; then
            rm -f "$OUT"
        fi
        echo "成功：自释放 shell 已生成 '$WRAP_OUT'（V7_WRAP 模式）"
    else
        echo "错误：shell 包装失败" >&2
        exit 1
    fi
fi
