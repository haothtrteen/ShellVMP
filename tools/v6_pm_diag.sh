#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# v6_pm_diag.sh —— V6 产物「跑几个命令就没了」的根因定位器
#==============================================================================
# 背景：V6 产物内部有个环境指纹机制（混淆器第 874-885 行）：
#
#     _pm=1
#     [ $(( _p % 4 )) -eq 1 ] && {
#         [ "$(builtin type -t eval)" != builtin ]        && _pm=0
#         case $- in *x*)                                    _pm=0 ;; esac
#         [ -n "${BASH_XTRACEFD:-}" ]                     && _pm=0
#         [ "${PS4:-+ }" != "+ " ]                        && _pm=0
#         [ -n "${LD_PRELOAD:-}" ]                        && _pm=0
#         TracerPid != 0                                  && _pm=0
#     }
#     [ "$_pm" = 1 ] || _mk="${_mk}q"     # ★ 给主密钥追加一个字符
#
# _pm=0 → 主密钥被改错 → 后续块解密成乱码 → 解释器
# `[ -n "$_code" ] || exit 1` 静默退出。**不报错、没有提示**，
# 表现就是「执行几条命令就停下」。
#
# 用法（在出问题的设备上，用运行产物的同一个 shell 执行）：
#     bash v6_pm_diag.sh
#  诊断的是**当前 shell 环境**。若产物由别的进程启动（V7 ELF 内部），
#  需保证环境变量继承一致；必要时在产物外层 wrapper 里 source 本脚本。
#==============================================================================

hit=0
say() { printf '%s\n' "$*"; }

say "==================== V6 环境指纹诊断 ===================="
say ""

# ★★★ 最高频元凶：宿主开了 errexit（set -e）★★★
# V6 产物忠实还原 shell 语义：如果你的脚本里有任何返回非 0 的命令
# （裸 `false`、失败的 `grep`、不成立的 `[ ... ]` 作最后一条等），
# 而宿主 bash 开了 set -e → 脚本在此处【立即终止，退出码 1】。
# 原始脚本在同样环境下也会停在同一位置 —— 与混淆无关，无需查 V6。
# 混淆器第 957 行注释记录了同一个坑（解释器自身语句也应避免返回非 0）。
say "[0] errexit（最高频元凶）"
say "    \$- = '$-'    SHELLOPTS = '${SHELLOPTS:-<空>}'"
if [[ "$-" == *e* || "${SHELLOPTS:-}" == *errexit* ]]; then
    say "    >>> 命中：宿主开了 set -e"
    say "        你的脚本中返回非 0 的命令会直接中断后续执行（退出码 1）。"
    say "        确认：bash -e <原脚本> 应与产物停在同一处 → 属预期语义。"
    hit=1
else
    say "    ok（未启用 errexit）"
fi
say ""

say "[1] xtrace 是否开启（\$-）"
say "    当前 \$- = '$-'"
if [[ "$-" == *x* ]]; then
    say "    >>> 命中：V6 会判定为调试中，主密钥被污染"
    hit=1
else
    say "    ok"
fi
say ""

say "[2] PS4（必须是精确的 '+ '，含尾空格）"
say "    当前 PS4 = '${PS4:-<未设置>}'"
if [ "${PS4:-+ }" != "+ " ]; then
    say "    >>> 命中：PS4 只要被改过（含加时间戳(\\t)、加 $[0-9]）即判定调试"
    hit=1
else
    say "    ok"
fi
say ""

say "[3] LD_PRELOAD"
say "    当前 = '${LD_PRELOAD:-<空>}'"
if [ -n "${LD_PRELOAD:-}" ]; then
    say "    >>> 命中"
    hit=1
else
    say "    ok"
fi
say ""

say "[4] BASH_XTRACEFD"
say "    当前 = '${BASH_XTRACEFD:-<空>}'"
if [ -n "${BASH_XTRACEFD:-}" ]; then
    say "    >>> 命中"
    hit=1
else
    say "    ok"
fi
say ""

say "[5] eval 是否为内建"
t="$(builtin type -t eval 2>/dev/null)"
say "    builtin type -t eval = '$t'"
if [ "$t" != builtin ]; then
    say "    >>> 命中：不是 builtin 即判定被 alias/function 劫持"
    hit=1
else
    say "    ok"
fi
say ""

say "[6] TracerPid（非 0 = 正在被 ptrace）"
if [ -r /proc/self/status ]; then
    z=$(grep "^TracerPid:" /proc/self/status 2>/dev/null | tr -dc "0-9")
    say "    TracerPid = '${z:-<读不到>}'"
    if [ "${z:-0}" != "0" ]; then
        say "    >>> 命中：有进程正在 trace 本 shell"
        hit=1
    else
        say "    ok"
    fi
else
    say "    /proc/self/status 不可读（SELinux 域限制？）→ 该子项不触发 _pm=0"
fi
say ""

say "[7] 参考：EPOCHREALTIME 形态（__TL__ 超时项）"
say "    EPOCHREALTIME = '${EPOCHREALTIME:-<不支持>}'"
say "    注：该项在现版本写法有误（_t0 未去小数点，算术报错后整条短路），"
say "        实际不会造成 _pm=0，仅作记录。"
say ""

say "==================== 结论 ===================="
if [ "$hit" = 1 ]; then
    say "命中上列项目 → 这是产物「跑几条就停」的直接原因。"
    say ""
    say "处置："
    if [[ "$-" == *e* || "${SHELLOPTS:-}" == *errexit* ]]; then
        say "  · errexit 是宿主语义，属【预期行为】而非缺陷："
        say "      对照验证： bash -e <你的原脚本>   ← 会停在同一处、同样 rc=1"
        say "    想让脚本继续跑，改写脚本里的失败命令："
        say "      false          →  false || true"
        say "      grep x f       →  grep x f || true"
        say "    或在该段前加 set +e（跑完再 set -e 恢复）"
    fi
    say "  · 干净环境重跑：env -i PATH=\$PATH HOME=\$HOME bash <产物> /dev/null"
    say "  · 别用 set -x / 别改 PS4 / 别挂 LD_PRELOAD / 别挂调试器"
    say "  · 运行时【不要加 2>/dev/null】：V7 层的 die(113) 提示会被吞掉"
else
    say "本 shell 环境全部通过 —— 若产物仍中断，问题在别的层面："
    say "  · V7 层（zread.c 的 v7_env_guards 五件套 / 启动时间窗 3000ms）"
    say "  · V6 与 V7 为两套独立检测，V7 通过后还要过 V6 这一层"
    say "  · 去掉 2>/dev/null 重跑，把完整 stderr 发出来"
fi
say "=============================================="
