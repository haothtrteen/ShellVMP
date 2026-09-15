/* ============================================================================
 * bash_random_portable.h —— bash $RANDOM 生成器的可移植移植版
 *
 * 用途：把 bash 的 $RANDOM 逐比特语义带给其它 shell（dash/ash/mksh/...），
 *       使 ShellVMP 产物的密钥链（解释器 _am() 的状态推进）在非 bash 上同样成立。
 *
 * 来源：bash-5.2 lib/sh/random.c（GPLv3+，见仓库 NOTICE）
 *   - intrand32()  : Park-Miller "Minimal Standard"（CACM 31(10):1195, 1988）
 *                    经 FreeBSD 过滤：x(n+1) = 16807*x(n) mod 2147483647
 *   - brand()      : (rseed>>16) ^ (rseed&65535)，再 & 0x7fff
 *   - get_random_number() : do-while 去重（rv == last_random_value 时重抽）
 *
 * 三个必须逐字对齐的点（漏一个就与 bash 分叉）：
 *   1. last==0 时代入 123459876（Park-Miller 不能以 0 为种子）
 *   2. 折叠公式 (rseed>>16)^(rseed&65535) 仅在 shell_compatibility_level > 50
 *      时启用；BASH_COMPAT=50 时直接取 rseed（实测 1234 → 30462 7764 12710）
 *   3. do-while 去重循环会「吃掉」重复值，必须连状态一起模拟
 *
 * 实测对拍（种子 1234 / 999999）：
 *   bash:    30658 14076 1273   /  19069 28971 24550
 *   本实现:  30658 14076 1273   /  19069 28971 24550   [一致]
 * ============================================================================
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 * AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL 
 */

#ifndef BASH_RANDOM_PORTABLE_H
#define BASH_RANDOM_PORTABLE_H

#include <stdint.h>

#define BASH_RAND_MAX_PORTABLE 32767   /* 0x7fff —— 16 bits */

typedef struct {
    uint32_t rseed;
    int last_random_value;
} bash_random_state;

/* Park-Miller Minimal Standard 单步推进 */
static uint32_t
bash_intrand32(uint32_t last)
{
    int32_t h, l, t;
    uint32_t ret;

    /* Can't seed with 0. */
    ret = (last == 0) ? 123459876u : last;
    h = (int32_t)(ret / 127773u);
    l = (int32_t)(ret - (127773u * (uint32_t)h));
    t = 16807 * l - 2836 * h;
    ret = (uint32_t)((t > 0) ? t : t + 2147483647);
    return ret;
}

/* 等价于 bash 的 sbrand(seed) */
static void
bash_srandom(bash_random_state *st, unsigned long seed)
{
    st->rseed = (uint32_t)seed;
    st->last_random_value = 0;
}

/* 等价于 bash 的 get_random_number()（含 do-while 去重） */
static int
bash_random_next(bash_random_state *st)
{
    int rv;

    do {
        st->rseed = bash_intrand32(st->rseed);
        /* shell_compatibility_level > 50（bash 5.1+ 默认） */
        rv = (int)((st->rseed >> 16) ^ (st->rseed & 65535u));
        rv &= BASH_RAND_MAX_PORTABLE;
    } while (rv == st->last_random_value);

    st->last_random_value = rv;
    return rv;
}

#endif /* BASH_RANDOM_PORTABLE_H */
