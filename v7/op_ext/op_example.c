/* op_example.c —— 值算子扩展示例（照着改就能加自己的算子）
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 * 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
 * 分发内含魔改 bash 的产物时必须提供对应完整源码。
 *
 * ===========================================================================
 * 怎么加一个算子（五步）
 * ===========================================================================
 *   第 1 步：在下面写一个 static 函数，签名照 v7_op_fn
 *   第 2 步：在本文件末尾的 V7_OP_TABLE[] 里加一行
 *   第 3 步：在 tools/v7_isa_ops.py 的 OP_SYMBOLS 里加同名（真名）
 *            —— 编译期改写器靠它把 v7_op_xxx(...) 识别出来并令牌化
 *   第 4 步：在 build_poc.sh 的源码清单里加入本文件（若另建文件）
 *   第 5 步：跑 tools/op_itest.py 自检（算子级回环测试）
 *
 * 本文件带三个**可直接使用**的示例算子（覆盖三类典型形态）：
 *   v7op_add      —— 纯算术（最简单的形态，照抄改逻辑即可）
 *   v7op_sha256   —— 字节处理 + 十六进制输出（复用 hex/sha 辅助）
 *   v7op_substr   —— 字符串切片（**边界校验的范本**，必读）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "op_registry.h"

/* ===================================================================
 * 示例 ①：v7op_add —— 两数相加
 * -------------------------------------------------------------------
 * 原脚本写法：  sum=$(( a + b ))
 * 编译期翻译：  v7p_sum_tok=$(v7p_add_tok v7p_a_tok v7p_b_tok)
 * 运行期执行：  取 a、b → 相加 → 写回 sum
 *
 * 这个形态最简单：两个入参，一个结果，无边界问题（除了溢出）。
 * =================================================================== */
static int
v7op_add (const char *const *args, int nargs, char *out, size_t outsz)
{
    long a, b, r;

    /* 参数个数已由表项的 nargs_min/nargs_max 预检，这里不必再查。
     * 但**仍要判返回值**——参数可能不是合法整数。 */
    if (v7_op_arg_long (args, nargs, 0, &a) != 0)
        return V7_OP_ERR_ARG;
    if (v7_op_arg_long (args, nargs, 1, &b) != 0)
        return V7_OP_ERR_ARG;

    /* ③ 整数溢出：显式定义行为。这里选择「拒绝」而非回绕 ——
     * 因为回绕会产生攻击者可控的意外结果（原脚本语义是 bash 算术，
     * 而 bash 本身是回绕的；若你要严格对齐 bash，改成 return r; 即可，
     * 但必须在注释里写清选择了哪种语义）。 */
    if ((b > 0 && a > LONG_MAX - b) || (b < 0 && a < LONG_MIN - b))
        return V7_OP_ERR_RANGE;
    r = a + b;

    return v7_op_ret_long (out, outsz, r);
}

/* ===================================================================
 * 示例 ②：v7op_sha256 —— 对输入串求 SHA-256，输出十六进制
 * -------------------------------------------------------------------
 * 原脚本写法：  h=$(printf '%s' "$x" | sha256sum | cut -d' ' -f1)
 * 编译期翻译：  v7p_h_tok=$(v7p_sha_tok v7p_x_tok)
 * 运行期执行：  取 x → sha256 → hex → 写回 h
 *
 * 对比原写法的好处（这就是本扩展点的价值）：
 *   · 产物里不再有 "sha256sum" / "cut" 这些命令名（少两个语义指纹）
 *   · 不 fork 子进程、不建管道（性能：从 ~3 个进程降到 0）
 *   · 中间摘要不以文本形式经过管道缓冲（明文窗口进一步收窄）
 * =================================================================== */
static int
v7op_sha256 (const char *const *args, int nargs, char *out, size_t outsz)
{
    char           in[V7_OP_OUT_MAX];
    unsigned char  dig[32];
    int            rc;

    rc = v7_op_arg_str (args, nargs, 0, in, sizeof in);
    if (rc != 0)
        return rc;

    v7_op_sha256 ((const unsigned char *) in, strlen (in), dig);

    /* 输入缓冲立即擦除（栈上，本函数返回前就没了；显式擦更保险） */
    memset (in, 0, sizeof in);

    return v7_op_hex_encode (out, outsz, dig, sizeof dig);
}

/* ===================================================================
 * 示例 ③：v7op_substr —— 字符串切片（**边界校验范本，必读**）
 * -------------------------------------------------------------------
 * 原脚本写法：  s=${x:2:5}
 * 编译期翻译：  v7p_s_tok=$(v7p_sub_tok v7p_x_tok 2 5)
 *
 * 为什么单独拿它做范本：这是**最容易写错**的一类算子。
 *
 * 攻击面清单（每一条都要处理，缺一就是漏洞）：
 *   · offset 为负 / 超长           → 必须钳制，不能直接指针运算
 *   · len 为负（原脚本可能算出来）→ 必须拒绝
 *   · offset + len 溢出            → 先判再加，不能写 offset+len > xlen
 *   · 源串长度                     → 必须先取 strlen 再比较
 *   · 输出定长                     → 必须判 outsz
 *
 * 这类算子的错误在正常输入下不会暴露（正常脚本不会传负 offset），
 * 但在**攻击者构造输入**时会变成越界读。攻击者拿不到源码，但能构造
 * 输入——所以这是真实攻击面，不是理论问题。
 * =================================================================== */
static int
v7op_substr (const char *const *args, int nargs, char *out, size_t outsz)
{
    char        src[V7_OP_OUT_MAX];
    long        off, len;
    size_t      slen, n;
    int         rc;

    rc = v7_op_arg_str (args, nargs, 0, src, sizeof src);
    if (rc != 0)
        return rc;
    if (v7_op_arg_long (args, nargs, 1, &off) != 0)
        { memset (src, 0, sizeof src); return V7_OP_ERR_ARG; }
    if (v7_op_arg_long (args, nargs, 2, &len) != 0)
        { memset (src, 0, sizeof src); return V7_OP_ERR_ARG; }

    /* ① 负数一律拒绝（不要"猜测调用者意图"地钳制到 0 —— 静默改语义
     *    比报错更危险，因为你无法区分"正常脚本传了负值"和"攻击者
     *    在试探边界"。报错让调用方按原语义走，fail-closed。） */
    if (off < 0 || len < 0)
        { memset (src, 0, sizeof src); return V7_OP_ERR_ARG; }

    slen = strlen (src);

    /* ② offset 超长：按 bash 语义返回空串（这不是攻击，是合法输入） */
    if ((size_t) off >= slen)
        { memset (src, 0, sizeof src); return v7_op_ret_str (out, outsz, ""); }

    /* ③ 长度钳制：先取 min 再运算，避免 off + len 溢出 */
    n = (size_t) len;
    if (n > slen - (size_t) off)
        n = slen - (size_t) off;

    /* ④ 输出空间（+1 是结尾 '\0'） */
    if (n + 1 > outsz)
        { memset (src, 0, sizeof src); return V7_OP_ERR_NOMEM; }

    memcpy (out, src + off, n);
    out[n] = '\0';

    memset (src, 0, sizeof src);   /* 输入副本立即擦除 */
    return V7_OP_OK;
}

/* ===================================================================
 * 算子注册表
 *
 * 每一项：{ 真名, 实现, 参数下限, 参数上限, 一行说明 }
 * 真名必须与 tools/v7_isa_ops.py 的 OP_SYMBOLS 完全一致（脚本会校验，
 * 不一致会在构建期报错而不是运行期静默失败）。
 * =================================================================== */
const v7_op_entry v7_op_table[] = {
    { "v7op_add",    v7op_add,    2, 2, "两数相加（溢出拒绝）" },
    { "v7op_sha256", v7op_sha256, 1, 1, "SHA-256 → hex" },
    { "v7op_substr", v7op_substr, 3, 3, "子串切片（边界严格校验）" },
    /* ↑ 在这里加你自己的算子 */
};

const int v7_op_table_n =
    (int) (sizeof (v7_op_table) / sizeof (v7_op_table[0]));

/* ===================================================================
 * 审计辅助：列出已注册算子（供 --list-ops 与构建期校验用）
 * =================================================================== */
void
v7_op_list (FILE *fp)
{
    int i;

    if (fp == NULL)
        return;
    for (i = 0; i < v7_op_table_n; i++)
        fprintf (fp, "  %-14s args[%d..%d]  %s\n",
                 v7_op_table[i].name,
                 v7_op_table[i].nargs_min,
                 v7_op_table[i].nargs_max,
                 v7_op_table[i].help ? v7_op_table[i].help : "");
}
