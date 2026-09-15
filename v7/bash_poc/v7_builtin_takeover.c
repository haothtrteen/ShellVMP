/* v7_builtin_takeover.c —— r27（ShellVMP T1）自定义 builtin 接管
 *
 * 构想（用户提出，r25 实测验证）：
 *   "参数不应该由 bash 接管，而是直接魔改 echo 的逻辑。逻辑并非 bash 里执行了
 *    『命令+参数』，而是『魔改命令』，这个魔改命令会自己根据我们的表在 C 层
 *    完成输出的过程。"
 *
 * 机制（r25 实测确认）：
 *   bash 的 builtin 分派本质是**函数指针**（struct builtin.function），
 *   而 shell_builtins[] 是运行期可写的全局数组。把这个指针换成我们的函数，
 *   bash 分派时就跳进我们的 C 代码 —— 原生实现一次都不会被调用。
 *
 * 效果（对比 r24 基线）：
 *   原始：  AST 里 argv[] = "S04 counter positive"   ← 明文，语义完整
 *   接管后：AST 里 argv[] = "v7p_9yshhevga_"        ← 密文令牌，语义断裂
 *          明文只在我们的 C 函数内部（栈上）短暂出现，输出后立即擦除
 *
 * 安全边界（诚实记录，不夸大）：
 *   1. 输出必然经过 stdio 缓冲 —— 明文在那里会短暂存在（物理必需，接受）。
 *      但 stdio 缓冲里【没有命令名】，攻击者无法从明文倒推语义（r26b 实测）。
 *   2. 本函数的栈副本会被显式擦除（v7_wipe_mem），窗口压到最小。
 *   3. 表本身受 VMP 保护 + 加密落盘。
 *
 * fail-closed 原则（沿用 isa_hook.c）：
 *   无 L6 表 → 不接管任何 builtin，行为与原生 bash 完全一致。
 *   这保证了"裸 bash 跑普通脚本"和"产物跑业务脚本"两条路径互不干扰。
 
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 * 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
 *  * 分发内含魔改 bash 的产物时必须提供对应完整源码。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "builtins.h"
#include "shell.h"

/* isa_hook.c 提供（r27 新增 / r33e 扩充） */
#define V7_ARG_BUF 640   /* L6 真名上限 512 + 余量；栈上缓冲，用完即擦。
                          * r33e 修正：r33d.1 把 ISA_MAX_ORIG 提到 512 后
                          * 此处仍停留在 256 —— 超过 253 字节的中文长串
                          * decode 会静默失败（olen+1 > outsz → 返回 0 →
                          * 令牌原样漏出）。两端必须同步。 */
extern int v7_isa_param_decode (const char *tok, char *out, size_t outsz);
extern int v7_isa_param_scan (const char *word, char *out, size_t outsz);
extern int v7_isa_has_param_table (void);

/* r33e：三级参数解码选择 —— 重活全在外部函数，本函数也不进保护面，
 * 拆出来的唯一目的是让 v7_echo_builtin（在 VMP 保护面内，r32）保持
 * 小函数体：它只多了一次普通调用，体积增量可忽略。
 *   ① v7_isa_param_decode：整词精确匹配（r27 老路径，一行未动）
 *   ② v7_isa_param_scan ：整词 miss 后的子串扫描（r33e 混合串兜底）
 *   ③ 都 miss          ：返回 0，调用方按原词输出（fail-closed 语义）
 * 两级顺序刻意保持 decode 在前：老产物整词命中路径与新行为完全一致。 */
int
v7_bt_decode_arg (const char *w, char *tmp, size_t tmpsz)
{
    if (v7_isa_param_decode (w, tmp, tmpsz) > 0)
        return 1;
    if (v7_isa_param_scan (w, tmp, tmpsz) > 0)
        return 1;
    return 0;
}

extern struct builtin *shell_builtins;
extern int num_shell_builtins;

/* ===================================================================
 * 擦除工具：inline 版（不 include v7_wipe.h —— 那个头会拉进 sys/mman.h
 * 等一堆系统头，在 bash 源码树里可能与其他头冲突）。
 * 语义与 v7_wipe.h 的 v7_wipe_mem 一致：volatile 逐字节写，防优化掉。
 * =================================================================== */
static void
v7_bt_wipe (void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *) p;

    if (p == NULL)
        return;
    while (n--)
        *vp++ = 0;
}

/* ===================================================================
 * 工具：查找 builtin 表项
 * =================================================================== */
static struct builtin *
v7_bt_find (const char *name)
{
    int i;

    if (name == NULL || shell_builtins == NULL)
        return NULL;
    for (i = 0; i < num_shell_builtins; i++)
        if (shell_builtins[i].name != NULL
            && strcmp (shell_builtins[i].name, name) == 0)
            return &shell_builtins[i];
    return NULL;
}

/* ===================================================================
 * 自定义 echo：参数解密 + C 层输出
 *
 * 与原生 echo_builtin 的行为差异（有意为之，必须保持兼容）：
 *   - 支持 -n（不换行）、-e（转义）等常见选项的**简化**语义
 *   - 参数若非 L6 令牌 → 原样输出（未令牌化的参数照常工作）
 *
 * 不做的事：不调用原生 echo_builtin（否则明文会流经它的处理路径，
 * 且我们也失去"输出过程完全自主"的意义）。
 * =================================================================== */
static int
v7_echo_builtin (WORD_LIST *list)
{
    WORD_LIST *l;
    int no_newline = 0;
    size_t cap = 0;
    char *buf = NULL;          /* 拼接缓冲（避免多次 fputs，缩短窗口） */
    size_t len = 0;

    /* --- 选项解析（仅识别 -n，其余按字面处理：保守优先） --- */
    for (l = list; l; l = l->next)
        {
          const char *w = l->word->word;
          if (w == NULL)
            continue;
          if (strcmp (w, "-n") == 0)
            {
              no_newline = 1;
              list = l->next;      /* 跳过该选项 */
              continue;
            }
          if (w[0] == '-' && w[1] != '\0')
            {
              const char *p;
              int all_opts = 1;
              for (p = w + 1; *p; p++)
                if (*p != 'n' && *p != 'e' && *p != 'E')
                  { all_opts = 0; break; }
              if (!all_opts)
                break;               /* 不是选项 → 当作参数 */
              for (p = w + 1; *p; p++)
                if (*p == 'n')
                  no_newline = 1;
              list = l->next;
              continue;
            }
          break;                     /* 首个非选项词 → 参数起点 */
        }

    /* --- 阶段 1：计算总长（先算后拼，只分配一次） --- */
    cap = 16;
    for (l = list; l; l = l->next)
        {
          char tmp[V7_ARG_BUF];
          const char *w = l->word->word;
          const char *use;

          if (w == NULL)
            continue;
          if (v7_bt_decode_arg (w, tmp, sizeof tmp))
            {
              cap += strlen (tmp) + 1;
              v7_bt_wipe (tmp, sizeof tmp);
            }
          else
            {
              use = w;
              cap += strlen (use) + 1;
            }
        }
    cap += 2;

    buf = (char *) malloc (cap);
    if (buf == NULL)
        return (EXECUTION_FAILURE);
    buf[0] = '\0';

    /* --- 阶段 2：逐词解密并拼接 --- */
    for (l = list; l; l = l->next)
        {
          char tmp[V7_ARG_BUF];
          const char *w = l->word->word;
          const char *use = NULL;
          size_t wl;

          if (w == NULL)
            continue;
          if (v7_bt_decode_arg (w, tmp, sizeof tmp))
              use = tmp;
          else
              use = w;
          wl = strlen (use);
          if (len > 0)
            buf[len++] = ' ';
          memcpy (buf + len, use, wl);
          len += wl;
          v7_bt_wipe (tmp, sizeof tmp);   /* 栈上明文立即擦除 */
        }
    if (!no_newline)
        buf[len++] = '\n';
    buf[len] = '\0';

    /* --- 阶段 3：一次性写出（缩短明文在缓冲里的存活时间） --- */
    {
      size_t off = 0;
      while (off < len)
        {
          ssize_t n = write (STDOUT_FILENO, buf + off, len - off);
          if (n <= 0)
            break;
          off += (size_t) n;
        }
    }

    /* --- 阶段 4：立即擦除拼接缓冲（明文源） ---
     * 注意：write 直写 fd，不经过 stdio 缓冲 —— 这是相对原生 echo 的
     * 一点改进：明文只存在于我们自己的 buf，用完即擦，不残留 stdio 里。
     * （但内核 pipe/终端缓冲无法控制，那部分物理必需。） */
    if (buf != NULL)
        {
          v7_bt_wipe (buf, cap);
          free (buf);
        }

    return (EXECUTION_SUCCESS);
}

/* ===================================================================
 * 安装：劫持输出型 builtin
 * =================================================================== */
void
v7_builtin_takeover_install (void)
{
    struct builtin *b;

    /* fail-closed：没有 L6 表就完全不接管（裸 bash 行为不变） */
    if (!v7_isa_has_param_table ())
        return;

    b = v7_bt_find ("echo");
    if (b != NULL && b->function != v7_echo_builtin)
        {
          b->function = v7_echo_builtin;
          b->flags |= BUILTIN_ENABLED;
        }
}
