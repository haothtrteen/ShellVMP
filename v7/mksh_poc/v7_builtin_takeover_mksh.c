/* v7_builtin_takeover_mksh.c —— V7 自定义 builtin 接管（mksh 版）
 *
 * 对应 bash 版的 v7_builtin_takeover.c。**不能直接复用 bash 版**，原因见下。
 *
 * ── 为什么必须重写而不是移植 ────────────────────────────────────────────
 * bash 与 mksh 的 builtin 模型是**物种差异**，不是参数差异：
 *
 *   | | bash | mksh |
 *   |---|---|---|
 *   | 注册表 | 静态数组 shell_builtins[]（编译期生成） | 运行期哈希表 `builtins`（struct table） |
 *   | 表项 | struct builtin（多字段：name/flags/function/…） | struct tbl（通用变量表项，func 复用 val.f） |
 *   | 函数签名 | int (*)(WORD_LIST *) | int (*)(const char **) |
 *   | 取表项 | 遍历数组 + strcmp | ktsearch(&builtins, name, hash(name)) / get_builtin(name) |
 *   | 关停标志 | b->flags |= BUILTIN_ENABLED | tp->type == CSHELL（已是即生效） |
 *
 * 所以本文件是**按 mksh 的数据结构重新实现**同一套机制（词参数解密 + C 层输出），
 * 而不是把 bash 版 ifdef 几下就完事。
 *
 * ── 机制（与 bash 版同源） ──────────────────────────────────────────────
 *   把 builtins 表里 "echo" 表项的 val.f 换成我们的函数。mksh 分派时
 *   （findcom → call_builtin）跳进我们的 C 代码，原生 c_print 一次都不被调用。
 *
 *   效果：AST / argv 里只有密文令牌 "v7p_9yshhevga_"，
 *         明文只在我们的 C 函数栈上短暂出现，输出后立即擦除。
 *
 * ── 安全边界（诚实记录） ────────────────────────────────────────────────
 *   1. 明文必然经过内核 write 缓冲（物理必需，接受）。但缓冲里没有命令名，
 *      攻击者无法从明文倒推语义。
 *   2. 本函数栈副本显式擦除，窗口压到最小。
 *   3. 表本身受 VMP 保护 + 加密落盘。
 *
 * ── fail-closed 原则（沿用 bash 版） ────────────────────────────────────
 *   无 L6 表 → 不接管任何 builtin，行为与原生 mksh 完全一致。
 *   保证"裸 mksh 跑普通脚本"与"产物跑业务脚本"两条路径互不干扰。
 
 *
 * SPDX-License-Identifier: MirOS
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 * 本文件是 mksh 的衍生作品，许可证由上游强制继承（MirOS，宽松）。
 *  * 义务：保留版权与许可声明即可，不要求提供完整源码。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sh.h"

/* isa_hook.c 提供（与 bash 版共用同一份实现，见该文件） */
#define V7_ARG_BUF 640   /* 与 bash 版一致：L6 真名上限 512 + 余量。
                          * 两端必须同步 —— bash 侧曾因这里停在 256 而让
                          * 超过 253 字节的长串 decode 静默失败（r33e）。 */
extern int v7_isa_param_decode (const char *tok, char *out, size_t outsz);
extern int v7_isa_param_scan (const char *word, char *out, size_t outsz);
extern int v7_isa_has_param_table (void);

/* 三级参数解码选择 —— 与 bash 版 v7_bt_decode_arg 逐字同逻辑。
 * 拆成独立函数的目的也一样：让 v7_echo_builtin（VMP 保护面内）保持小体积。
 *   ① 整词精确匹配 → ② 子串扫描 → ③ 都 miss 则按原词输出 */
int
v7_bt_decode_arg (const char *w, char *tmp, size_t tmpsz)
{
    if (v7_isa_param_decode (w, tmp, tmpsz) > 0)
        return 1;
    if (v7_isa_param_scan (w, tmp, tmpsz) > 0)
        return 1;
    return 0;
}

/* ===================================================================
 * 擦除工具：inline 版（不 include v7_wipe.h —— 那个头会拉进 sys/mman.h
 * 等系统头，在 shell 源码树里可能与其他头冲突）。
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
 * 自定义 echo：参数解密 + C 层输出（mksh argv 风格）
 *
 * wp 是 mksh 的 argv 数组：wp[0] = "echo"（builtin 名），wp[1..] = 参数。
 * 与 bash 版的 WORD_LIST 链表不同，这里直接按下标遍历。
 *
 * 与原生 c_print 的行为差异（有意为之，必须保持兼容）：
 *   - 支持 -n（不换行）的**简化**语义
 *   - 参数若非 L6 令牌 → 原样输出（未令牌化的参数照常工作）
 *
 * 不做的事：不调用原生 c_print（否则明文会流经它的处理路径，
 * 且我们也失去"输出过程完全自主"的意义）。
 *
 * 返回：mksh builtin 约定 —— 0 成功，非 0 失败（用 1，与 c_print 一致）。
 * =================================================================== */
static int
v7_echo_builtin (const char **wp)
{
    const char **ap;
    int no_newline = 0;
    size_t cap = 0;
    char *buf = NULL;          /* 拼接缓冲（避免多次 write，缩短窗口） */
    size_t len = 0;

    if (wp == NULL || wp[0] == NULL)
        return (1);

    /* --- 选项解析（仅识别 -n，其余按字面处理：保守优先） --- */
    ap = wp + 1;
    for (; *ap != NULL; ap++)
        {
          const char *w = *ap;

          if (strcmp (w, "-n") == 0)
            {
              no_newline = 1;
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
              continue;
            }
          break;                     /* 首个非选项词 → 参数起点 */
        }

    /* --- 阶段 1：计算总长（先算后拼，只分配一次） --- */
    cap = 16;
    for (const char **q = ap; *q != NULL; q++)
        {
          char tmp[V7_ARG_BUF];
          const char *w = *q;

          if (v7_bt_decode_arg (w, tmp, sizeof tmp))
            {
              cap += strlen (tmp) + 1;
              v7_bt_wipe (tmp, sizeof tmp);
            }
          else
            cap += strlen (w) + 1;
        }
    cap += 2;

    buf = (char *) malloc (cap);
    if (buf == NULL)
        return (1);
    buf[0] = '\0';

    /* --- 阶段 2：逐词解密并拼接 --- */
    for (const char **q = ap; *q != NULL; q++)
        {
          char tmp[V7_ARG_BUF];
          const char *w = *q;
          const char *use;
          size_t wl;

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

    /* --- 阶段 3：一次性写出（缩短明文在缓冲里的存活时间） ---
     * 直写 fd，不经过 mksh 的 shf 层 —— 既避开其缓冲，也保证
     * 明文只存在于我们自己的 buf（用完即擦）。 */
    {
      size_t off = 0;

      while (off < len)
        {
          ssize_t n = write (1, buf + off, len - off);

          if (n <= 0)
            break;
          off += (size_t) n;
        }
    }

    /* --- 阶段 4：立即擦除拼接缓冲（明文源） --- */
    v7_bt_wipe (buf, cap);
    free (buf);

    return (0);
}

/* ===================================================================
 * 安装：劫持输出型 builtin
 *
 * 与 bash 版的差异：mksh 取表项走哈希表（get_builtin），
 * 表项函数指针在 tp->val.f，且**没有"启用位"** ——
 * 改了 val.f 立即生效（type 已是 CSHELL）。
 * =================================================================== */
void
v7_builtin_takeover_install (void)
{
    struct tbl *tp;

    /* fail-closed：没有 L6 表就完全不接管（裸 mksh 行为不变） */
    if (!v7_isa_has_param_table ())
        return;

    tp = get_builtin ("echo");
    if (tp == NULL || tp->type != CSHELL)
        return;                        /* 表里没有 / 不是内建 → 不接管 */
    if (tp->val.f != v7_echo_builtin)
        tp->val.f = v7_echo_builtin;
}
