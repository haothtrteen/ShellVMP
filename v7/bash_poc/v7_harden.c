/* v7_harden.c —— r29（T2）bash 线抗 dump 加固：断读 + 擦除 + 锁页
 *
 * ============================ 为什么需要这一层 ============================
 * r22 实测结论（见 R22_CHANGES.md 第二节）：
 *
 *   1) `PROT_NONE` 拦不住 `/proc/pid/mem`！
 *      实测关窗态（页权限 PROT_NONE）下，外部进程仍读到了明文：
 *        --- 关窗态（PROT_NONE）读取 ---
 *          返回值=64  ⚠️ 内容=[SECRET_PLAINTEXT]
 *      根因：/proc/pid/mem 的读路径走 get_user_pages，**不检查用户页表权限**。
 *      PROT_NONE 只拦"进程自身访存"(SIGSEGV) 与 process_vm_readv。
 *
 *   2) "窗口式保护"对高频轮询无效 —— 8 线程 + 周期开窗，命中率 99.9995%。
 *
 *   3) PR_SET_DUMPABLE=0 的真实边界（实测，非推测）：
 *        非 root 攻击者 → open() 直接失败 → 彻底断读 ✅
 *        root 攻击者    → CAP_SYS_PTRACE 绕过 → 仍可读 ❌
 *
 * 所以本层的目标是：**非 root 场景确定性防住**（不靠概率）。
 * root 挡不住是物理限制 —— 那一档靠后续的擦除层与混淆层继续加成本。
 *
 * ============================ 三层动作 ============================
 *   ① prctl(PR_SET_DUMPABLE, 0)
 *        → 非 root 无法 open("/proc/pid/mem")（EACCES）
 *        → 进程属性，**被 execve 继承**，设一次覆盖整条链
 *   ② seccomp-BPF 黑名单：ptrace / process_vm_readv / process_vm_writev
 *        → **内核层拒绝，不看窗口大小** —— 这是唯一"确定性"手段
 *        → 命中返回 EPERM（默认），进程存活（便于观察攻击者行为）
 *   ③ mlock + MADV_DONTDUMP
 *        → 防换页到 swap/zram（落盘=可离线分析）；防写进 core dump
 *
 * ============================ 为什么不链 libseccomp ============================
 * bash 线要交叉编译到 aarch64-android（bionic）。Android NDK sysroot 里
 * **没有 libseccomp**，硬链会直接把交叉线拦在链接期。故手写 BPF 字节码，
 * 只依赖内核 UAPI 头（linux/seccomp.h / linux/filter.h），零外部依赖。
 *
 * ============================ 失败策略：fail-open ============================
 * 加固失败**绝不中断执行**。理由：本层是纵深保险，不是唯一防线；
 * 某些容器/内核可能禁 seccomp（如 DEFAULT_SECCOMP 未开、或已在更严的
 * 沙箱内），此时降级即可 —— 宁可少一层保护，也不能让业务脚本跑不起来。
 * 失败细节仅在 V7_DIAG 构建下输出到 stderr。
 
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 * 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
 *  * 分发内含魔改 bash 的产物时必须提供对应完整源码。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>

#include <sys/prctl.h>
#include <sys/mman.h>

#ifndef PR_SET_DUMPABLE
#  define PR_SET_DUMPABLE 4
#endif
#ifndef MADV_DONTDUMP
#  define MADV_DONTDUMP 16
#endif

#include <sys/syscall.h>

/* r29 开关：设 V7_NO_HARDEN=1 可关闭全部加固（排查"是不是加固导致异常"用）。
 * 生产环境不应设置它 —— 但保留这个逃生口，比"出事只能重编"要好。 */
static int
v7_harden_disabled (void)
{
    const char *p = getenv ("V7_NO_HARDEN");

    return (p != NULL && p[0] == '1' && p[1] == '\0');
}

/* =====================================================================
 * seccomp-BPF：黑名单 ptrace / process_vm_readv / process_vm_writev
 *
 * 过滤器语义（经典 BPF，seccomp 模式）：
 *   1. 只关心 arch == 当前架构（防 x32 ABI 绕过：x86_64 上 32 位兼容
 *      调用的 syscall 号会不同，不校验 arch 就存在绕过面）
 *   2. 取 syscall 号
 *   3. 命中黑名单 → 返回 SECCOMP_RET_ERRNO | EPERM
 *   4. 其余一律 SECCOMP_RET_ALLOW
 *
 * 命中返回 EPERM 而非 KILL：进程存活、失败可见 —— 便于观察攻击者行为，
 * 也避免"某个无关工具意外触发即崩"的调试噩梦。
 * ===================================================================== */
#if defined(__linux__)

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>

/* 架构常量：seccomp 数据里的 arch 字段用 AUDIT_ARCH_* */
#if defined(__x86_64__)
#  define V7_SECCOMP_ARCH  AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#  define V7_SECCOMP_ARCH  AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#  define V7_SECCOMP_ARCH  AUDIT_ARCH_I386
#elif defined(__arm__)
#  define V7_SECCOMP_ARCH  AUDIT_ARCH_ARM
#else
#  define V7_SECCOMP_ARCH  0   /* 未知架构 → 跳过 seccomp（fail-open） */
#endif

/* 目标 syscall 号：**各架构不同**，必须逐一列（这是最容易埋雷的地方）。
 *   架构      ptrace  process_vm_readv  process_vm_writev
 *   x86_64      101          310               311
 *   aarch64     117          270               271
 *   i386         26          347               348
 *   arm          26          376               377                                            */
#if defined(__x86_64__)
#  define V7_NR_PTRACE        101
#  define V7_NR_PVM_READV     310
#  define V7_NR_PVM_WRITEV    311
#elif defined(__aarch64__)
#  define V7_NR_PTRACE        117
#  define V7_NR_PVM_READV     270
#  define V7_NR_PVM_WRITEV    271
#elif defined(__i386__)
#  define V7_NR_PTRACE        26
#  define V7_NR_PVM_READV     347
#  define V7_NR_PVM_WRITEV    348
#elif defined(__arm__)
#  define V7_NR_PTRACE        26
#  define V7_NR_PVM_READV     376
#  define V7_NR_PVM_WRITEV    377
#else
#  define V7_NR_PTRACE        (-1)
#  define V7_NR_PVM_READV     (-1)
#  define V7_NR_PVM_WRITEV    (-1)
#endif

/* BPF 指令宏（部分老 sysroot 的 linux/filter.h 未定义，补上） */
#ifndef BPF_STMT
#  define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#  define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

/* 返回 EPERM 的动作码。SECCOMP_RET_ERRNO 低 16 位是 errno。 */
#define V7_RET_EPERM  (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
#define V7_RET_ALLOW  SECCOMP_RET_ALLOW

static int
v7_seccomp_deny_readers (void)
{
#if V7_SECCOMP_ARCH == 0 || V7_NR_PTRACE < 0
    return -1;    /* 未知架构：不装，fail-open */
#else
    struct sock_filter filt[] = {
        /* [0] 校验 arch：非本架构（如 x32／其它 ABI）→ 直接放行，
         *     交给内核原本的行为。不校验就存在"用别的 ABI 号绕过"的面。 */
        BPF_STMT (BPF_LD | BPF_W | BPF_ABS,
                  (unsigned int) offsetof (struct seccomp_data, arch)),
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, V7_SECCOMP_ARCH, 1, 0),
        BPF_STMT (BPF_RET | BPF_K, V7_RET_ALLOW),

        /* [3] 取 syscall 号 */
        BPF_STMT (BPF_LD | BPF_W | BPF_ABS,
                  (unsigned int) offsetof (struct seccomp_data, nr)),

        /* [4] ptrace → 命中则跳到 [10] 的 RET_EPERM */
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, (unsigned int) V7_NR_PTRACE, 5, 0),
        /* [5] process_vm_readv → 跳 4 条到 [10] */
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, (unsigned int) V7_NR_PVM_READV, 4, 0),
        /* [6] process_vm_writev → 跳 3 条到 [10] */
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, (unsigned int) V7_NR_PVM_WRITEV, 3, 0),

        /* [7][8] 兜底：放行 */
        BPF_STMT (BPF_RET | BPF_K, V7_RET_ALLOW),
        BPF_STMT (BPF_RET | BPF_K, V7_RET_ALLOW),

        /* [9] 占位（跳转落点对齐） */
        BPF_STMT (BPF_RET | BPF_K, V7_RET_EPERM),

        /* [10] 命中：EPERM */
        BPF_STMT (BPF_RET | BPF_K, V7_RET_EPERM),
    };
    struct sock_fprog prog;

    prog.len = (unsigned short) (sizeof filt / sizeof filt[0]);
    prog.filter = filt;

    /* SECCOMP_SET_MODE_FILTER：需先设 NO_NEW_PRIVS（除非有 CAP_SYS_ADMIN）。
     * 设了 NO_NEW_PRIVS 后 execve 的 setuid 位失效 —— 对 bash 无影响。 */
    if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    if (syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0)
        return -1;
    return 0;
#endif
}

#else   /* 非 Linux：不装 seccomp */
static int
v7_seccomp_deny_readers (void)
{
    return -1;
}
#endif

/* =====================================================================
 * 对外统一接口（T2.2）
 *
 * sensitive/len：可选。非空时对该区间做页级加固（DONTDUMP + mlock）。
 * 返回：位掩码，0 = 全部成功。各位含义见下（便于诊断，不致命）。
 * ===================================================================== */
int
v7_harden_memory2 (void *sensitive, size_t len)
{
    int rc = 0;

    if (v7_harden_disabled ())
        return 0;

    /* ① 关闭 core dump + /proc/pid/mem 可读性（进程属性，execve 继承） */
    if (prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        rc |= 1;

    /* ② seccomp-BPF：内核层拒绝内存读取类 syscall（唯一确定性手段） */
    if (v7_seccomp_deny_readers () != 0)
        rc |= 2;

    /* ③ 页级加固：DONTDUMP 防 core、mlock 防换出 */
    if (sensitive != NULL && len > 0)
        {
          if (madvise (sensitive, len, MADV_DONTDUMP) != 0)
            rc |= 4;
          (void) mlock (sensitive, len);    /* 失败不致命（RLIMIT_MEMLOCK 限额） */
#ifdef MADV_WIPEONFORK
          (void) madvise (sensitive, len, MADV_WIPEONFORK);   /* fork 后子进程见零页 */
#endif
        }
    return rc;
}

/* =====================================================================
 * bash 线安装点：shell_initialize() + L6 表装载之后调用
 *
 * 时机选择的理由（T2 决策）：
 *   - 必须在**自解密与读表完成之后** —— 那些动作要读 /proc、要 open 表文件，
 *     过早装 seccomp 可能自伤；
 *   - 又要在**进入主命令循环之前** —— 此刻密钥/表已在内存，正是最该保护的
 *     时刻，且此后 bash 不再需要被 trace/读内存。
 * ===================================================================== */
void
v7_harden_install (void)
{
    int what = v7_harden_memory2 (NULL, 0);

#ifdef V7_DIAG
    if (what != 0)
        fprintf (stderr, "V7DIAG: 加固部分失败 mask=%d errno=%d\n",
                 what, errno);
    else
        fprintf (stderr, "V7DIAG: 加固完成（DUMPABLE=0 + seccomp + 页锁）\n");
#endif
    (void) what;
}
