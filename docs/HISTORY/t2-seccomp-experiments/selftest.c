/* SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 *
 * ShellVMP 历史归档 —— T2 反调试 A/B 实验，不参与构建。
 * 详见 docs/HISTORY/README.md
 */
/* T2 seccomp 自测：验证过滤器真的拦住 ptrace / process_vm_readv
 * 编译： gcc -O2 -o selftest selftest.c ../../../bash_poc/v7_harden.c
 * 运行： ./selftest
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <sys/wait.h>

extern int  v7_harden_memory2 (void *sensitive, size_t len);
extern void v7_harden_install (void);

/* 读自己的 /proc/pid/mem（外部 dump 最常用手段） */
static int try_proc_mem_read (void)
{
    char path[64];
    char buf[32] = {0};
    FILE *f;
    size_t n;

    snprintf (path, sizeof path, "/proc/%d/mem", (int) getpid ());
    f = fopen (path, "rb");
    if (f == NULL)
        return -errno;                 /* 打不开 = 被 PR_SET_DUMPABLE 挡住 ✅ */
    n = fread (buf, 1, sizeof buf, f);
    fclose (f);
    if (n == 0)
        return -1;
    return (int) n;                    /* >0 = 读到了 ⚠️ */
}

int main (void)
{
    int rc, r_mem;

    printf ("==== T2 seccomp / 断读 自测 ====\n");
    printf ("pid=%d\n\n", (int) getpid ());

    printf ("[加固前]\n");
    r_mem = try_proc_mem_read ();
    printf ("  /proc/self/mem 读取: %s\n",
            r_mem > 0 ? "成功（预期：加固前可读）" : "失败");
    printf ("  ptrace(PTRACE_TRACEME): ");
    fflush (stdout);
    printf ("%s\n", ptrace (PTRACE_TRACEME, 0, 0, 0) == 0 ? "允许" : "拒绝");

    printf ("\n[安装加固]\n");
    rc = v7_harden_memory2 (NULL, 0);
    printf ("  v7_harden_memory2 rc=%d（0=全部成功）\n", rc);
    printf ("  bit0=PR_SET_DUMPABLE失败 bit1=seccomp失败 bit2=MADV_DONTDUMP失败\n");

    printf ("\n[加固后]\n");
    printf ("  ptrace(PTRACE_TRACEME): ");
    fflush (stdout);
    {
        long r = ptrace (PTRACE_TRACEME, 0, 0, 0);
        printf ("%s (errno=%d %s)\n",
                r == 0 ? "⚠️ 仍允许" : "✅ 被拒",
                errno, strerror (errno));
    }
    {
        char buf[32];
        struct iovec li = { buf, sizeof buf }, ri = { buf, sizeof buf };
        long r = syscall (310 /*process_vm_readv*/, getpid (), &li, 1, &ri, 1, 0);
        printf ("  process_vm_readv: %s (errno=%d %s)\n",
                r < 0 ? "✅ 被拒" : "⚠️ 仍可调用",
                errno, strerror (errno));
    }
    r_mem = try_proc_mem_read ();
    printf ("  /proc/self/mem 读取: %s (code=%d)\n",
            r_mem > 0 ? "⚠️ 仍可读" : "✅ 已断读", r_mem);

    printf ("\n==== 判读 ====\n");
    printf ("  非 root 下 /proc/self/mem 应【已断读】；ptrace/vm_readv 应【被拒】\n");
    printf ("  root 下自身 /proc/self/mem 可能仍可读（CAP_SYS_PTRACE）——预期\n");
    return 0;
}
