/* SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 *
 * ShellVMP 历史归档 —— T2 反调试 A/B 实验，不参与构建。
 * 详见 docs/HISTORY/README.md
 */
/* 受害进程：持有一段"业务明文"，等外部来 dump
 * 编译： gcc -O2 -o victim victim.c ../../bash_poc/v7_harden.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
extern int v7_harden_memory2 (void *sensitive, size_t len);

int main (int argc, char **argv)
{
    int do_harden = (argc > 1 && argv[1][0] == 'h');
    /* 模拟敏感明文（比如解密后的业务串） */
    char *secret = malloc (4096);
    strcpy (secret, "S04 counter positive / SECRET_PAYLOAD_XYZ");

    if (!do_harden)
        {
          /* 模拟"未加固"：显式打开 dumpable（很多正常程序/Setuid后
             都是这个状态）。不设的话，非 root 攻击者对谁都打不开，
             对照就没有意义了。 */
          prctl (PR_SET_DUMPABLE, 1, 0, 0, 0);
        }
    if (do_harden)
        {
          /* 页对齐区间：DONTDUMP + mlock */
          unsigned long pg = 4096UL;
          unsigned long a = ((unsigned long) secret) & ~(pg - 1);
          unsigned long b = ((unsigned long) secret + 400) & ~(pg - 1);
          v7_harden_memory2 ((void *) a, (b > a ? b - a : pg));
        }
    printf ("READY %d\n", (int) getpid ());
    fflush (stdout);
    sleep (30);
    return 0;
}
