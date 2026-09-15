/* SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 *
 * ShellVMP 历史归档 —— T2 反调试 A/B 实验，不参与构建。
 * 详见 docs/HISTORY/README.md
 */
/* 最严谨验证：fork 一个子进程，子进程装 seccomp 后尝试 ptrace/vm_readv，
 * 父进程用 root 权限 open(/proc/child/mem) —— 分离验证两条防线。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

extern int v7_harden_memory2 (void *s, size_t l);

int main (void)
{
    int hardened = 0;
    pid_t c;
    int pfd[2];

    pipe (pfd);
    c = fork ();
    if (c == 0)
      {
        char *secret = malloc (4096);
        long r;
        struct iovec li, ri;
        char buf[32];

        strcpy (secret, "SECRET_PAYLOAD_XYZ");
        close (pfd[0]);



        /* 子进程：装加固 */
        v7_harden_memory2 (secret, 64);

        /* 子进程内尝试 ptrace */
        r = ptrace (PTRACE_TRACEME, 0, 0, 0);
        dprintf (pfd[1], "child_ptrace=%ld errno=%d\n", r, errno);

        /* 子进程内尝试 process_vm_readv */
        li.iov_base = buf; li.iov_len = sizeof buf;
        ri.iov_base = secret; ri.iov_len = sizeof buf;
        errno = 0;
        r = syscall (310, getpid (), &li, 1, &ri, 1, 0);
        dprintf (pfd[1], "child_vmreadv=%ld errno=%d\n", r, errno);
        dprintf (pfd[1], "READY_DUMP_NOW\n");
        close (pfd[1]);
        sleep (8);
        _exit (0);
      }

    close (pfd[1]);
    {
        FILE *cf = fdopen (pfd[0], "r");
        char line[256];
        while (fgets (line, sizeof line, cf))
          {
            char *nl = strchr (line, '\n');
            if (nl) *nl = 0;
            if (!*line) continue;
            if (strcmp (line, "READY_DUMP_NOW") == 0)
                break;              /* 此刻子进程活着，去 dump */
            printf ("  [子进程自述] %s\n", line);
          }
        fclose (cf);
    }

    /* 父进程（root）：尝试 dump 子进程 */
    {
        char path[64], b[65536];
        int fd, n, hits = 0;
        const char *pat = "SECRET_PAYLOAD_XYZ";
        int plen = strlen (pat);
        snprintf (path, sizeof path, "/proc/%d/mem", (int) c);
        fd = open (path, O_RDONLY);
        if (fd < 0)
            printf ("  [root 父进程] open(%s) 失败 errno=%d (%s)\n",
                    path, errno, strerror (errno));
        else
          {
            while ((n = read (fd, b, sizeof b)) > 0)
                for (int i = 0; i + plen <= n; i++)
                    if (!memcmp (b + i, pat, plen)) hits++;
            close (fd);
            printf ("  [root 父进程] dump 子进程明文命中: %d %s\n", hits,
                    hits ? "（root 仍可读 —— 符合 r22 判断）" : "");
          }
    }
    kill (c, 9);
    waitpid (c, NULL, 0);
    return 0;
}
