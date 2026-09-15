/* SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 *
 * ShellVMP 历史归档 —— T2 反调试 A/B 实验，不参与构建。
 * 详见 docs/HISTORY/README.md
 */
/* 通用 dump 探针: ./probe <pid>
 * 读 Dumpable（若能）、尝试 open(/proc/pid/mem)、扫业务明文
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int main (int argc, char **argv)
{
    char path[64], buf[8192];
    int fd, n, hits = 0;
    const char *pat = "S04 counter positive";
    int plen = (int) strlen (pat);
    char stp[64], lb[256];
    FILE *st;

    if (argc < 2) { fprintf (stderr, "用法: %s <pid>\n", argv[0]); return 2; }
    printf ("  euid=%d\n", (int) geteuid ());

    snprintf (stp, sizeof stp, "/proc/%s/status", argv[1]);
    st = fopen (stp, "r");
    if (st)
      {
        while (fgets (lb, sizeof lb, st))
          if (!strncmp (lb, "Dumpable", 8) || !strncmp (lb, "Seccomp", 7))
            printf ("  %s", lb);
        fclose (st);
      }
    else
        printf ("  (读 status 失败: %s)\n", strerror (errno));

    snprintf (path, sizeof path, "/proc/%s/mem", argv[1]);
    fd = open (path, O_RDONLY);
    if (fd < 0)
      {
        printf ("  🔒 open(%s) 失败 errno=%d (%s) → 断读 ✅\n",
                path, errno, strerror (errno));
        return 1;
      }
    while ((n = (int) read (fd, buf, sizeof buf)) > 0)
      {
        int i;
        for (i = 0; i + plen <= n; i++)
          if (memcmp (buf + i, pat, plen) == 0) hits++;
      }
    close (fd);
    printf ("  ✅ open 成功，业务明文命中: %d\n", hits);
    return 0;
}
