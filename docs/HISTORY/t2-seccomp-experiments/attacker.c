/* SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 *
 * ShellVMP 历史归档 —— T2 反调试 A/B 实验，不参与构建。
 * 详见 docs/HISTORY/README.md
 */
/* 外部攻击者（C 版）：open(/proc/pid/mem) 扫明文
 * 用法: ./attacker <pid>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int main (int argc, char **argv)
{
    char path[64], buf[65536];
    int fd, n, hits = 0;
    const char *pat = "SECRET_PAYLOAD_XYZ";
    int plen = (int) strlen (pat);

    if (argc < 2) { fprintf (stderr, "用法: %s <pid>\n", argv[0]); return 2; }
    snprintf (path, sizeof path, "/proc/%s/mem", argv[1]);

    fd = open (path, O_RDONLY);
    if (fd < 0)
        {
          printf ("  🔒 open(%s) 失败: errno=%d (%s)  ← 断读生效\n",
                  path, errno, strerror (errno));
          return 1;      /* 被拒 */
        }
    while ((n = (int) read (fd, buf, sizeof buf)) > 0)
        {
          int i;
          for (i = 0; i + plen <= n; i++)
            if (memcmp (buf + i, pat, plen) == 0)
              hits++;
        }
    close (fd);
    printf ("  明文命中: %d %s\n", hits, hits ? "⚠️ 读到了" : "（未命中）");
    return hits ? 0 : 2;
}
