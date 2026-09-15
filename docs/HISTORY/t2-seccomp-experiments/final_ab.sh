#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md
# T2 终验：非 root 攻击者 dump 两种 bash
cd /root/work/she/v7/tools/t2_seccomp
printf 'sleep 25\n' > /tmp/t2_long.sh
chmod 644 /tmp/t2_long.sh

for pair in "plain:/bin/bash" "harden:/tmp/bs_t2d/bash-5.2/bash"; do
  tag=${pair%%:*}; tgt=${pair#*:}
  setsid $tgt /tmp/t2_long.sh >/dev/null 2>&1 &
  sleep 0.8
  # 找到刚起的那个进程
  pid=$(pgrep -n -f "bash.*t2_long.sh")
  echo "===== [$tag] $tgt  pid=$pid ====="
  setpriv --reuid=65534 --regid=65534 --clear-groups ./probe $pid 2>&1 | sed 's/^/  /'
  echo
  kill $pid 2>/dev/null
  sleep 0.3
done
