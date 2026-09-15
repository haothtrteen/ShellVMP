#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md
# root 攻击者视角（T2 的最难场景）——验证 r22 的"防不住 root"判断
printf 'sleep 25\n' > /tmp/t2_long.sh
for pair in "plain:/bin/bash" "harden:/tmp/bs_t2d/bash-5.2/bash"; do
  tag=${pair%%:*}; tgt=${pair#*:}
  setsid $tgt /tmp/t2_long.sh >/dev/null 2>&1 &
  sleep 0.8
  pid=$(pgrep -n -f "bash.*t2_long.sh")
  echo "===== [$tag] pid=$pid ====="
  ./probe $pid 2>&1 | sed 's/^/  /'
  kill $pid 2>/dev/null; sleep 0.3
done
