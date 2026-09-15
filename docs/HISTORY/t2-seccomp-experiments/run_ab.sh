#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md
# 对照：非 root 攻击者 vs 加固前后
for mode in plain harden; do
  ./victim $mode > /tmp/t2_ready.$$ 2>&1 &
  vpid=$!
  sleep 0.5
  echo "[$mode] 目标 pid=$vpid"
  setpriv --reuid=65534 --regid=65534 --clear-groups ./attacker $vpid 2>&1 | sed 's/^/    /'
  kill $vpid 2>/dev/null; wait $vpid 2>/dev/null
done
