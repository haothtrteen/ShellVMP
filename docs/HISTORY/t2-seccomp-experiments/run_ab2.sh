#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md
# 更严谨的对照：用 setsid 让 victim 脱离本 shell 的 dumpable 继承
for mode in plain harden; do
  setsid ./victim $mode > /tmp/t2r 2>&1 < /dev/null &
  sleep 0.6
  vpid=$(awk '/READY/{print $2}' /tmp/t2r)
  echo "[$mode] pid=$vpid  dumpable=$(cat /proc/$vpid/status 2>/dev/null | awk '/^Dumpable/{print $2}')"
  setpriv --reuid=65534 --regid=65534 --clear-groups /root/work/she/v7/tools/t2_seccomp/attacker $vpid 2>&1 | sed 's/^/    /'
  kill $vpid 2>/dev/null
  sleep 0.2
done
