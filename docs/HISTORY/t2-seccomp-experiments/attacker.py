#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— T2 反调试 A/B 实验，不参与构建。
# 详见 docs/HISTORY/README.md
"""外部攻击者视角：尝试 dump 目标进程，找业务明文"""
import subprocess, sys, re, time, os

hardened = sys.argv[1] if len(sys.argv) > 1 else "plain"
p = subprocess.Popen(["./victim"] + (["harden"] if hardened == "harden" else []),
                     stdout=subprocess.PIPE, text=True)
line = p.stdout.readline()          # READY <pid>
pid = int(line.split()[1])
time.sleep(0.4)

pat = b"SECRET_PAYLOAD_XYZ"
found = 0
try:
    with open(f"/proc/{pid}/mem", "rb", 0) as f:
        for m in open(f"/proc/{pid}/maps"):
            mm = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", m)
            if not mm: continue
            s, e, perm = int(mm.group(1),16), int(mm.group(2),16), mm.group(3)
            if "r" not in perm: continue
            if e - s > 64*1024*1024: continue
            try:
                f.seek(s); d = f.read(e - s)
            except Exception:
                continue
            found += d.count(pat)
except PermissionError as ex:
    print(f"  🔒 open(/proc/{pid}/mem) 被拒: {ex}")
    found = -1
except Exception as ex:
    print(f"  ⚠️  {type(ex).__name__}: {ex}")
    found = -2

print(f"[{hardened:8s}] 明文命中: {'被拒（断读）' if found<0 else found}")
p.kill()
