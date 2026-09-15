#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
#
# ShellVMP 历史归档 —— 早期原型，不参与构建，不保证可运行。
# 详见 docs/HISTORY/README.md
# 在两个 bash 内部分别尝试 ptrace / process_vm_readv
probe_inside() {
  cat > /tmp/inner.c <<'CE'
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
int main(void){
    long r;
    char b[32]=""; struct iovec li={b,32}, ri={b,32};
    errno=0; r=ptrace(PTRACE_TRACEME,0,0,0);
    printf("    ptrace      = %2ld errno=%d(%s)\n", r, errno, strerror(errno));
    errno=0; r=syscall(310, getpid(), &li,1,&ri,1,0);
    printf("    vm_readv    = %2ld errno=%d(%s)\n", r, errno, strerror(errno));
    return 0;
}
CE
  gcc -O2 -o /tmp/inner /tmp/inner.c 2>/dev/null
}
probe_inside
echo "--- 系统 bash ---"
/bin/bash -c '/tmp/inner'
echo "--- 魔改 bash（应被 seccomp 拒）---"
/tmp/bs_t2d/bash-5.2/bash -c '/tmp/inner'
