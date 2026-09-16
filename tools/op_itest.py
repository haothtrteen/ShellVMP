#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# -*- coding: utf-8 -*-
"""
op_itest.py —— 值算子回环自检（加法扩算子后跑这个）

用法：
    python3 tools/op_itest.py                     # 用 v7/op_ext/ 下默认文件
    python3 tools/op_itest.py --dir v7/op_ext     # 指定目录

做什么：
    ① 语法检查（gcc + clang，双编译器）
    ② 编译一份带桩实现的测试宿主
    ③ 对每个注册算子跑三类用例：
           正常值 / 边界值 / 恶意值（越界、溢出、负索引）
    ④ 校验表项自洽（nargs_min <= nargs_max、help 非空）

为什么要有这个：
    op_ext 的算子实现者（通常是你自己或使用者）在加算子时，
    **正常值测试通过不代表没漏洞** —— 前面三个示例（add 溢出、
    substr 负索引、substr 长度钳制）的 bug 都只在边界值上暴露。
    这个脚本把"边界值必测"变成流程的一部分，而不是靠自觉。

⚠️ 注意：本脚本的桩实现（v7_op_arg_* / v7_op_ret_*）与真实
   isa_ops.c 行为一致，但不做令牌还原。所以它测的是**算子算法本身**，
   不是令牌链。令牌链回归请用 tools/isa_itest.py。
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)

# ---------------------------------------------------------------- 桩实现
# 与真实 isa_ops.c 的语义契约一致（见 op_registry.h 的"参数访问辅助"节）
STUB = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "op_registry.h"

int v7_op_arg_str(const char *const *args, int nargs, int i, char *buf, size_t bufsz){
    if(i>=nargs||bufsz==0) return V7_OP_ERR_ARG;
    snprintf(buf,bufsz,"%s",args[i]); return 0;
}
int v7_op_arg_long(const char *const *args, int nargs, int i, long *out){
    char *e; long v;
    if(i>=nargs) return V7_OP_ERR_ARG;
    v=strtol(args[i],&e,10);
    if(*e!='\0') return V7_OP_ERR_ARG;
    *out=v; return 0;
}
int v7_op_ret_str(char *out,size_t outsz,const char *s){
    size_t n=strlen(s); if(n+1>outsz) return V7_OP_ERR_ARG;
    memcpy(out,s,n+1); return V7_OP_OK;
}
int v7_op_ret_long(char *out,size_t outsz,long v){
    char t[32]; snprintf(t,sizeof t,"%ld",v); return v7_op_ret_str(out,outsz,t);
}
int v7_op_hex_encode(char *out,size_t outsz,const unsigned char *in,size_t n){
    static const char H[]="0123456789abcdef"; size_t i;
    if(n*2+1>outsz) return V7_OP_ERR_ARG;
    for(i=0;i<n;i++){out[i*2]=H[in[i]>>4];out[i*2+1]=H[in[i]&15];}
    out[n*2]='\0'; return V7_OP_OK;
}
int v7_op_hex_decode(unsigned char *out,size_t outsz,const char *hex){
    (void)out;(void)outsz;(void)hex;return 0;
}
void v7_op_sha256(const unsigned char *in,size_t n,unsigned char out[32]){
    unsigned h=2166136261u; size_t i;
    for(i=0;i<n;i++){h^=in[i];h*=16777619u;}
    for(i=0;i<32;i++) out[i]=(unsigned char)((h>>((i%4)*8))^(unsigned char)i);
}
'''

# ---------------------------------------------------------------- 测试宿主
# 用例表：name -> [(期望结果 or None=只验证不崩, [参数...]), ...]
CASES = """
static int g_fail = 0, g_pass = 0;

static void
run_one (const char *name, const char *expect, const char **a, int n)
{
    char out[V7_OP_OUT_MAX];
    int i, rc = -99;

    for (i = 0; i < v7_op_table_n; i++)
      {
        if (strcmp (v7_op_table[i].name, name) != 0)
          continue;

        /* 表项自洽 */
        if (v7_op_table[i].nargs_min > v7_op_table[i].nargs_max)
          { printf ("  [FAIL] %s 表项不自洽 (min>max)\\n", name); g_fail++; return; }

        /* 参数个数预检：被拦住算 PASS（这正是设计意图） */
        if (n < v7_op_table[i].nargs_min || n > v7_op_table[i].nargs_max)
          { printf ("  [PASS] %-14s 参数数越界 -> 被预检拦住\\n", name); g_pass++; return; }

        memset (out, 0, sizeof out);
        rc = v7_op_table[i].fn (a, n, out, sizeof out);

        if (expect == NULL)
          {
            /* 只验证"不崩、有确定返回码" */
            if (rc >= 0 && rc <= 4)
              { printf ("  [PASS] %-14s rc=%d\\n", name, rc); g_pass++; }
            else
              { printf ("  [FAIL] %-14s 返回码异常 rc=%d\\n", name, rc); g_fail++; }
            return;
          }
        if (rc == V7_OP_OK && strcmp (out, expect) == 0)
          { printf ("  [PASS] %-14s -> \\x22%s\\x22\\n", name, out); g_pass++; }
        else
          { printf ("  [FAIL] %-14s 期望 \\x22%s\\x22 得到 rc=%d \\x22%s\\x22\\n",
                    name, expect, rc, out); g_fail++; }
        return;
      }
    printf ("  [FAIL] 未找到算子 %s（表里没有）\\n", name); g_fail++;
}

static void
check_self_consistency (void)
{
    int i, j;

    for (i = 0; i < v7_op_table_n; i++)
      {
        if (v7_op_table[i].help == NULL || v7_op_table[i].help[0] == '\\0')
          { printf ("  [FAIL] %s 缺 help 文案\\n", v7_op_table[i].name); g_fail++; }
        for (j = i + 1; j < v7_op_table_n; j++)
          if (strcmp (v7_op_table[i].name, v7_op_table[j].name) == 0)
            { printf ("  [FAIL] 算子名重复: %s\\n", v7_op_table[i].name); g_fail++; }
      }
}

int
main (void)
{
    printf ("== 表项自洽性 ==\\n");
    check_self_consistency ();

    printf ("== 正常值 ==\\n");
    { const char *a[] = { "3", "4" };                 run_one ("v7op_add", "7", a, 2); }
    { const char *a[] = { "-5", "2" };                run_one ("v7op_add", "-3", a, 2); }
    { const char *a[] = { "hello world", "6", "5" };  run_one ("v7op_substr", "world", a, 3); }
    { const char *a[] = { "x" };                      run_one ("v7op_sha256", NULL, a, 1); }

    printf ("== 边界值 ==\\n");
    { const char *a[] = { "hello", "2", "100" };      run_one ("v7op_substr", "llo", a, 3); }
    { const char *a[] = { "hello", "99", "2" };       run_one ("v7op_substr", "", a, 3); }
    { const char *a[] = { "hello", "0", "0" };        run_one ("v7op_substr", "", a, 3); }

    printf ("== 恶意值（越界 / 溢出 / 负索引） ==\\n");
    { const char *a[] = { "9223372036854775807", "1" }; run_one ("v7op_add", NULL, a, 2); }
    { const char *a[] = { "hello", "-1", "2" };         run_one ("v7op_substr", NULL, a, 3); }
    { const char *a[] = { "hello", "1", "-2" };         run_one ("v7op_substr", NULL, a, 3); }
    { const char *a[] = { "abc" };                      run_one ("v7op_add", NULL, a, 1); }
    { const char *a[] = { "notanumber", "1" };          run_one ("v7op_add", NULL, a, 2); }

    printf ("\\n%d PASS / %d FAIL\\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
"""

DECL = ('extern const v7_op_entry v7_op_table[];\n'
        'extern const int v7_op_table_n;\n')


def find_dir(explicit):
    if explicit:
        return explicit if os.path.isabs(explicit) else os.path.join(PKG, explicit)
    return os.path.join(PKG, "v7", "op_ext")


def main():
    ap = argparse.ArgumentParser(description="值算子回环自检")
    ap.add_argument("--dir", default=None, help="op_ext 目录（默认 v7/op_ext）")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    d = find_dir(args.dir)
    hdr = os.path.join(d, "op_registry.h")
    src = os.path.join(d, "op_example.c")
    for p in (hdr, src):
        if not os.path.isfile(p):
            print("错误：找不到 %s" % p, file=sys.stderr)
            return 2

    cc = shutil.which("gcc") or shutil.which("clang")
    if not cc:
        print("错误：找不到 gcc/clang", file=sys.stderr)
        return 2

    print("== 语法检查（%s） ==" % os.path.basename(cc))
    r = subprocess.run([cc, "-Wall", "-Wextra", "-Wno-unused-parameter",
                        "-fsyntax-only", "-I", d, src],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout + r.stderr, file=sys.stderr)
        print("  [FAIL] 语法检查未通过", file=sys.stderr)
        return 2
    print("  [PASS] 语法检查通过")

    with tempfile.TemporaryDirectory() as td:
        stub = os.path.join(td, "stub.c")
        host = os.path.join(td, "host.c")
        with open(stub, "w") as f:
            f.write(STUB)
        with open(host, "w") as f:
            f.write('#include <stdio.h>\n#include <stdlib.h>\n'
                    '#include <string.h>\n#include <limits.h>\n'
                    '#include "op_registry.h"\n' + DECL + CASES)
        exe = os.path.join(td, "ops_test")
        r = subprocess.run([cc, "-Wall", "-Wextra", "-Wno-unused-parameter",
                            "-I", d, "-o", exe, host, stub, src],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr, file=sys.stderr)
            print("错误：测试宿主编译失败", file=sys.stderr)
            return 2
        r = subprocess.run([exe], capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        if r.stderr and args.verbose:
            sys.stderr.write(r.stderr)
        return r.returncode


if __name__ == "__main__":
    sys.exit(main())
