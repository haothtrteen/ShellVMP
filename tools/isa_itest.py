#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
isa_itest.py —— r16 四层随机化表【端到端集成测试】（Python 改写器 × C hook）
================================================================================
为什么要有这个文件（r16-5 教训，别说“下次注意”已经说过一次了）：

  v7_isa.py 的 selftest 只验证「文本改写产物长得对」，最后一关还是
  `bash -n`（纯语法检查）——而 bash -n 用的是**宿主 bash**，根本不会走
  C 侧 hook。于是这两个整类缺陷能一路溜到交付：

    · 长度不同步：xmalloc(1+旧token_index) + strcpy(新串) → 堆腐蚀；
    · 所有权掠夺：静态 token 被换成 strdup 小块，外层 xrealloc 它 →
      munmap_chunk(): invalid pointer。

  两者都只在「魔改 bash 真跑起来 + 脚本足够长 + 触发递归词法」时爆。
  本测试就是把这个组合钉死：真二进制、真表、真执行、与宿主 bash 逐字节比对。

用法：
  python3 tools/isa_itest.py --bash <魔改bash> --table <表.bin> [--json <表.json>]
  python3 tools/isa_itest.py --bash /path/to/bash --table /tmp/isa_t2.bin -v

判据（任一不满足即 FAIL）：
  1) 每个用例的输出(stdout/stderr)与退出码必须与【宿主 bash 跑原脚本】完全一致；
  2) 每个用例改写产物必须真的命中了别名（防「测试空洞」：表换了 seed 就没人跑）；
  3) 命中集合必须覆盖【变长命中】（alias 比 orig 短的项）——本次两类堆 bug
     的共同引爆条件，必须有用例专门覆盖。
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v7_isa  # noqa: E402


# ---- 测试用例：全部用 shell 真名书写，运行时按表改写 -------------------------
# (name, script, args, need_grow)   need_grow=True ⇒ 该用例必须命中变长项
CASES = [
    ("simple", """echo hello
echo "argv1=$1 argv2=$2"
""", ["ONE", "TWO"], False),

    # 【r16-5 munmap_chunk 回归用例】原样保留当初炸出
    # `munmap_chunk(): invalid pointer` 的脚本（内容/shell 参数都别改）。
    # 逐行二分的结果：去掉 f(){} 定义行、for 行、路径 echo 行中的【任意一行】
    # 都不再崩 —— 崩与不崩取决于堆布局，不是单行语义。所以别试图把它裁成
    # 「等价的最小程序」，那恰恰会让它失去拦截力。原样钉住，最省心也最有效。
    ("l3_structures", """f() { echo "func: $1 / $2"; }
f A B
echo "argv1=$1 argv2=$2"
if [ "$1" = "ONE" ]; then echo "IF-OK"; else echo "IF-NO"; fi
for x in 1 2; do echo "F$x"; done
i=0
while [ $i -lt 2 ]; do echo "W$i"; i=$((i+1)); done
case "$2" in TWO) echo "CASE-HIT";; *) echo "CASE-DEF";; esac
echo "/system/bin/sh /data/adb/m1 /sdcard/f1"
set -- NEW1 NEW2
echo "after-set: $1 $2"
""", ["ONE", "TWO"], False),

    # 【生长型 token 专项】while/function 的别名比本名短 ⇒ 替换后字符串变长。
    # 命中即触发 xmalloc(1+旧长度)+strcpy(新串) 的越界路径。
    ("grow_token", """grow_fn() { printf "%s\\n" "FN"; }
grow_fn
n=0
while [ $n -lt 2 ]; do
  printf "N%d\\n" "$n"
  n=$((n+1))
done
""", [], True),

    # 【递归词法专项】parse_matched_pair 递归回 read_token_word ⇒ 内层
    # 翻译会把外层静态 token 指针改掉（所有权掠夺 bug 的唯一引爆路径）。
    # 命令替换 / 嵌套命令替换 / 算术替换 / case 头部命令替换全上。
    ("recursive_lex", """echo "$(echo cmdsub)"
echo "arith: $(( 3 + 4 ))"
if [ "$(echo y)" = "y" ]; then printf "%s\\n" IF-GROW; else echo NO; fi
for x in a b; do
  j=0
  while [ $j -lt 1 ]; do echo "ln-$x-$j"; j=$((j+1)); done
done
case "$(echo cs)" in cs) echo CASE-HIT;; *) echo CASE-DEF;; esac
r=$(echo $(echo nested)); echo "nested=$r"
""", [], False),

    ("l4_path", """echo "/system/bin/sh /data/adb/m1 /sdcard/f1"
printf "%s\\n" "/system/bin/sh/x"
echo 'sq-/system/bin/sh-not-rewritten'
""", [], False),

    ("quoted_and_comment", """# echo in comment stays
echo "#not-a-comment-inside-string"
echo 'echo single-quoted'
case a in a) echo Q-OK;; esac
""", [], False),
]


def _run(binary, script_path, args, extra_env=None, timeout=20):
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    try:
        p = subprocess.run([binary, script_path] + list(args),
                           env=env, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT", b"", b""


def _hits(orig_script, rewritten, table):
    """返回改写产物中确实被替换命中的 alias 集合（用于防空洞）"""
    alias = set()
    for e in table:
        a = e.get("alias")
        if a and (a in rewritten) and (a not in orig_script):
            alias.add(a)
    return alias


def main():
    ap = argparse.ArgumentParser(description="ISA 四层随机化端到端集成测试")
    ap.add_argument("--bash", required=True, help="待验证的魔改 bash 二进制")
    ap.add_argument("--table", required=True, help="V7ISA 表 .bin")
    ap.add_argument("--json", help="表 .json（用于变长项断言，缺省则同目录推断）")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--keep", action="store_true", help="保留生成的中间脚本")
    args = ap.parse_args()

    if not os.path.isfile(args.bash):
        sys.stderr.write("错误：--bash 不存在: %s\n" % args.bash)
        return 2
    if not os.path.isfile(args.table):
        sys.stderr.write("错误：--table 不存在: %s\n" % args.table)
        return 2

    with open(args.table, "rb") as f:
        table = v7_isa.deserialize(f.read())

    jpath = args.json or os.path.splitext(args.table)[0] + ".json"
    grow_aliases = set()
    if os.path.isfile(jpath):
        with open(jpath, "r", encoding="utf-8") as f:
            j = json.load(f)
        for e in j.get("table", []):
            if e.get("layer") not in (1, 2, 3):
                continue
            orig = e.get("orig", "")
            if len(orig) > len(e.get("alias", "")):
                grow_aliases.add(e["alias"])
    elif args.json:
        sys.stderr.write("警告：--json 不存在，变长覆盖断言降级为跳过\n")

    tmpdir = "/tmp/isa_itest_%d" % os.getpid()
    os.makedirs(tmpdir, exist_ok=True)

    npass = nfail = 0
    grow_covered = set()

    for name, script, script_args, need_grow in CASES:
        orig_path = os.path.join(tmpdir, name + ".orig.sh")
        rew_path = os.path.join(tmpdir, name + ".rew.sh")
        with open(orig_path, "w", encoding="utf-8") as f:
            f.write(script)
        rewritten, _counts = v7_isa.rewrite_all(script, table)
        with open(rew_path, "w", encoding="utf-8") as f:
            f.write(rewritten)

        erc, eout, eerr = _run("/bin/bash", orig_path, script_args)
        arc, aout, aerr = _run(args.bash, rew_path, script_args,
                               {"V7_ISA_TABLE": args.table})

        hits = _hits(script, rewritten, table)
        grow_covered |= (hits & grow_aliases)

        problems = []
        if not hits:
            problems.append("空洞：改写产物未命中任何别名（表/用例失效）")
        if need_grow and not (hits & grow_aliases):
            problems.append("未覆盖变长命中（起不到拦截堆越界的作用）")
        if arc == "TIMEOUT":
            problems.append("执行超时（疑似死循环/挂起）")
        else:
            if arc != erc:
                problems.append("退出码 %r != 期望 %r" % (arc, erc))
            if aout != eout:
                problems.append("stdout 不一致\n"
                                "        期望: %r\n        实际: %r"
                                % (eout[:400], aout[:400]))
            if aerr != eerr:
                problems.append("stderr 不一致\n"
                                "        期望: %r\n        实际: %r"
                                % (eerr[:400], aerr[:400]))

        if problems:
            nfail += 1
            print("FAIL %-18s (%s)%s" % (name, os.path.basename(args.bash),
                                         " needs-grow" if need_grow else ""))
            for p in problems:
                print("       - %s" % p)
        else:
            npass += 1
            print("PASS %-18s 命中 %d 项%s"
                  % (name, len(hits), "（含变长 %d）" % len(hits & grow_aliases)
                     if hits & grow_aliases else ""))
        if args.verbose:
            print("       payload: %s" % rew_path)

    # 全局断言：变长项必须至少被某个用例真的执行到
    if grow_aliases and not grow_covered:
        nfail += 1
        print("FAIL 全局              变长别名一个都没被命中：本测试对堆越界 bug "
              "零防护\n       已知变长项: %s" % ", ".join(sorted(grow_aliases)))

    if not args.keep:
        for name, _, _, _ in CASES:
            for suf in (".orig.sh", ".rew.sh"):
                p = os.path.join(tmpdir, name + suf)
                if os.path.exists(p):
                    os.unlink(p)
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass

    print("-" * 60)
    print("合计：%d PASS / %d FAIL%s"
          % (npass, nfail, "（中间脚本保留于 %s）" % tmpdir if args.keep else ""))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
