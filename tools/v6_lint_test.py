#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v6_lint 回归测试 —— 重点是 harden() 的【语义等价】而非字符串替换是否发生。

为什么这么设计（r16-6 教训）：
    硬化器改的是用户源码。判断它对不对，看"替换有没有发生"是不够的 ——
    早期版本用整行替换，`echo hi; set -x; echo bye` 里的 `echo hi` 和
    `echo bye` 被一起吃掉时，所有"替换成功"的检查都是绿的。
    所以这里的判据只有一条最硬的：**硬化前后用真实 bash 跑，stdout 与
    exit code 必须逐字节相同**（一旦允许例外，就在那儿单独写明为什么）。

用法：
    python3 tools/v6_lint_test.py            # 跑全部
    python3 tools/v6_lint_test.py -v         # 打印每条硬化后的源码
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v6_lint as L  # noqa: E402

TMP = tempfile.mkdtemp(prefix="v6lint-")


def run_src(src, tag="t"):
    fp = os.path.join(TMP, "%s.sh" % tag)
    with open(fp, "w", encoding="utf-8") as f:
        f.write(src)
    try:
        p = subprocess.run(["bash", fp], capture_output=True, timeout=20,
                           cwd=TMP)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""


# ---------------------------------------------------------------- 1) 结构用例
# (名字, 源码, 必须出现在结果里, 不得出现在结果里)
STRUCT = [
    ("同行混合-核心", 'echo hi; set -x; echo bye',
     ['echo hi', 'echo bye'], ['set -x']),
    ("同行混合-&&", 'echo a && set -x && echo b',
     ['echo a', 'echo b'], ['set -x']),
    ("同行混合-管道", 'echo hi | set -x | wc -l',
     ['echo hi', 'wc -l'], ['set -x']),
    ("双引号内分号不误切", 'echo "a;b" ; set -x',
     ['echo "a;b"'], ['set -x']),
    ("双引号内 # 不误判注释", 'echo "a#b" ; set -x',
     ['echo "a#b"'], ['set -x']),
    ("单引号串必须完好", "echo 'a' ; set -x",
     ["echo 'a'"], ['set -x']),
    ("行尾注释要带回", 'echo hi; set -x  # keep me',
     ['echo hi', '# keep me'], ['set -x']),
    ("set -ex 只摘 x", 'set -ex\necho keep',
     ['set -e', 'echo keep'], ['set -ex']),
    ("set -o xtrace", 'set -o xtrace\necho keep',
     ['echo keep'], ['xtrace']),
    ("PS4 赋值", 'PS4="+x "\necho keep',
     ['echo keep'], ['PS4=']),
    ("shebang 不当注释", '#!/bin/bash\nset -x',
     ['#!/bin/bash'], ['set -x']),
    ("$# 与 ${#x} 不被切断", 'set -- a b; echo $# ${#x}; set -x',
     ['echo $# ${#x}'], []),
    # ---- 默认模式下【不许动】的两条：它们会改变用户可观察语义 ----
    ("LD_PRELOAD 默认不动", 'export LD_PRELOAD=/tmp/x.so\necho keep',
     ['LD_PRELOAD=/tmp/x.so', 'echo keep'], []),
    ("DEBUG trap 默认不动", "trap 'echo dbg' DEBUG\necho keep",
     ['trap', 'DEBUG', 'echo keep'], []),
    # ---- 业务语义一律不许碰 ----
    ("set -e 不动", 'set -e\nfalse\necho never', ['set -e', 'false'], []),
    ("false||true 不误伤", 'false || true\necho keep',
     ['false || true'], []),
    ("heredoc 体不动", 'cat <<EOF\nset -x\nPS4=q\nEOF\necho after',
     ['cat <<EOF', 'set -x', 'PS4=q', 'EOF'], []),
    ("普通多行零改动",
     'echo one\necho two\nfor i in 1 2; do echo $i; done',
     ['echo one', 'echo two', 'for i in 1 2; do echo $i; done'], []),
    ("if-then 结构不破坏", 'if [ 1 = 1 ]; then set -x; fi; echo k',
     ['echo k'], []),
]


def test_struct(verbose=False):
    print("── 1) 结构检查（替换的位置与范围是否正确） ──")
    bad = 0
    for name, src, want, unwanted in STRUCT:
        out, ch = L.harden(src)
        errs = []
        for w in want:
            if w not in out:
                errs.append("丢了 %r" % w)
        for u in unwanted:
            if u in out:
                errs.append("不该有 %r" % u)
        if ch:
            fp = os.path.join(TMP, "chk.sh")
            with open(fp, "w", encoding="utf-8") as f:
                f.write(out)
            if subprocess.call(["bash", "-n", fp]) != 0:
                errs.append("改完语法不合法")
        if errs:
            bad += 1
        print("  %-22s %s   %s" % (name, "FAIL" if errs else "PASS",
                                   "; ".join(errs)))
        if verbose or errs:
            print("       结果=%r" % out)
    print("  → %d/%d PASS\n" % (len(STRUCT) - bad, len(STRUCT)))
    return bad


# ------------------------------------------------------- 2) 运行期语义等价
# 每条都会真的 bash 跑两遍：原脚本 vs 硬化脚本，比对 rc + stdout。
DIFF = {
    "混合-基本": 'echo hi; set -x; echo bye\n',
    "混合-管道": 'echo hi | set -x | wc -l\n',
    "引号保护": 'echo "a;b"\necho "c#d"; set -x\necho done\n',
    "单引号串": "echo 'x;y set -x' ; set -x\necho ok\n",
    "行尾注释": 'echo hi; set -x  # keep me\necho done\n',
    "set -e 语义保持": 'echo before\nset -e\nfalse\necho never\n',
    "false||true": 'false || true\necho survived\n',
    "PS4 赋值": 'PS4="++ "\necho kept\n',
    "LD_PRELOAD(默认不动)": 'export LD_PRELOAD=/nope.so\necho rc=$?\n',
    "DEBUG trap(默认不动)": "trap 'echo dbg' DEBUG\necho s1\necho s2\n",
    "for 循环": 'for i in 1 2 3; do echo n$i; done\n',
    "函数+参数": 'f(){ echo "arg=$1 n=$#"; }\nf a b\n',
    "heredoc": 'cat <<EOF\nset -x\nPS4=x\nEOF\necho after\n',
    "中文与变量": 'n="李明"\necho "你好 $n"\nprintf "%s\\n" ok\n',
    "位置参数": 'set -- p1 p2\necho "$1 $2 $#"\n',
    "多行混排": 'echo A\nset -x\necho B\nset +x\necho C\n',
    "算数与数组": 'a=(1 2 3); echo $(( ${#a[@]} + 1 ))\n',
    "case 分支": 'case x in x) echo hit;; *) echo miss;; esac\n',
    "退出码传递": '(exit 42)\necho rc=$?\n',
    "命令替换": 'v=$(echo inner)\necho "[$v]"\n',
}


def test_diff(verbose=False):
    print("── 2) 运行期差分（硬化前后真跑，比 rc + stdout） ──")
    bad = 0
    for name, src in sorted(DIFF.items()):
        out, ch = L.harden(src)
        rc0, o0 = run_src(src, "orig")
        rc1, o1 = run_src(out, "hard")
        ok = (rc0 == rc1 and o0 == o1)
        if not ok:
            bad += 1
        print("  %-22s %s   rc %s→%-3s %s" % (
            name, "FAIL" if not ok else "PASS", rc0, rc1,
            "输出一致" if o0 == o1 else "★输出变了"))
        if not ok or verbose:
            print("       原: rc=%s %r" % (rc0, o0))
            print("       硬: rc=%s %r" % (rc1, o1))
            print("       硬化后=%r" % out)
    print("  → %d/%d 语义等价\n" % (len(DIFF) - bad, len(DIFF)))
    return bad


# -------------------------------------------- 3) --aggressive 是明确知情的选择
AGGRESSIVE = {
    "DEBUG trap": "trap 'echo dbg' DEBUG\necho step1\n",
    "LD_PRELOAD": 'export LD_PRELOAD=/nope.so\necho alive\n',
}


def test_aggressive(verbose=False):
    print("── 3) --aggressive：允许改变语义，但必须【真的改了】且语法合法 ──")
    bad = 0
    for name, src in AGGRESSIVE.items():
        out, ch = L.harden(src, aggressive=True)
        changed = bool(ch)
        fp = os.path.join(TMP, "ag.sh")
        with open(fp, "w", encoding="utf-8") as f:
            f.write(out)
        legal = subprocess.call(["bash", "-n", fp]) == 0
        ok = changed and legal
        if not ok:
            bad += 1
        print("  %-12s %s   中和=%-13s 语法=%s" % (
            name, "PASS" if ok else "FAIL", [c[3] for c in ch] or "无",
            "合法" if legal else "★坏"))
        if verbose:
            print("       硬化后=%r" % out)
    # 反向确认：默认模式一定不能动这两条
    for name, src in AGGRESSIVE.items():
        _, ch = L.harden(src, aggressive=False)
        if ch:
            bad += 1
            print("  ★ %s 默认模式下被改了，违反保守约定" % name)
    print("  → 默认保守 / 激进可逆，共 %d 项异常\n" % bad)
    return bad




# ------------------------------------------------------- 4) 变异测试（自检）
# 「新写的测试如果抓不到旧 bug，那它只是另一个看起来绿的摆设」——
# 这条在 r16-3 用堆崩溃血泪换来。所以这里内置一个【已知有 bug 的旧实现】，
# 每次都要求整套测试在它身上 FAIL。哪天它偷偷全绿了，说明测试已经失效。
def _mutant_harden(text, aggressive=False):
    """早期版本复刻：行级 search 判定 + 整行替换 + 误用 _code_of。
    三样都是当年真实踩过的坑，别把它改"聪明"了。"""
    import re as _re
    out, changes = [], []
    for idx, raw in enumerate(text.split("\n")):
        code = L._code_of(raw)              # 坑1：_code_of 删引号/单引号串
        s = code.strip()
        if not s:
            out.append(code); continue
        hit = None
        if   _re.search(r'\bset\s+-[a-zA-Z]*x', s):      hit = "xtrace"
        elif _re.search(r'\bset\s+-o\s+xtrace', s):     hit = "xtrace"
        elif _re.search(r'\bPS4\s*=', s):               hit = "ps4"
        elif _re.search(r'\bBASH_XTRACEFD\s*=', s):     hit = "xtracefd"
        elif _re.search(r'\bLD_PRELOAD\s*=', s):        hit = "ldpreload"
        elif _re.search(r'\btrap\s+.*\s+DEBUG', s):    hit = "debug_trap"
        if hit:
            out.append(":")                 # 坑2：整行换成占位符
            changes.append((idx + 1, raw, ":", hit))
        else:
            out.append(code)                # 坑3：没命中也吐 code
    return "\n".join(out), changes


def test_mutation():
    """用变异体验证本套测试的有效性：变异体必须 FAIL，越多越好。"""
    print("── 4) 变异自检：给回归测试注入旧 bug，它必须报警 ──")
    good = L.harden
    L.harden = _mutant_harden
    try:
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            nbad = test_struct() + test_diff() + test_aggressive()
    finally:
        L.harden = good
    ok = nbad > 0
    print("  变异体触发缺陷数 = %-3d %s" % (
        nbad, "PASS（测试有区分力）" if ok else "★ FAIL（测试已失效，必须重写）"))
    if not ok:
        print("  这套用例抓不到已知的旧 bug —— 等于没有防线")
    print()
    return 0 if ok else 1


def main():
    verbose = "-v" in sys.argv
    if subprocess.call(["bash", "-c", "true"]) != 0:
        print("本机没有 bash，无法做运行期差分"); return 2
    b = test_struct(verbose) + test_diff(verbose) + test_aggressive(verbose)
    b += test_mutation()
    print("=" * 58)
    if b == 0:
        print("全部通过：harden() 只动该动的，且不动的部分语义零漂移")
    else:
        print("存在 %d 项未通过 —— 硬化器在改用户源码，任何一项都不能放过" % b)
    return 1 if b else 0


if __name__ == "__main__":
    sys.exit(main())
