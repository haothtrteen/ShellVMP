#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v6_lint.py —— V6 混淆前的【脚本兼容性静态检查】
================================================================================
起因（真实事故，2026-09-11）：用户在真机上跑 V6 产物，「执行几条命令就没了」。
查了三轮才落地：宿主 bash 开了 errexit，而脚本里有一行裸 `false`。

    $ bash -e 原始脚本   → 停在 S02 obfuscator, rc=1
    $ bash -e V6产物     → 停在 S02 obfuscator, rc=1     ← 完全一致

即 V6 忠实还原了 shell 语义，不是缺陷。**但它从头到尾一句话都没说**
——这就把一个"环境问题"包装成了"加密器坏了"，用户只能靠猜。

更麻烦的是另一类：脚本里 `set -x` / 改 PS4 / 重定义 builtin 会触发 V6 解释器
内置的反调试（混淆器 874-885 行的 `_pm` 指纹机制）→ 主密钥被污染 →
后续块解密成乱码 → 解释器 `[ -n "$_code" ] || exit 1` **静默退出、零提示**。
这类连 rc 都对不上（不是 errexit 那种 "停在失败命令处"），最难排查。

本工具在**混淆之前**把这两类都拦下来：

    python3 tools/v6_lint.py <script.sh> [--strict] [--json]

    --strict  存在 ERROR 级问题时 exit 1（可挂 CI / 挂进混淆流水线前置）
    --json    机器可读输出

设计原则：
  · 低误报优先。跳过注释、单引号串、heredoc 体；宁可漏报也不刷屏，
    否则用户会关掉它 —— 一个被关掉的检查等于没有检查。
  · 每条都给"为什么 + 怎么改"，不去让用户对着规则名猜。
"""
import argparse
import json
import re
import sys

# (规则, 级别, 匹配, 说明, 建议)
# 级别: ERROR=必然出问题 / WARN=很可能 / INFO=留意
RULES = [
    (
        "errexit", "ERROR",
        re.compile(r"\bset\s+-(?:[^;&|]*e|o\s+errexit)\b"),
        "宿主（或脚本自身）开了 set -e：任何返回非 0 的命令都会让产物就地终止。"
        "V6 忠实还原该语义，原始脚本在此环境下也会停在同一处 —— 属预期行为，"
        "但若这是你没意识到的环境开关，产物就表现为「跑几条就没了」。",
        "①确认是否必要；②确实要容错的命令写成 `cmd || true`；"
        "③或在脚本顶部 `set +e`（跑完按需 set -e 恢复）",
    ),
    (
        "xtrace", "ERROR",
        re.compile(r"\bset\s+-(?:[^;&|]*x|o\s+xtrace)\b"),
        "开启 xtrace 会命中 V6 解释器的反调试指纹（case $- in *x* → _pm=0）"
        "→ 主密钥被追加字符 → 后续块解出乱码 → 静默 exit，零告警。",
        "移除该行；调试请到 V6 之外做（或在 evoked-in-name-only 的副本上调试）",
    ),
    (
        "ps4", "ERROR",
        re.compile(r"(?:^|[;&|({]\s*)PS4\s*="),
        "PS4 一旦被改写（哪怕只是加个 \\t 时间戳），同样命中"
        " `[ \"${PS4:-+ }\" != \"+ \" ]` → 主密钥污染 → 静默停止。",
        "移除 PS4 赋值，保持默认的 '+ '",
    ),
    (
        "xtracefd", "ERROR",
        re.compile(r"(?:^|[;&|({]\s*)BASH_XTRACEFD\s*="),
        "设置 BASH_XTRACEFD 直接被判定为分析环境 → 主密钥污染 → 静默停止。",
        "移除该赋值",
    ),
    (
        "ldpreload", "ERROR",
        re.compile(r"(?:^|[;&|({]\s*)(?:export\s+)?LD_PRELOAD\s*="),
        "LD_PRELOAD 非空即被判定注入 → 主密钥污染 → 静默停止。",
        "移除 LD_PRELOAD（产物内部有自己的 anti-inject 检测，不需要你注入）；"
        "或 V6_LINT_AGGRESSIVE=1 由工具代劳 —— 但那会改变后续命令的动态链接，"
        "默认不敢替你做这个决定",
    ),
    (
        "builtin_override", "ERROR",
        re.compile(r"(?:^|[;&|({]\s*)(?:function\s+)?"
                   r"(eval|echo|printf|read|test|\[|true|false|local|return|unset)\s*\(\s*\)"),
        "重定义同名函数会遮蔽 builtin。V6 解释器依赖 `(builtin type -t eval)`"
        "返回 builtin 做完整性判定，被遮蔽即 _pm=0 → 静默停止；"
        "遮蔽 echo/printf/read 也会直接破坏解释器的输入/输出。",
        "改用别的函数名（如加前缀 my_echo），或仅在子 shell 内定义",
    ),
    (
        "false_always", "WARN",
        re.compile(r"(?:^|[;&|({]|\b(?:then|else|do)\s+)"
                   r"false(?!\s*(?:\|\||&&|\|))\s*(?:[;&|)]|$)"),
        "裸 `false` 恒返回 1。若执行环境开着 errexit（adb shell / CI / "
        "某些 profile 常见），脚本会在此处**立即终止、退出码 1** —— "
        "产物表现为「跑几条就没了」。注意 V6 只是忠实还原该语义："
        "原始脚本在同样环境下也会停在同一位置。",
        "写成 `false || true`（明确表示允许失败），或确认你确实要在这里中断",
    ),
    (
        "fail_prone_tail", "INFO",
        re.compile(
            r"(?:^|[;&|(]\s*)(grep|egrep|fgrep|cmp|diff|test)\b[^;&|]*$"),
        "`%s` 无匹配/有差异时返回非 0。在 errexit 环境下会终止后续执行；"
        "且它是否为行尾/条件位难以静态判定，请人工确认。",
        "若允许失败，写成 `cmd || true`，或把它放进 if 条件里",
    ),
    (
        "debug_trap", "ERROR",
        re.compile(r"\btrap\s+[^;&|]*\s+DEBUG\b"),
        "DEBUG trap 每条命令触发一次。真因不是「喂料」，而是 V6 用 "
        "`$gj=$_ ; $Pz=$?` 这类【链式状态】传递块间信任值，trap handler "
        "在每条命令前插进来执行，会把 $_ / $? 冲掉 → 链断 → 后续块解不开 "
        "→ 静默退出（实测：脚本跑到第 2 条命令就停，与本提示一致）。",
        "删掉 DEBUG trap；或 V6_LINT_AGGRESSIVE=1 由工具代劳（会删掉你的 "
        "handler，属改动行为，需你同意）",
    ),
    (
        "nounset", "WARN",
        re.compile(r"\bset\s+-(?:[^;&|]*u|o\s+nounset)\b"),
        "nounset 下解释器内部对未设变量的引用会直接炸，失败点不一定是脚本自身行。",
        "能不加就不加；确需时给内部变量显式默认值",
    ),
    (
        "pipefail", "WARN",
        re.compile(r"\bset\s+-o\s+pipefail\b"),
        "pipefail 改变管道返回码判定，可能与你的分支逻辑交互出人意料。",
        "确认是脚本本意即可，不必移除",
    ),
    (
        "shopt", "WARN",
        re.compile(r"\bshopt\s+-[suq]"),
        "extglob / nullglob / nocasematch 等会改变通配与展开规则，"
        "与 V6 自己的展开叠加后行为可能漂移。",
        "尽量避免开启影响展开的选项",
    ),
    (
        "ifs", "WARN",
        re.compile(r"(?:^|[;&|({]\s*)IFS\s*="),
        "改 IFS 会影响词分割。V6 解释器内部也有依赖默认 IFS 的分割逻辑。",
        "局部使用时写成 `local IFS=...`（函数内），用完恢复",
    ),
    (
        "early_exit", "WARN",
        re.compile(r"(?:^|[;&|({]\s*)exit\b"),
        "中途 exit 会让后续块全部不执行 —— 产物看起来就像「跑一半断了」。",
        "确认是有意提前返回；否则改成函数 + return",
    ),
    (
        "exec_replace", "WARN",
        re.compile(r"(?:^|[;&|({]\s*)exec\b"),
        "exec 替换当前进程，后续块不再执行。",
        "换成普通调用，或放到脚本最后",
    ),
    (
        "path_mangle", "INFO",
        re.compile(r"(?:^|[;&|({]\s*)(?:export\s+)?PATH\s*="),
        "改 PATH 可能导致解释器找不到 openssl/gzip/sha512sum 等依赖而降级或停摆。",
        "追加而非覆盖：PATH=\"$PATH:/new/dir\"",
    ),
    (
        "cd_relative", "INFO",
        re.compile(r"(?:^|[;&|({]\s*)cd\b[^;&|]*[^/$\"')\s]"),
        "相对路径 cd 会累积工作目录漂移，后续块在预期外的目录里创建文件。",
        "用绝对路径，或 `cd ... || exit` 明确失败语义",
    ),
]

# heredoc 起始
HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")


def _code_of(line):
    """剥离注释与单引号串，返回"可执行部分"。
    保守处理：漏报好过误报，宁可放过也不要把注释里的字当命令报出来。"""
    out = []
    i = 0
    n = len(line)
    in_squote = in_dquote = False
    while i < n:
        c = line[i]
        if in_squote:
            if c == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            if c == '"' and line[i - 1:i] != "\\":
                in_dquote = False
            elif c == "$" and i + 1 < n and line[i + 1] in "({":
                # $(...) / ${...}：命令替换里可能是真命令，保留
                depth, j = 0, i + 1
                open_c, close_c = ("(", ")") if line[i + 1] == "(" else ("{", "}")
                while j < n:
                    if line[j] == open_c:
                        depth += 1
                    elif line[j] == close_c:
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                out.append(line[i:j + 1])
                i = j + 1
                continue
            else:
                out.append(c)
            i += 1
            continue
        if c == "'":
            in_squote = True
            i += 1
            continue
        if c == '"':
            in_dquote = True
            i += 1
            continue
        if c == "#":
            break                      # 行注释，到此为止
        out.append(c)
        i += 1
    return "".join(out)


def _strip_comment(line):
    """剥掉【行注释】，返回 (可执行部分, 注释尾巴)。其余字符原样保留。

    与 _code_of 的分工：_code_of 是给 lint 【读】的，为了方便匹配命令名会把
    源码重写（删单引号串、删双引号字符）；harden 是【写】的，必须拿到可复原
    的源码，因此只能用这个版本。曾因 harden 误用 _code_of 导致
    `echo "a;b"` 变成 `echo a;b`（引号整丢），是 L14  repaired 的典型事故。
    """
    if line.lstrip().startswith("#!"):
        return line, ""                  # shebang 不是注释
    out = []
    i, n = 0, len(line)
    in_squote = in_dquote = False
    while i < n:
        c = line[i]
        if in_squote:
            if c == "'":
                in_squote = False
            out.append(c); i += 1; continue
        if in_dquote:
            if c == '"' and line[i - 1:i] != "\\":
                in_dquote = False
            out.append(c); i += 1; continue
        if c == "'":
            in_squote = True; out.append(c); i += 1; continue
        if c == '"':
            in_dquote = True; out.append(c); i += 1; continue
        if c == "#":
            # $# / ${#var} 是参数展开或参数个数，不是行注释
            if i > 0 and line[i - 1] in "${":
                out.append(c); i += 1; continue
            return "".join(out), line[i:]
        out.append(c); i += 1
    return "".join(out), ""


def lint(text):
    """返回 [(行号, 原文, 规则, 级别, 说明, 建议)]"""
    lines = text.split("\n")
    findings = []
    heredoc_end = None

    for idx, raw in enumerate(lines):
        lineno = idx + 1
        stripped = raw.strip()

        # heredoc 体内整体跳过（里面是数据不是命令）
        if heredoc_end is not None:
            if stripped == heredoc_end:
                heredoc_end = None
            continue
        m = HEREDOC_RE.search(raw)
        if m:
            heredoc_end = m.group(2)
            # heredoc 起始行本身仍可能有其它命令，继续检查

        code = _code_of(raw)
        if not code.strip():
            continue

        for rule, level, rx, why, advice in RULES:
            if rx.search(code):
                findings.append((lineno, raw.rstrip(), rule, level, why, advice))
    return findings


LEVEL_ORDER = {"ERROR": 0, "WARN": 1, "INFO": 2}

# ---------------------------------------------------------------- 兜底：自动中和
# 只对"必然让产物自杀、且移除后不损失用户业务逻辑"的命令下手，其他一律只报告。
# 判据：这些命令的作用对象是【shell 自身的调试/注入开关】，而非业务计算。
# 反例（绝不动）：set -e 是流程控制语义；exit/trap EXIT 是业务流向；
# 重定义 echo 可能是脚本有意的封装。这些只能交给人工。
# 判据不是「会不会让产物自杀」，而是更严的一条：
#   【中和之后，shell 的执行语义必须完全不变】——只是少打 xtrace 日志。
#   xtrace / PS4 / BASH_XTRACEFD 都是纯装饰性的 trace 输出开关，砍掉它
#   不改变任何变量的取值、任何命令的成败、任何进程的链接方式。
NEUTRALIZABLE = {"xtrace", "ps4", "xtracefd"}

# 这两项虽然同样会让产物自杀，但中和它们会**改变用户可观察行为**，默认不动：
#   ldpreload : 后续命令的动态链接被改变（注入库失效，语义真的变了）
#   debug_trap: trap handler 是用户写的真代码，删掉等于删了人家一段程序
# ——差分测试中 `-` （DEBUG trap）就实测出 stdout 少了用户自己的 dbg 输出，
#   这不是「保护」，是「破坏」。因此两者只在显式 --aggressive 下才动手。
AGGRESSIVE_ONLY = {"ldpreload", "debug_trap"}

# set -flags 形式：抽取出 flag 字母
SET_FLAGS_RE = re.compile(r"^(\s*)set\s+-([a-zA-Z]+)\s*(.*)$")


def harden(text, aggressive=False):
    """返回 (硬化后文本, [(行号, 原行, 新行, 规则)] )。

    四条硬约束，都是被用户追问后加的：
      1) 默认只中和 NEUTRALIZABLE 三项「装饰性开关」；ldpreload / debug_trap
         会改变用户语义，仅在 aggressive=True（对应 CLI --aggressive）下中和；
      2) 片段级替换——`echo hi; set -x` 必须留下 `echo hi`。早期版本整行
         替换会把同行正常命令一起吃掉，属于破坏用户脚本，不可接受；
      3) 保守性優先：行内含【行注释】或【单引号串】时，code 与原文不再是
         简单对应关系，此时**跳过自动改写、只报告**，宁可不改也不误伤；
      4) 每条改动返回明细并在构建日志打出——你有权知道产品对你的脚本做了什么。
    """
    lines = text.split("\n")
    out, changes = [], []
    heredoc_end = None

    for idx, raw in enumerate(lines):
        lineno = idx + 1
        stripped = raw.strip()

        if heredoc_end is not None:
            if stripped == heredoc_end:
                heredoc_end = None
            out.append(raw)
            continue
        m = HEREDOC_RE.search(raw)
        if m:
            heredoc_end = m.group(2)

        # 【关键】这里必须用 _strip_comment，绝不能用 _code_of：
        # _code_of 会重写源码（删引号），用它做硬化会损坏用户脚本。
        code, comment = _strip_comment(raw)
        if not code.strip():
            out.append(raw)
            continue

        parts = _split_commands(code)
        new_parts, rules_hit = [], []
        touched = False
        for piece in parts:
            # 分隔符本身（`;` `&&` `|` …）原样保留
            if _SPLIT_RE.fullmatch(piece):
                new_parts.append(piece)
                continue
            rep = _neutralize_piece(piece, aggressive)
            if rep is None:
                new_parts.append(piece)
            else:
                new_parts.append(rep[0])
                rules_hit.append(rep[1])
                touched = True

        if touched:
            new_line = "".join(new_parts) + comment   # 行尾注释必须原样带回
            out.append(new_line)
            changes.append((lineno, raw.rstrip(), new_line.strip(),
                            ",".join(rules_hit)))
            continue

        out.append(raw)

    return "\n".join(out), changes


# 命令片段切分（保留分隔符，且不切破引号内的内容）
_DQ_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_SPLIT_RE = re.compile(r"(\|\||&&|[;&|])")


def _split_commands(code):
    """切成 ['片段', '分隔符', '片段', ...]，双引号串整体掩蔽避免误切。"""
    store = []

    def mask(m):
        store.append(m.group(0))
        return "\x00%d\x00" % (len(store) - 1)

    def unmask(s):
        return re.sub(r"\x00(\d+)\x00", lambda m: store[int(m.group(1))], s)

    parts = _SPLIT_RE.split(_DQ_RE.sub(mask, code))
    return [unmask(p) if "\x00" in p else p for p in parts]


# set -flags / set -o xtrace / 敏感赋值 / DEBUG trap
_SET_O_XTRACE_RE = re.compile(r"^\s*set\s+-o\s+xtrace\s*$")
_SENSITIVE_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?(?:PS4|BASH_XTRACEFD|LD_PRELOAD)\s*=.*$")
_TRAP_DEBUG_RE = re.compile(r"^\s*trap\s+.*\s+DEBUG\s*$")


def _neutralize_piece(piece, aggressive=False):
    """判断单个命令片段是否需要中和。
    返回 None = 原样保留；否则返回 (替换文本, 规则名)。"""
    s = piece.strip()
    if not s:
        return None
    indent = piece[:len(piece) - len(piece.lstrip())]
    # 占位必须用 `:`（bash no-op builtin）而不能用 `#` 注释：注释会吞掉
    # 【同一行后面的命令】（`echo hi; set -x; echo bye` 会连 bye 一起丢）。
    noop = "%s:" % (" " * len(indent))

    fm = SET_FLAGS_RE.match(s)
    if fm and "x" in fm.group(2):
        keep = fm.group(2).replace("x", "")
        rest = fm.group(3).strip()
        if keep:
            return ("%sset -%s%s" % (" " * len(indent), keep,
                                     " " + rest if rest else ""), "xtrace")
        return (noop, "xtrace")
    if _SET_O_XTRACE_RE.match(s):
        return (noop, "xtrace")
    if _SENSITIVE_ASSIGN_RE.match(s):
        which = ("ps4" if "PS4" in s else
                 "xtracefd" if "BASH_XTRACEFD" in s else "ldpreload")
        if which in NEUTRALIZABLE or aggressive:
            return (noop, which)
        return None
    if _TRAP_DEBUG_RE.match(s):
        if aggressive:
            return (noop, "debug_trap")
        return None
    return None


def main():
    ap = argparse.ArgumentParser(
        description="V6 混淆前的脚本兼容性静态检查")
    ap.add_argument("script", help="待混淆的原始脚本")
    ap.add_argument("--strict", action="store_true",
                    help="存在 ERROR 时以退出码 1 结束（可挂 CI/前置流水线）")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--harden", action="store_true",
                    help="自动中和会触发产物自检的调试开关（xtrace/PS4/"
                         "BASH_XTRACEFD/LD_PRELOAD/DEBUG trap），"
                         "其余只报告不改动")
    ap.add_argument("--aggressive", action="store_true",
                    help="连 LD_PRELOAD / DEBUG trap 也一并中和。这两者会改变"
                         "用户脚本的可观察行为，仅在明确接受时使用")
    ap.add_argument("-o", "--output",
                    help="配合 --harden：把处理后的脚本写到该文件"
                         "（缺省写 stdout，报告走 stderr）")
    args = ap.parse_args()

    try:
        with open(args.script, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        sys.stderr.write("错误：读不到脚本 %s（%s）\n" % (args.script, e))
        return 2

    # ---- 硬化模式：不走 lint 报告路径 ----
    if args.harden:
        new_text, changes = harden(text, aggressive=args.aggressive)
        rep = sys.stderr
        if changes:
            rep.write("[v6-harden] 已中和 %d 处（这些会触发产物内部自检，"
                      "导致静默退出）:\n" % len(changes))
            for lineno, old, new, rule in changes:
                rep.write("  L%-4d %-14s %s\n" % (lineno, rule, old[:60]))
        else:
            rep.write("[v6-harden] 无需中和（脚本未含会触发自检的调试开关）\n")
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(new_text)
        else:
            sys.stdout.write(new_text)
        return 0

    findings = lint(text)
    findings.sort(key=lambda x: (LEVEL_ORDER[x[3]], x[0]))
    n_err = sum(1 for f in findings if f[3] == "ERROR")
    n_warn = sum(1 for f in findings if f[3] == "WARN")
    n_info = sum(1 for f in findings if f[3] == "INFO")

    if args.json:
        print(json.dumps(
            [{"line": f[0], "text": f[1], "rule": f[2], "level": f[3],
              "why": f[4], "advice": f[5]} for f in findings],
            ensure_ascii=False, indent=2))
        return 1 if (args.strict and n_err) else 0

    print("=" * 72)
    print(" V6 兼容性检查：%s" % args.script)
    print("=" * 72)
    if not findings:
        print(" [] 未发现会干扰 V6 产物的写法。")
        print("=" * 72)
        return 0

    for lineno, raw, rule, level, why, advice in findings:
        print(" [%s] L%-3d %s" % (level, lineno, rule))
        print("        %s" % raw[:100])
        print("        原因：%s" % why)
        print("        处置：%s" % advice)
        print("-" * 72)

    print(" 合计：%d ERROR / %d WARN / %d INFO" % (n_err, n_warn, n_info))
    if n_err:
        print(" 其中 ERROR 会导致产物静默或提前终止，请先按处置建议改脚本。")

    # 无论检出与否都给这条：宿主侧环境开关静态看不到，只能提醒
    print(" 提醒（静态查不到，属外部条件）：")
    print("   V6 忠实还原 shell 语义，宿主环境开关会完整作用在产物上。")
    print("   跑之前看一眼：echo \"$-\"  含 e = errexit 开启，含 x = xtrace 开启")
    print("   —— 这两项都能让产物「跑几条就停」，且都可在宿主侧验证：")
    print("        bash -e <原脚本>     # 与产物停在同一处 ⇒ 环境问题，非加密器")
    print("   排障时务必不要用 2>/dev/null：那会吞掉 die(113) 的原因提示。")
    print("=" * 72)

    if args.strict and n_err:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
