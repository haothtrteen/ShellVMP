#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
argv_leak_scan.py —— 「敏感参数进 argv」泄露点扫描器（TShell 配套工具）

为什么需要它
------------
TShell 保护的是**脚本文本本身**，但脚本调用外部命令时，参数会以明文出现在
`/proc/<pid>/cmdline`，加壳对此零防护。实测（加壳产物运行期间，外部扫 /proc）：

    命中 /proc/528521：grep -r sk_live_abc123XYZ /usr/share/

也就是说：「脚本文本是否泄露」与「脚本里的机密是否泄露」是两件独立的事。
本工具扫的是后者 —— 列出脚本中所有会被写进 argv 的敏感字面量，并给出改造建议。

适用阶段：扫**明文输入脚本**（打包后是密文，扫不出来）。

用法
----
    python3 tools/argv_leak_scan.py 脚本.sh [更多.sh ...] [目录 ...]
    python3 tools/argv_leak_scan.py --self-test        # 内置样例自检
    python3 tools/argv_leak_scan.py --aggressive x.sh  # 启用高误报规则
    python3 tools/argv_leak_scan.py --no-mask  x.sh    # 不脱敏（便于就地改，别外传输出）

退出码：0=未发现高危/中危；1=发现需处理项；2=用法或 IO 错误

输出默认对敏感串脱敏（保留首尾各 4 位），避免扫描报告本身成为新的泄露源。
同一位置多个规则命中时，保留更具体的那条（按 pri 优先级去重）。
"""

import argparse
import os
import re
import sys

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
RISK_TAG = {"HIGH": "高危", "MEDIUM": "中危", "LOW": "低危"}

# ---------------------------------------------------------------- 敏感串规则
# re     : 正则
# risk   : 风险等级
# aggr   : True 表示仅 --aggressive 时启用（误报率高）
# ctx    : 命令上下文白名单；为 None 表示不限制。行内无这些命令则跳该规则
# mg     : 脱敏/展示时用第几个捕获组（0=整条匹配）。用于只打码 value 不打码 key
# pri    : 优先级，同一区间重叠时保留 pri 高者
PATTERNS = [
    {"id": "stripe_live", "name": "Stripe live key",
     "re": r'sk_live_[A-Za-z0-9]{8,}', "risk": "HIGH", "aggr": False,
     "ctx": None, "mg": 0, "pri": 95},
    {"id": "aws_akid", "name": "AWS access key id",
     "re": r'AKIA[0-9A-Z]{16}', "risk": "HIGH", "aggr": False,
     "ctx": None, "mg": 0, "pri": 95},
    {"id": "github_tok", "name": "GitHub token",
     "re": r'gh[pousr]_[A-Za-z0-9]{20,}', "risk": "HIGH", "aggr": False,
     "ctx": None, "mg": 0, "pri": 95},
    {"id": "slack_tok", "name": "Slack token",
     "re": r'xox[abpsr]-[A-Za-z0-9-]{10,}', "risk": "HIGH", "aggr": False,
     "ctx": None, "mg": 0, "pri": 95},
    {"id": "google_key", "name": "Google API key",
     "re": r'AIza[0-9A-Za-z_\-]{35}', "risk": "HIGH", "aggr": False,
     "ctx": None, "mg": 0, "pri": 95},
    {"id": "jwt", "name": "JWT",
     "re": r'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}',
     "risk": "HIGH", "aggr": False, "ctx": None, "mg": 0, "pri": 95},
    {"id": "privkey_pem", "name": "PEM 私钥块",
     "re": r'-----BEGIN [A-Z ]*PRIVATE KEY-----', "risk": "HIGH", "aggr": False,
     "ctx": None, "mg": 0, "pri": 95},
    {"id": "stripe_test", "name": "Stripe test key",
     "re": r'sk_test_[A-Za-z0-9]{8,}', "risk": "MEDIUM", "aggr": False,
     "ctx": None, "mg": 0, "pri": 70},
    {"id": "bearer", "name": "Authorization Bearer 头",
     "re": r'(?i)Bearer\s+([A-Za-z0-9_\-\.=]{10,})', "risk": "HIGH", "aggr": False,
     "ctx": None, "mg": 1, "pri": 90},
    {"id": "url_cred", "name": "URL 内嵌凭证 user:pass@host",
     "re": r'[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:([^/\s:@]+)@',
     "risk": "HIGH", "aggr": False, "ctx": None, "mg": 1, "pri": 90},
    {"id": "dash_p_pass", "name": "命令行 -p 直连密码",
     "re": r'(?<![\w-])-p[A-Za-z0-9!@#$%^&*_]{4,}', "risk": "HIGH", "aggr": False,
     "ctx": ["mysql", "mysqldump", "pg_dump", "psql", "sshpass", "smbclient",
             "ldapsearch"], "mg": 0, "pri": 85},
    {"id": "dashdash_pass", "name": "--password=/--token= 形态",
     "re": r'(?i)--(?:password|passwd|pwd|token|api[_-]?key|secret)=["\']?([^"\'\s]{3,})',
     "risk": "HIGH", "aggr": False, "ctx": None, "mg": 1, "pri": 85},
    {"id": "dash_u_cred", "name": "-u user:pass 形态",
     "re": r'(?<![\w-])-u\s+[A-Za-z0-9_.\-]+:([^\s]{3,})', "risk": "HIGH",
     "aggr": False, "ctx": None, "mg": 1, "pri": 85},
    {"id": "url_secret_q", "name": "URL query 含 token/key/secret",
     "re": r'[?&](?:token|access_token|key|secret|password|passwd|pwd|api_key'
           r'|auth)=([^&\s"\']{3,})',
     "risk": "HIGH", "aggr": False, "ctx": None, "mg": 1, "pri": 80},
    {"id": "kv_secret", "name": "敏感 key=value 字面量",
     "re": r'(?i)\b(?:token|api[_-]?key|apikey|secret|password|passwd|pwd'
           r'|access[_-]?token|private[_-]?key)\s*=\s*["\']?([A-Za-z0-9_\-\.]{6,})',
     "risk": "HIGH", "aggr": False, "ctx": None, "mg": 1, "pri": 60},
    {"id": "keyfile_path", "name": "私钥/凭证文件路径",
     "re": r'(?i)(?:^|[\s=])~?/(?:[^/\s]*/)*(?:\.ssh/id_[a-z0-9]+'
           r'|\.aws/credentials|\.docker/config\.json|\.netrc|\.pgpass)',
     "risk": "MEDIUM", "aggr": False, "ctx": None, "mg": 0, "pri": 50},
    {"id": "hex_long", "name": "长 hex 串（≥32，可能是密钥或 hash）",
     "re": r'\b[0-9a-fA-F]{32,}\b', "risk": "MEDIUM", "aggr": False,
     "ctx": None, "mg": 0, "pri": 30},
    {"id": "b64_long", "name": "长 base64 类串（≥24，误报率高）",
     "re": r'\b[A-Za-z0-9+/]{24,}={0,2}\b', "risk": "LOW", "aggr": True,
     "ctx": None, "mg": 0, "pri": 10},
]

# ------------------------------------------------------------ 命令级改造建议
# 选项均已在 bash 5.2 / curl / gpg / openssl 上核实存在；未核实的已注明
FIX = {
    "grep": "grep -f <(printf '%s\\n' \"$P\") 或 -f FILE —— 模式不进 argv",
    "egrep": "同 grep：-f FILE",
    "fgrep": "同 grep：-f FILE",
    "rg": "rg -f FILE",
    "sed": "sed -f <(printf '%s\\n' \"$PROG\") —— 脚本体不进 argv",
    "awk": "awk -f <(printf '%s\\n' \"$PROG\") —— 程序体不进 argv",
    "curl": "curl -K/--config FILE（已核实）；彻底方案：改用 libcurl 在 C 内发请求，参数不出进程",
    "wget": "无「从文件读 URL」选项 —— 建议换 curl，或改用 C 实现",
    "ssh": "走 ~/.ssh/config 或 SSH_ASKPASS；勿在命令行放密码",
    "scp": "同上：ssh config / 密钥认证",
    "rsync": "--password-file=FILE（本机未装 rsync，使用前请 rsync --help 核实）",
    "mysql": "MYSQL_PWD，或 --defaults-extra-file=<(...)",
    "mysqldump": "同 mysql：--defaults-extra-file=FILE",
    "psql": "PGPASSWORD，或 ~/.pgpass（权限 600）",
    "pg_dump": "同 psql：PGPASSWORD / .pgpass",
    "openssl": "-passin file:FILE 或 -passin env:VAR（已核实支持，勿用 pass:）",
    "gpg": "--passphrase-fd N 或 --passphrase-file FILE（已核实存在）",
    "aws": "走 ~/.aws/credentials 或环境变量；勿在 argv 放 key",
    "git": "URL 内嵌 token 改用 credential helper 或 ~/.netrc",
    "docker": "docker login 走 ~/.docker/config.json；勿用 -p 传密码",
}
GENERAL_FIX = ("该命令无「从文件读参数」的通用方案 —— 建议：① 用 C 封装该调用，"
               "参数内嵌加密 + VMP；② 或接受「同权限用户可读」，至少挡住 ps 批量扫描")

ASSIGN_FIX = ("变量赋值：值最终会经 $VAR 进 argv。建议改为运行时从文件/fd 读取"
              "（如 SECRET=\"$(< /path/secret)\"），或把该参数改为 -f FILE / config 形式")


def mask(s, keep=4):
    """脱敏：保留首尾各 keep 位，中间打星。避免扫描报告二次泄露。"""
    s = str(s)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]


def strip_comment(line):
    """去掉行尾注释（仅处理 ' #' 形式，避免误伤字符串内的 #）。"""
    m = re.search(r'\s#', line)
    return line[:m.start()] if m else line


def find_commands(line):
    """提取行内的命令名（按 ; && || | 切分后取首个 token，剥掉 sudo/command）。"""
    cmds = []
    for part in re.split(r'(?:;|&&|\|\||\|)', line):
        part = part.strip().lstrip("(").strip()
        m = re.match(r'^(?:sudo\s+|command\s+)?([A-Za-z0-9_./\-]+)', part)
        if m:
            cmds.append(os.path.basename(m.group(1)))
    return cmds


def is_assignment(line):
    """是否为变量赋值行（敏感值会经变量最终进 argv）。"""
    return bool(re.match(r'^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=', line))


def scan_text(text, path="<stdin>", aggressive=False, do_mask=True):
    """扫描脚本文本，返回 findings 列表（同一区间保留优先级最高者）。"""
    compiled = [(p, re.compile(p["re"])) for p in PATTERNS]
    findings = []

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        code = strip_comment(line)
        if not code.strip():
            continue
        cmds = find_commands(code)
        assign = is_assignment(code)
        cmdset = set(cmds)

        # 收集本行所有命中：(start, end, pri, finding)
        hits = []
        for p, rx in compiled:
            if p["aggr"] and not aggressive:
                continue
            if p["ctx"] and not (cmdset & set(p["ctx"])):
                continue
            for m in rx.finditer(code):
                mg = p["mg"]
                # m.re.groups 是正则的捕获组数量（int）；m.groups() 返回的是元组
                target = m.group(mg) if (mg > 0 and m.re.groups >= mg) else m.group(0)
                if not target:
                    continue
                # 命令：赋值行不猜命令；否则优先取 FIX 表里有的
                cmd = ""
                if not assign:
                    for c in cmds:
                        if c in FIX:
                            cmd = c
                            break
                    if not cmd and cmds:
                        cmd = cmds[0]
                shown = target if not do_mask else mask(target)
                src = code.strip()
                if do_mask:
                    src = src.replace(target, shown)
                findings_hit = {
                    "file": path, "line": lineno, "id": p["id"], "name": p["name"],
                    "risk": p["risk"], "cmd": cmd, "hit": shown, "src": src,
                    "assign": assign,
                }
                hits.append((m.start(), m.end(), p["pri"], findings_hit))

        # 去重：优先级高的先占位，区间重叠的丢弃
        hits.sort(key=lambda x: (-x[2], x[0]))
        taken = []
        for st, en, _pri, f in hits:
            if any(not (en <= s or st >= e) for s, e in taken):
                continue
            taken.append((st, en))
            findings.append(f)

    return findings


def print_findings(findings, total_files):
    if not findings:
        print("未发现「敏感参数进 argv」的字面量。")
        print("注意：本工具只扫静态字面量；运行时拼出的敏感串（$VAR 展开、命令替换）扫不到。")
        return 0

    findings.sort(key=lambda f: (RISK_ORDER[f["risk"]], f["file"], f["line"]))
    cur = None
    for f in findings:
        if f["file"] != cur:
            cur = f["file"]
            print("\n" + "=" * 70)
            print("文件: %s" % cur)
            print("=" * 70)
        note = "  [变量赋值]" if f["assign"] else ""
        print("\n  行 %-4d [%s] %s%s" % (f["line"], RISK_TAG[f["risk"]],
                                         f["name"], note))
        if f["cmd"]:
            print("       命令 : %s" % f["cmd"])
        print("       命中 : %s" % f["hit"])
        print("       原文 : %s" % f["src"])
        if f["assign"]:
            print("       建议 : %s" % ASSIGN_FIX)
        else:
            print("       建议 : %s" % FIX.get(f["cmd"], GENERAL_FIX))

    hi = sum(1 for f in findings if f["risk"] == "HIGH")
    md = sum(1 for f in findings if f["risk"] == "MEDIUM")
    lo = sum(1 for f in findings if f["risk"] == "LOW")
    cmds = sorted({f["cmd"] for f in findings if f["cmd"]})
    print("\n" + "-" * 70)
    print("汇总：扫描 %d 个文件，命中 %d 处 —— 高危 %d / 中危 %d / 低危 %d"
          % (total_files, len(findings), hi, md, lo))
    if cmds:
        print("涉及命令：%s" % ", ".join(cmds))
    if hi or md:
        print("\n这些串在产物运行时会出现在 /proc/<pid>/cmdline —— 加壳不提供任何防护，")
        print("外部扫一遍 /proc 即可取得。建议优先处理高危项。")
        return 1
    return 0


SELF_TEST_SAMPLE = r'''#!/bin/bash
# 自检样例：覆盖常见泄露形态（均为假数据）
TOKEN="ghp_1234567890abcdefghijklmnopqrstuvwxyz"
API_URL="https://api.example.com/v1/data?token=abc123secret"

curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" \
     "$API_URL"
curl https://user:pa55word@example.com/pull
mysql -h db.internal -u root -pSup3rS3cret mydb
wget https://download.example.com/pkg.tar.gz
grep -r "sk_live_FIXTURE1234" /srv/app/
echo "clean line, nothing sensitive here"
printf '%s\n' "$(date)" > /tmp/log
'''


def iter_files(paths):
    """展开参数：文件直接用，目录递归找 .sh/.bash。"""
    out = []
    for p in paths:
        if os.path.isfile(p):
            out.append(p)
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs
                           if d not in (".git", "__pycache__", "node_modules")]
                for fn in files:
                    if fn.endswith((".sh", ".bash")):
                        out.append(os.path.join(root, fn))
        else:
            print("警告：路径不存在，已跳过：%s" % p, file=sys.stderr)
    return sorted(set(out))


def main():
    ap = argparse.ArgumentParser(
        description="扫描 shell 脚本中「敏感参数进 argv」的泄露点（加壳不防此类泄露）")
    ap.add_argument("paths", nargs="*", help="脚本文件或目录")
    ap.add_argument("--self-test", action="store_true", help="用内置样例自检")
    ap.add_argument("--aggressive", action="store_true",
                    help="启用高误报规则（长 base64 类串）")
    ap.add_argument("--no-mask", action="store_true",
                    help="不脱敏（便于就地修改；注意输出本身含机密）")
    args = ap.parse_args()

    do_mask = not args.no_mask

    if args.self_test:
        print("[自检] 内置样例（假数据），应当命中多处：")
        fs = scan_text(SELF_TEST_SAMPLE, "<self-test>", args.aggressive, do_mask)
        return print_findings(fs, 1)
    if not args.paths:
        ap.print_help()
        return 2

    files = iter_files(args.paths)
    if not files:
        print("错误：没有找到可扫描的脚本文件", file=sys.stderr)
        return 2

    all_f = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                txt = fh.read()
        except OSError as e:
            print("警告：读取失败 %s（%s）" % (fp, e), file=sys.stderr)
            continue
        all_f.extend(scan_text(txt, fp, args.aggressive, do_mask))

    return print_findings(all_f, len(files))


if __name__ == "__main__":
    sys.exit(main())
