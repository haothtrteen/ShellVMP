#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diag_strip.py —— 剔除 zread 注入层的 `v7: ` 诊断串（对应 S2）

为何要做
--------
`strings <产物>` 能直接看到 9 条 `v7: xxx`，包括：
    v7: 无法打开 /proc/self/exe
    v7: 产物未内嵌脚本（尺寸异常）
    v7: 外层口令错误或产物被篡改（HMAC 校验失败）
    ...
这等于免费告诉攻击者三件事：①这是 TShell V7 加壳产物；②脚本走 /proc/self/exe
自读；③认证用 HMAC 且失败有独立退出码。属于「零成本情报泄漏」。

【明确边界：哪些串不能动】
    TracerPid  —— 运行时读 /proc/self/status 用的键名字面量
    frida      —— 运行时匹配注入特征用的目标串
  这两个是**功能性常量**，剔除会直接打断反调试功能本身，本脚本刻意不碰。
  要隐藏它们只能改成运行时拼接构造（后续可选项，非本步范围）。

做法
----
定位每一处 `v7: ` 起始的 C 字符串，整串覆写为 NUL（保持原字节长度不变，
文件大小与所有偏移地址完全不动，因此不影响任何重定位/符号/VM 元数据）。
替换后 `fprintf(stderr, "")` 为空输出；退出码契约（114 等）保持不变，
排错改看 README 的「退出码契约」表。

用法
----
    python3 diag_strip.py <ELF文件>            # 原地剔除
    python3 diag_strip.py <输入> -o <输出>
    python3 diag_strip.py <ELF文件> --check    # 仅统计，不改写
"""
import sys

MARK = b"v7: "
MODE = "blank"


def find_strings(data: bytes):
    """返回每处 v7: 串的 (start, end)，end 指向结尾 NUL 之后。"""
    out = []
    pos = data.find(MARK)
    while pos != -1:
        nul = data.find(b"\x00", pos)
        if nul == -1:
            nul = len(data)
        out.append((pos, nul + 1))
        pos = data.find(MARK, nul + 1)
    return out


def check(path: str) -> int:
    d = open(path, "rb").read()
    found = find_strings(d)
    print("%s: 发现 %d 条 v7: 诊断串" % (path, len(found)))
    for s, e in found:
        txt = d[s:e - 1].decode("utf-8", "replace")
        print("   [0x%x] %r" % (s, txt))
    return 1 if found else 0


def strip(data: bytearray, mode: str = "blank") -> int:
    """覆写每处诊断串。mode:
        blank —— 等长空格（保留末尾 \\n），输出干净且不泄漏情报（默认）
        raw   —— 全部置 0（会因 fwrite 常量长度仍吐出 NUL，不推荐）
    """
    hits = find_strings(bytes(data))
    for s, e in hits:
        body_end = e - 1                      # NUL 位置
        has_nl = body_end - 1 > s and data[body_end - 1:body_end] == b"\n"
        tail = body_end - 1 if has_nl else body_end
        if mode == "raw":
            fill = 0
        else:
            fill = 0x20                       # 空格
        for i in range(s, tail):
            data[i] = fill
        # 末尾换行保留，避免多个错误串连成一行
    return len(hits)


def main(argv):
    global MODE
    out = None
    check_only = False
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-o":
            i += 1; out = argv[i]
        elif a == "--check":
            check_only = True
        elif a == "--mode":
            i += 1; MODE = argv[i]
        elif a in ("-h", "--help"):
            sys.stdout.write(__doc__ or ""); return 0
        else:
            args.append(a)
        i += 1
    if not args:
        sys.stderr.write(__doc__ or ""); return 2
    path = args[0]

    if check_only:
        return check(path)

    data = bytearray(open(path, "rb").read())
    n = strip(data, MODE)
    target = out or path
    with open(target, "wb") as f:
        f.write(bytes(data))
    print("已剔除 %d 条 v7: 诊断串（mode=%s）→ %s (%d 字节，大小不变)"
          % (n, MODE, target, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
