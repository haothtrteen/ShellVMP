/* 自动生成，勿手改 —— 由 tools/v7_isa.py emit-c 生成。
 * 顺序与 ISA_SYMBOLS 严格一致：sym id 即下标。
 * 表内只存 sym id，真名仅存在于本文件（编进二进制，受 VMP 保护）。 
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 * 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
 *  * 分发内含魔改 bash 的产物时必须提供对应完整源码。
 */

#ifndef V7_ISA_SYMS_H
#define V7_ISA_SYMS_H

static const char *const v7_isa_syms[] = {
    "echo",
    "printf",
    "export",
    "local",
    "unset",
    "read",
    "true",
    "false",
    "getprop",
    "setprop",
    "am",
    "pm",
    "mount",
    "umount",
    "find",
    "mkdir",
    "date",
    "if",
    "then",
    "elif",
    "else",
    "fi",
    "while",
    "until",
    "do",
    "done",
    "for",
    "case",
    "esac",
    "function",
    "$0",
    "$1",
    "$2",
    "$3",
    "$4",
    "$5",
    "$6",
    "$7",
    "$8",
    "$9",
    "$@",
    "$#",
    "$*",
    "/data",
    "/system",
    "/system/bin",
    "/data/adb",
    "/sdcard",
};

#define V7_ISA_NSYMS ((int)(sizeof(v7_isa_syms) / sizeof(v7_isa_syms[0])))

#endif /* V7_ISA_SYMS_H */
