/* 自动生成，勿手改 —— 由 tools/v7_isa.py emit-c 生成。
 * 顺序与 ISA_SYMBOLS 严格一致：sym id 即下标。
 * 表内只存 sym id，真名仅存在于本文件（编进二进制，受 VMP 保护）。 */
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
