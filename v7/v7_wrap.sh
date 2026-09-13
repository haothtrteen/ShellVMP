#!/usr/bin/env bash
# v7_wrap.sh —— ELF → 自释放 POSIX shell 包装
#
# 用法：bash v7_wrap.sh <input.elf> <output.sh> [isa_table.bin]
#   第 3 参（可选，r16-6）：ISA 四层随机化表（tools/v7_isa.py gen 产物，
#   r21 起为 V7IST 加密表：表体已加密+MAC，磁盘上无明文）。有表时多嵌入
#   一段 __V7_ISA__，运行期释放到临时目录（600 权限）并 export V7_ISA_TABLE
#   —— 单文件分发不破坏，表随载荷一起受加载器自校验保护（改一字节=114）。
#   环境变量 V7_SELF_MODE=1：输入为 V7_SELF 全内置产物（r19 修复）。
#   此类产物的骨架靠 zread 劫持"读脚本文件"注入 —— bash 必须带一个脚本参数
#   才会走这条路径，故加载器强制补 /dev/null 占位（空文件，内容被劫持替换），
#   否则无参数时 bash 不触发劫持 → 静默无输出（rc=0 但什么都没跑）。
#   用户参数跟在占位符后，骨架内 $1 仍等于用户第一个参数。
# 产物特性：
#   - 纯 POSIX sh（sh/bash/mksh/dash/busybox ash 均可执行）
#   - 加载器极简：无注释、紧凑单行（用户可读的只有错误提示）
#   - 运行期自剥离 LD_PRELOAD（termux-exec 注入不再误杀内层反调试；
#     同时防"hook sha256sum 伪造自校验"的注入路径）
#   - 加载器自校验：V7_SUM = sha256(全文件去掉 V7_SUM 行)，
#     篡改加载器/载荷任意字节 → 拒跑（exit 114）；载荷另受内层 HMAC 双保险
#   - 释放策略：当前目录可写且可执行 → 原地释放；否则按序回退
#     /data/local/tmp → $TMPDIR → /tmp → $HOME（noexec 挂载靠 execve 探测现形）
#   - 运行结束自动删除释放物（V7_KEEP=1 保留）；INT/TERM 亦清理
#   - 载荷 gzip 压缩（节省 ≥25% 才启用，否则裸 base64 零 gzip 依赖）
#
# 生成端依赖：base64、sha256sum、gzip（可选）
# 目标机依赖：sh、sed、base64、sha256sum、gzip（仅压缩载荷时）
set -euo pipefail

IN="${1:?用法: v7_wrap.sh <input.elf> <output.sh> [isa_table.bin]}"
OUT="${2:?用法: v7_wrap.sh <input.elf> <output.sh> [isa_table.bin]}"
ISA_T="${3:-}"
[ -f "$IN" ] || { echo "错误：输入不存在：$IN" >&2; exit 1; }
[ -z "$ISA_T" ] || [ -f "$ISA_T" ] || { echo "错误：ISA 表不存在：$ISA_T" >&2; exit 1; }
HAS_ISA=0; [ -n "$ISA_T" ] && HAS_ISA=1
command -v sha256sum >/dev/null 2>&1 || { echo "错误：生成端缺少 sha256sum（加载器自校验必需）" >&2; exit 1; }

IN_SZ=$(wc -c < "$IN")
# V7_SELF 全内置产物 → 加载器需补 /dev/null 占位参数（由 v7_build.sh 传入）
SELF_MODE="${V7_SELF_MODE:-0}"

# ---- gzip 判定（压缩收益 ≥25% 才启用）----
GZ=0
if command -v gzip >/dev/null 2>&1; then
    GZ_SZ=$(gzip -9c "$IN" | wc -c) || GZ_SZ=$IN_SZ
    if [ "$GZ_SZ" -lt $((IN_SZ * 3 / 4)) ]; then
        GZ=1
    fi
fi

# ---- base64（GNU 带 -w；BSD/busybox 无 -w 但默认换行，兼容）----
b64_file() {
    base64 -w 76 "$1" 2>/dev/null || base64 "$1"
}
b64_stream() {
    base64 -w 76 2>/dev/null || base64
}

# ---- 组装（原子写：临时文件 + mv，杜绝 IN==OUT 截断）----
# 两阶段：先写含 V7_SUM=__V7_SUM__ 占位的完整产物 → 对"去掉 V7_SUM 行"
# 的内容求 sha256 → 回填。运行期同公式复算，篡改任意字节即失配。
OUT_TMP="${OUT}.tmp.$$"
OUT_TMP2="${OUT}.tmp2.$$"
trap 'rm -f "$OUT_TMP" "$OUT_TMP2" 2>/dev/null' EXIT
{
    cat <<'HDR' | sed "s/__V7_GZ__/$GZ/; s/__V7_HAS_ISA__/$HAS_ISA/; s/__V7_SELFMODE__/$SELF_MODE/"
#!/bin/sh
V7_SUM=__V7_SUM__
V7_GZ=__V7_GZ__
V7_HAS_ISA=__V7_HAS_ISA__
V7_ELF=
V7_ISA_F=
V7_KEEP=${V7_KEEP:-0}
_v7_c(){ [ -n "$V7_ELF" ] && [ "$V7_KEEP" != 1 ] && rm -f "$V7_ELF" 2>/dev/null; [ -n "$V7_ISA_F" ] && [ "$V7_KEEP" != 1 ] && rm -f "$V7_ISA_F" 2>/dev/null; return 0; }
trap _v7_c EXIT; trap '_v7_c;exit 130' INT; trap '_v7_c;exit 143' TERM
unset LD_PRELOAD
command -v sha256sum >/dev/null 2>&1 || { echo "错误：缺少 sha256sum，无法校验加载器完整性" >&2; exit 114; }
_v7_h=$(sed '/^V7_SUM=/d' "$0" | sha256sum) || { echo "错误：加载器读取失败" >&2; exit 114; }
_v7_h=${_v7_h%% *}
[ "$_v7_h" = "$V7_SUM" ] || { echo "错误：加载器完整性校验失败（文件被篡改或传输损坏）" >&2; exit 114; }
_v7_ok(){ _v7_p=$1/.v7probe.$$; printf 'exit 0\n' > "$_v7_p" 2>/dev/null || return 1; chmod 755 "$_v7_p" 2>/dev/null || { rm -f "$_v7_p"; return 1; }; "$_v7_p" >/dev/null 2>&1 || { rm -f "$_v7_p"; return 1; }; rm -f "$_v7_p"; }
V7_DIR=; _v7_w=$(pwd 2>/dev/null) || _v7_w=.; mkdir -p /data/local/tmp 2>/dev/null
for _v7_d in "$_v7_w" /data/local/tmp "${TMPDIR:-/nonexistent}" /tmp "${HOME:-/nonexistent}"; do [ -d "$_v7_d" ] || continue; _v7_ok "$_v7_d" && { V7_DIR=$_v7_d; break; }; done
[ -n "$V7_DIR" ] || { echo "错误：找不到可写且可执行的目录（cwd、/data/local/tmp、tmp、home 均不可用）" >&2; exit 1; }
V7_ELF="$V7_DIR/.v7run.$$"
if [ "$V7_GZ" = 1 ]; then
    command -v gzip >/dev/null 2>&1 || { echo "错误：载荷为 gzip 压缩，目标机缺少 gzip" >&2; exit 1; }
    sed -n '/^__V7_PAYLOAD_BEGIN__$/,/^__V7_PAYLOAD_END__$/{/^__V7_PAYLOAD/d;p;}' "$0" | base64 -d | gzip -dc > "$V7_ELF" || { echo "错误：载荷解码/解压失败" >&2; exit 1; }
else
    sed -n '/^__V7_PAYLOAD_BEGIN__$/,/^__V7_PAYLOAD_END__$/{/^__V7_PAYLOAD/d;p;}' "$0" | base64 -d > "$V7_ELF" || { echo "错误：载荷解码失败" >&2; exit 1; }
fi
chmod 755 "$V7_ELF" 2>/dev/null || { echo "错误：chmod 失败：$V7_ELF" >&2; exit 1; }
if [ "$V7_HAS_ISA" = 1 ]; then
    V7_ISA_F="$V7_DIR/.v7isa.$$"
    # r21：落盘的是**密文表**（V7IST/v3），明文只在内层 bash 的堆里存在，
    # 用完即焚；这里再收紧权限并在退出时随 trap 一并删除。
    sed -n '/^__V7_ISA_BEGIN__$/,/^__V7_ISA_END__$/{/^__V7_ISA/d;p;}' "$0" | base64 -d > "$V7_ISA_F" || { echo "错误：ISA 表解码失败" >&2; exit 1; }
    chmod 600 "$V7_ISA_F" 2>/dev/null
    export V7_ISA_TABLE="$V7_ISA_F"
fi
_v7sm=__V7_SELFMODE__
if [ "$_v7sm" = 1 ]; then V7_SELF=1 "$V7_ELF" /dev/null ${1+"$@"}; else V7_SELF=1 "$V7_ELF" "$@"; fi
exit $?
__V7_PAYLOAD_BEGIN__
HDR

    if [ "$GZ" = "1" ]; then
        gzip -9c "$IN" | b64_stream
    else
        b64_file "$IN"
    fi
    echo "__V7_PAYLOAD_END__"
    if [ "$HAS_ISA" = "1" ]; then
        echo "__V7_ISA_BEGIN__"
        b64_file "$ISA_T"
        echo "__V7_ISA_END__"
    fi
} > "$OUT_TMP"

# ---- 自校验哈希回填 ----
SUM=$(sed '/^V7_SUM=/d' "$OUT_TMP" | sha256sum | cut -c1-64)
sed "s/^V7_SUM=__V7_SUM__$/V7_SUM=$SUM/" "$OUT_TMP" > "$OUT_TMP2"
mv -f "$OUT_TMP2" "$OUT"
chmod 755 "$OUT"
echo "成功：自释放 shell 已生成 '$OUT'（$(wc -c < "$OUT") 字节，gzip=$GZ，自校验 ${SUM:0:16}...）"
