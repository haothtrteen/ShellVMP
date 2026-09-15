#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
# V6 终版三件套加固回归样本：确定性输出（无 date/$RANDOM/$$/网络/stdin/cd/set -e）
# 专门覆盖三条新绑定路径：
#   rc 绑定 —— 多个块以非零返回码结尾（false/[ ]/((0))/command-not-found）
#   rt 绑定 —— $_ 含空格/引号/反引号/换行/空串/中文 的命令
#   pp 绑定 —— 任意块都触发（路径字段强制掺入 _s）

echo "T01 start"
msg="hello world"
echo "$msg"
false
[ 1 -eq 2 ]
zzz_missing_cmd_xyz 2>/dev/null
x=0
((x))
grep -q zzz_nonexistent_line /etc/hostname
echo "T10 past rc traps"

greet() {
    local who="$1"
    printf 'hi %s' "$who"
}
greet "tester"
echo "T12 func rc=$?"

acc=0
for i in 1 2 3 4 5; do
    acc=$((acc + i))
done
echo "T14 acc=$acc"

case $((acc % 3)) in
    0) echo "T15 rem zero" ;;
    1) echo "T15 rem one" ;;
    *) echo "T15 rem other" ;;
esac

nl=$'line1\nline2'
echo "$nl"
echo 'T17 special: "double" `tick` $dollar \back'
empty_arg=""
true "$empty_arg"
echo "T19 after empty"

counter=0
counter=$((counter + 1))
echo "T21 count=$counter"
test 2 -gt 3
echo "T22 test rc=$?"

sum=0
n=1
while [ "$n" -le 4 ]; do
    sum=$((sum + n))
    n=$((n + 1))
done
echo "T25 sum=$sum"

cat <<'EOF'
T26 heredoc alpha
T26 heredoc beta
EOF

arr=(10 20 30)
echo "T28 total=$((arr[0] + arr[1] + arr[2]))"

echo "T29 中文输出测试"
printf '%s\n' "T30 printf pct 100%% done"

double() {
    echo "$(( $1 * 2 ))"
}
echo "T32 double=$(double 21)"

if [ "$counter" -ge 1 ]; then
    echo "T33 counter positive"
else
    echo "T33 counter zero"
fi

echo "T34 tail $_"

join3() {
    local IFS=','
    printf '%s' "$*"
}
join3 a b c
echo ""
echo "T37 joined"

until [ "$counter" -ge 3 ]; do
    counter=$((counter + 1))
done
echo "T39 counter=$counter"

echo -n "T40 no-newline"
echo ""
echo "T41 $_ last-arg probe"
: "silent colon arg"
echo "T42 after colon"

subshell_test=$(echo "T43 subshell capture")
echo "$subshell_test"
echo "T44 end of sample"
