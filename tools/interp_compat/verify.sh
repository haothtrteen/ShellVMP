#!/bin/sh
# verify.sh —— 对拍 patched dash 与 bash 的 $RANDOM 是否逐比特一致
# 用法： sh verify.sh /path/to/patched/dash
D="${1:?用法: sh verify.sh <patched-dash>}"
[ -x "$D" ] || { echo "错误：$D 不可执行"; exit 1; }
ok=0; bad=0
for seed in 1234 999999 42 1 0 2147483647 65535; do
    d=$("$D"   -c "RANDOM=$seed; i=0; while [ \$i -lt 5 ]; do printf '%s ' \"\$RANDOM\"; i=\$((i+1)); done")
    b=$(bash  -c "RANDOM=$seed; for i in 1 2 3 4 5; do printf '%s ' \"\$RANDOM\"; done")
    if [ "$d" = "$b" ]; then
        ok=$((ok+1)); printf '[ok] seed=%-11s %s\n' "$seed" "$d"
    else
        bad=$((bad+1)); printf '[FAIL] seed=%-11s dash=[%s] bash=[%s]\n' "$seed" "$d" "$b"
    fi
done
echo "----------------------------------------"
echo "一致 $ok / 不一致 $bad"
[ "$bad" -eq 0 ] || exit 1
