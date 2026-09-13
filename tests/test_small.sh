#!/usr/bin/env bash
echo "S01 begin"
name="obfuscator"
echo "S02 $name"
false
echo "S03 rc=$?"
for i in a b c; do echo "S04 $i"; done
sp='has "quotes" and $vars'
echo "S05 $sp"
echo "S06 end"
