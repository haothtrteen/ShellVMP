#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL
echo "S01 begin"
name="obfuscator"
echo "S02 $name"
false
echo "S03 rc=$?"
for i in a b c; do echo "S04 $i"; done
sp='has "quotes" and $vars'
echo "S05 $sp"
echo "S06 end"
