# 解释器兼容层实证 —— 给 dash 装 bash 兼容的 `$RANDOM`

> ## ⚠ 状态更新（2026-09-14）：**本路线已被更简单的方法取代，保留作历史记录**
>
> mksh 兼容改造期间发现：**不需要给任何 shell 打补丁**。用一个**纯算术的内联 PRNG**（`_rn()`，约 15 行 shell 代码）就能在 **bash / mksh / dash 三个 shell 下**逐位复刻 bash 5.1+ 的 `$RANDOM` 序列。
>
> ```
> 本方案的路线：改 dash 源码（var.c +75 行）→ 重新编译 → 用户得装补丁版 dash
> 取代它的方案：产物里内联一个 _rn() 函数 → 零依赖 → 三个 shell 同时覆盖
> ```
>
> 所以：
> - `tools/interp_compat/dash-random-hook.patch`、`bash_random_portable.h` **不再是路线**，
>   保留在仓库里作为**方法论存档**（它证明了"逐位复刻 bash 序列"这个目标是可达成的，
>   这是当时最有价值的信息）。
> - `verify.sh`（差分测试脚本）仍有参考价值 —— 它对比 7 组种子与 bash 的一致性，
>   这个**验证思路**被 `tools/sh_compat_check.sh` 继承并扩展到了整个产物层面。
> - 实测结果见 [`SHELL_TARGETS.md`](SHELL_TARGETS.md) 第九节。
>
> **教训**：当时把"让别的 shell 具备 bash 语义"理解成了"得改 shell 本身"。
> 实际上，**只要这段语义可以用纯算术表达，就可以内联进产物** ——
> 不改环境，改脚本。这不仅更简单，而且顺带覆盖了所有 shell，
> 而不是一个 shell 一个补丁。

> **一句话结论**：**思路成立，已跑通，实测逐比特一致。** 但它是"把 bash 语义搬给别的 shell"的**第一块砖**，不是通用化的全部 —— 实测 patched dash 跑 V6 产物**仍失败**，卡在下一层（语法）。
>
> 这份文档记录的是**真跑过的代码**，不是推演。

---

## 一、你的思路为什么成立

你问的是：

> "像 random 这种我们可以把 bash 的模拟器提取出来写个 hook 补丁让用户把它编译进自己的 sh 解释器里吗？"

**成立，而且比预想的干净。** 三个理由：

1. **`$RANDOM` 的实现是自包含的。** bash 的 `$RANDOM` 全部逻辑在 `lib/sh/random.c`（240 行），核心只有 `intrand32()` 一个 20 行的纯算术函数 —— 不碰文件系统、不碰终端、不依赖 bash 的其它子系统。

2. **dash 有现成的 hook 位置。** dash 所有变量取值都走 `var.c:lookupvar()`，而它**自己就已经有同类先例**：`WITH_LINENO` 时 `$LINENO` 就是在 `lookupvar` 里现场格式化到静态缓冲区再返回（`var.c:361-363`）。照搬这个模式即可。

3. **代码量极小。** 实测 `var.c` 只增加 **75 行**，不动 parser / expand / exec，不动构建系统。

---

## 二、实测结果

### 2.1 逐比特对拍（7 组种子，各取 5 个连续值）

```
[ok] seed=1234        30658 14076 1273 22557 9363
[ok] seed=999999      24550 28971 19069 1986 5165
[ok] seed=42          17772 26794 1435 24388 11074
[ok] seed=1           16807 10791 19566 13983 29619
[ok] seed=0           20814 24386 149 25587 12277
[ok] seed=2147483647  ...
[ok] seed=65535       ...
----------------------------------------
一致 7 / 不一致 0
```

**patched dash 与 bash 5.2 输出完全一致。** 包括边界种子 `0`（Park-Miller 不能以 0 为种子，需代入 `123459876`）和 `2147483647`（模数上界）。

### 2.2 产物复现（`verify.sh`）

```sh
sh verify.sh /path/to/patched/dash
```

对拍脚本已随仓库提供，任何人可自行复现。**这是"可复现"而非"我声称"**。

---

## 三、实现要点（三个踩过的坑）

这三个坑都**实测踩到并修掉**了，照抄时务必留意：

### 坑 1 · 注册时**不能**加 `VTEXTFIXED`

第一版我按 `linenovar` 的样子注册：

```c
{ 0, VSTRFIXED|VTEXTFIXED, randomvar, 0 },
```

结果 `$RANDOM` 回显字面量（`1234 1234 1234`）。

**原因**：`setvareq()` 在 `var.c:340` 判断 `(vp->flags & (VTEXTFIXED|VSTACK)) == 0` 才 `ckfree(vp->text)`；加了 `VTEXTFIXED` 就**不 free**，但紧接着 `var.c:367` 直接把 `vp->text = s` 覆盖成新串 —— 我那个 `v->text == randomvar` 的指针判定从此永远为假。

### 坑 2 · 赋值路径必须用 `func` hook 吞掉

**bash 里 `RANDOM=n` 是「播种」，不是「赋值」**。而 dash 默认把它当普通赋值。

修法：注册时挂 `func`（照搬 `changepath` 的模式），在 hook 里把数字解析成种子、**不落 text**：

```c
{ 0, VSTRFIXED|VTEXTFIXED, randomvar, v7_setrandom },
```

### 坑 3 · `setvareq` 尾部要拦住 `text` 覆盖

即使坑 2 修好，`setvareq` 尾部那一行 `vp->text = s` 仍会把占位符冲掉。需要在赋值后判断"原本是不是 `randomvar`"，是就还原（并释放临时串）：

```c
if (vp->text == randomvar) {
    if (s != randomvar && !(flags & (VTEXTFIXED|VSTACK|VNOSAVE)))
        ckfree(s);
} else {
    vp->text = s;
}
```

> 这三处合起来才构成完整补丁。**任何一处单独拿掉，`$RANDOM` 都会静默退化成普通变量** —— 不报错，只是值不对。

---

## 四、必须说清楚的边界

### 4.1 `$RANDOM` 只是第一块砖 —— 实测仍未跑通产物

我把这个补丁装进 dash，然后拿 **V6 的真实产物**去跑：

| 解释器 | 跑 V6 产物 | 失败点 |
|---|---|---|
| bash 5.2 | ✅ 正常输出 | — |
| **原版 dash** | ❌ | `declare: not found` ×2、`Bad substitution`、数组赋值被当命令 ×6 |
| **patched dash**（打了 RANDOM 补丁） | ❌ **仍然失败** | **报错种类完全一样**：`declare: not found`、`Bad substitution` |

**patched dash 的报错和原版 dash 一模一样。** `$RANDOM` 那层通了（我单独对拍验证过），但它被挡在了**更前面**的语法层 —— `declare -a`、数组下标、`${var//}`、`[[ ]]`、`<<<`。

这就是 `GENERALIZATION_FEASIBILITY.md` 里说的**第 2 层阻塞**，`$RANDOM` 属于第 3 层。**第 3 层通了，第 2 层没过，产物照样跑不起来。**

### 4.2 还有几个"同样可 hook"的量

顺着你的思路，这些**也能用同类手法补**（都是"提取 bash 语义 → 给自定义解释器"）：

| 量 | bash 行为 | 可 hook 性 |
|---|---|---|
| `$RANDOM` | Park-Miller + 折叠 + 去重 | ✅ **已实证跑通** |
| `$SRANDOM` | `/dev/urandom` 直读 | ✅ 容易 |
| `$EPOCHREALTIME` | `gettimeofday` 微秒 | ✅ 容易（`v7_build.sh` 里已用类似手段） |
| `$BASH_VERSINFO[0]` | 主版本号 | ✅ 容易（常量） |
| `$-` | 选项位串 | ⚠️ **难**：dash 的选项位语义与 bash 不同（实测 dash 空串、zsh `569X`） |
| `$_` | 上条命令最后一个参数 | ⚠️ **难**：dash 根本没有这个变量，要改 expand 层 |
| `$?` | 退出码 | ⚠️ **难**：管道退出码等边界语义与 bash 有差异 |

**但这些都是第 3 层。** 第 2 层（语法）不解决，补再多第 3 层也没用。

### 4.3 一个反直觉的结论

> **"让别的解释器拥有 bash 语义" ≠ "让 ShellVMP 支持别的 shell"。**

前者是把 bash 的行为搬过去（本条路线）；后者要求**产物本身只用目标 shell 的语法**。两者方向不同：

- 本条路线：产物仍是 bash 语法，但跑在"学会 bash 语义的 dash"上 → **还需改语法**
- 另一条路线：产物改用 POSIX 语法，跑在原生 dash 上 → **不需要 hook，但要去掉 bash 专属保护**

**两条都绕不开第 2 层的语法改造。** 区别只在于第 3 层由谁来补。

---

## 五、这条路线的真实价值

虽然单靠它跑不通产物，但**它把第 3 层从"死结"变成了"已解的方程"**：

| 之前的判断 | 修正后 |
|---|---|
| `$RANDOM` 算法不同 → 必须重新逆向，工作量大 | ✅ **已逆向完成并验证**，75 行代码 |
| dash 没有 `$RANDOM` → 需要整条密钥推进机制换实现 | ✅ **不必换实现**：hook 上去后密钥推进公式原样可用 |
| 跨 shell 的最大障碍是 `$RANDOM` | ❌ **修正**：`$RANDOM` 反而**最容易解**；真正的障碍是第 2 层语法（`declare -a`、`[[ ]]`、`${var//}`、`<<<`） |

**换句话说：你点的这个方向，恰好是整个跨 shell 工程里最"干净"的一块 —— 它已经通了。**

---

## 六、产物清单

| 文件 | 说明 |
|---|---|
| `bash_random_portable.h` | bash `$RANDOM` 生成器的可移植 C 实现（自包含，无依赖） |
| `dash-random-hook.patch` | 给 dash 的 `var.c` 打的 diff（+75 行，含三处坑的注释） |
| `verify.sh` | 对拍脚本：`sh verify.sh <patched-dash>`，7 组种子逐比特比对 |

**构建**：

```sh
# 1) 取 dash 源码并生成 configure
cd dash-0.5.12 && sh ./autogen.sh

# 2) 打补丁
patch -p0 < dash-random-hook.patch     # 或按 .patch 内说明手工应用

# 3) 构建
sh ./configure && make -j4

# 4) 验证
sh verify.sh ./src/dash
```

**摘除**：`make CPPFLAGS=-DV7_NO_BASH_RANDOM` —— 编译期关闭，零残留。

---

## 七、下一步建议

如果你的目标是"真正让产物跑在 dash 上"，按这个顺序推：

1. **先做第 2 层语法改造**（`declare -a` → 空格分隔 + `set --`；`[[ ]]` → `case`；`<<<` → 重定向；`${var//}` → `tr`）—— 这是**大头**，也是能否跑通的决定因素。
2. **`$RANDOM` 直接复用本补丁**（已通，零风险）。
3. **`$-` / `$_` / `$?` 建议"参数化"而非"hook"** —— 见 `GENERALIZATION_FEASIBILITY.md` 第 3 层因子表：`$-` 在编译期就是个常量，注入即可，不必 hook。
4. **止损点不变**：第 2 层改造完，生成一个 dash 产物试跑**第一个块**。跑不通就停。

---

*实证环境：x86_64 / Ubuntu 22.04，bash 5.2.21、dash 0.5.12（源码构建）、zsh 5.9。*
*相关文档：[`GENERALIZATION_FEASIBILITY.md`](GENERALIZATION_FEASIBILITY.md)（三层阻塞分析）、[`ARCHITECTURE.md`](ARCHITECTURE.md)（密钥链设计）。*
