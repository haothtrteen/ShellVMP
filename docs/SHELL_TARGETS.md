# Shell 靶子选择调研（SHELL_TARGETS）

> 回答一个问题：**兼容哪些 shell 才值得？** 以及一个意外发现：**我们一直瞄错了靶子。**
>
> 调研 + 实测时间：2026-09-14。所有兼容性数据均为本机实测（bash 5.2 / mksh R59 / dash 0.5.12 / zsh 5.9），非引用。

---

## 一、最重要的发现：Android 用的是 mksh，不是 dash

**ShellVMP 的目标平台是 Android。而 Android 的系统 shell 不是 dash。**

`/system/bin/sh` 的真实身份（按 Android 官方 `shell_and_utilities/README.md` 与实测）：

| Android 版本 | `/system/bin/sh` 实际是 |
|---|---|
| ≤ 4.0（ICS 之前） | NetBSD ash |
| 4.0（Ice Cream Sandwich）起 | **mksh**（MirBSD Korn Shell） |
| 5.0 起 | **mksh**（ash 已从树中移除） |
| 至今（14/15） | **mksh** |

实测确认（来自设备 `$KSH_VERSION`）：

```
@(#)MIRBSD KSH R55 2017/04/12
```

**这意味着：如果为了"让产物能在 Android 上不装 bash 跑起来"去做 dash 兼容，那是白做。** Android 上要兼容的是 **mksh**。

> 这个发现**直接改变了档位 2 的定义**：原来写的"dash-only PoC"应该改成 **"mksh-only PoC"**，甚至可以直接叫 **"Android 原生 PoC"**。

---

## 二、关键实测：mksh 的兼容性远好于 dash

这是本轮最有价值的数据。对产物用到的每一个构造，逐 shell 实测：

| 构造 | bash | **mksh** | dash | zsh |
|---|---|---|---|---|
| `declare -a X` | ✅ | ❌ | ❌ | ❌ |
| `${a[0]}` 下标读 | ✅ | ✅ | ✅ | ✅ |
| **真数组 `a=(1 2 3)`** | ✅ | ✅ | ❌ | ✅ |
| `${#a[@]}` | ✅ | ✅ | ❌ | ✅ |
| `[[ ]]` 条件 | ✅ | ✅ | ❌ | ✅ |
| **here-string `<<<`** | ✅ | ✅ | ❌ | ✅ |
| `${var//x/y}` 替换 | ✅ | ✅ | ❌ | ✅ |
| `$(( ))` 算术 | ✅ | ✅ | ✅ | ✅ |
| `for ((;;))` C 风格 | ✅ | ❌ | ❌ | ❌ |
| **进程替换 `<(…)`** | ✅ | ❌ | ❌ | ❌ |
| `local`（函数内） | ✅ | ✅ | ✅ | ✅ |
| `builtin type -t` | ✅ | ❌ | ❌ | ❌ |
| `EPOCHREALTIME` | ✅ | ✅(空) | ✅(空) | ✅ |

### 结论：mksh 只差 3 个构造

**`declare -a`、`for ((;;))`、`<(…)`、`builtin type -t`** —— 就这几个。

**而 dash 差的是一大片**：真数组、`[[ ]]`、`<<<`、`${var//}` 全不支持。

> **所以正确顺序是：先兼容 mksh，not dash。** mksh 的兼容成本比 dash **低得多**，而且它才是 Android 上真正会遇到的那个 shell。

---

## 三、实测：产物在 mksh 上到底差多少

拿真实 V6 产物（`demo_app.sh`）实测：

### 3.1 原始产物

```
$ mksh prod_test.sh
E: prod_test.sh[6]: declare: inaccessible or not found
E: prod_test.sh[6]: declare: inaccessible or not found
E: prod_test.sh[13]: syntax error: unexpected '(('
```

**只有 2 类错误**（对比 dash 的满屏 `Bad substitution`）：
- 行 6：`declare -a`（2 处）
- 行 13：`for ((_ki = 0; ...))`（C 风格循环）

### 3.2 改掉这两处之后

```
$ mksh prod_mksh2.sh
（无语法错误，rc=0）
```

**语法层全过。** 剩下的无输出**不是兼容性问题**，而是产物**自校验（`_hs`）发现文件被改** —— 这是反篡改特性在正常工作，不是 bug。

### 3.3 用产物内置旁路 `V7_EMBED=1` 复测

```
$ V7_EMBED=1 mksh prod_mksh3.sh
E: prod_mksh3.sh: syntax error: unexpected '('
```

**还剩 1 个错**：`<(…)` 进程替换。

### 3.4 为什么文本替换够不到它

解释器函数（`_kG` / `_Xg` / `_qp`）是产物**用 `eval` 展开出来的**，不在文件文本里。所以：

> **必须改【生成器模板】，产物才会干净。** 在产物文件上做文本替换是徒劳的。
>
> 我们前面用 `sed` 能修掉 `declare -a` 和 `for ((;;))`，是因为它们在**骨架文本**里；而 `<(…)` 在**`eval` 载荷**里。

---

## 四、但有个天大的好消息：产物本来就有"纯 POSIX 档"

产物的执行分派是三档（生成器 `1128–1132` 行）：

```bash
case "$_pp" in
    0) builtin eval "$_code" ;;              ← ✅ mksh 支持
    1) builtin source /dev/fd/9 9<<< "$_code" ;;  ← ✅ mksh 支持
    *) builtin source <(printf '%s' "$_code") ;;  ← ❌ mksh 不支持
esac
```

实测确认：

| 档位 | mksh |
|---|---|
| 档 0 `builtin eval` | ✅ **OK** |
| 档 1 `source /dev/fd/9 9<<<` | ✅ **OK** |
| 档 2 `source <(…)` | ❌ FAIL |

**`_pp=0` 是干净路径。** `_pp` 是运行期探测变量（trace 开关 / TracerPid / `LD_PRELOAD` / 耗时），**正常环境下通常就是 0 或 1**，档 2 是"探测到异常"时的保险路径。

> **所以 mksh 支持的真正障碍只有一处**：当 `_pp` 落到档 2 时的 `<(…)`。
>
> **最省力的修法**：**给档 2 换一个 POSIX 实现**（临时文件），而不是逐处改写。一处改动覆盖全部 4 个调用点。

---

## 五、修正后的兼容优先级

基于"用得多少 × 兼容成本"两个维度：

| 优先级 | shell | 理由 | 新增改动 |
|---|---|---|---|
| **P0** | **mksh** | **Android 系统 shell**，兼容成本最低，**是真正的靶子** | 见下方"精确改动清单" |
| **P1** | **bash** | 已完成（当前产物就是 bash 的） | — |
| **P2** | **dash** | Debian/Ubuntu 的 `/bin/sh`；服务器场景；**但兼容成本最高** | 真数组、`[[ ]]`、`<<<`、`${var//}` 全线 |
| **P3** | busybox ash | Alpine/Docker/嵌入式 | ≈ dash |
| **—** | **zsh** | **交互 shell，不是脚本 shell**。zsh 用户写脚本仍用 bash/POSIX。94% CI 用 bash，生产基础设施 zsh 使用率≈0 | 建议**不做** |
| **—** | ksh93 / fish | 极少数 | 不做 |

### mksh 的精确改动清单（已定位到生成器行号）

| # | 构造 | 生成器位置 | 在产物模板里？ | 改法 |
|---|---|---|---|---|
| 1 | `declare -a ${N_C}` | `2239` | ✅ 是 | → `${N_C}=` |
| 2 | `declare -a ${N_D}` | `2246` | ✅ 是 | → `${N_D}=` |
| 3 | `declare -a _K` | `2275` | ✅ 是 | → `_K=` |
| 4 | `declare -a _KS` | `2279` | ✅ 是 | → `_KS=` |
| 5 | `for ((_ki=…))` | `2333` / `2412` | ✅ 是 | → `while` + 手动递增 |
| 6 | `for ((_kj=…))` | `2335` / `2374` | ✅ 是 | → `while` + 手动递增 |
| 7 | `builtin source <(…)` | `1131/1160/1248/1276` | ❌ 在 `eval` 载荷里 | 改档 2 实现（一处覆盖 4 点） |
| 8 | `builtin type -t eval` | `1096` / `1214` | ❌ 同一载荷 | 加 mksh 分支 |

**重要区分**：生成器自身有 **23 处 `for ((;;))`**（`107/363/416/467/511/566/588/698/1723/1916/1948/2030/2055/2072/2085/2087/2149/2240/2247/2276/2280/2885/2887`）—— **这些不用改**，因为生成器继续在 bash 下运行。只有落在**产物模板**里的那 4 处（`2333/2335/2374/2412`）才需处理。

> 这正是第 1 层"生成端语法不用改"原则的又一次体现：**改产物，不改生成器。**

### 关于 zsh 的明确建议

市场数据支持"不做 zsh"：

- **JetBrains 2025**：自定义 shell 的开发者中，**62% 用 zsh 作交互 shell**，31% bash，7% fish。
- 但 **CNCF 2025**：**94% 的 CI/CD 流水线用 bash**；"zsh 在生产基础设施中的使用率基本为零"。
- zsh **不是**脚本 shell —— 它的定位是交互体验（Oh My Zsh 17 万星是交互插件生态，不是脚本需求）。

> **zsh 作为"交互 shell"的份额很高，但作为"脚本运行环境"的份额接近零。**
> 我们要兼容的是**脚本运行环境**。所以 **zsh 不做**，除非有用户明确提出。

---

## 六、需要澄清的一个概念

"用了哪个 shell"有**三种完全不同的含义**，混起来会得出错误结论：

| 含义 | bash | zsh | mksh | dash |
|---|---|---|---|---|
| **① 交互 shell**（人打命令用的） | 31% | **62%** | (Android 全部) | ~0% |
| **② 脚本 shebang**（`#!/bin/bash`） | **绝大多数** | ~0% | ~0% | 少量 |
| **③ 系统 `/bin/sh`** | — | — | **Android** | **Debian/Ubuntu** |

ShellVMP 关心的是 **② 和 ③**。在这个维度上：

- **bash** —— ② 的绝对主力
- **mksh** —— ③ 的 Android 答案
- **dash** —— ③ 的 Debian/Ubuntu 答案
- **zsh** —— ① 的冠军，但 ②③ 几乎为零

> 所以你的直觉"如果只有 bash、zsh、dash 用得多就先兼容这几个"**方向对，但名单要改**：
>
> **应该是 bash + mksh + dash**，**去掉 zsh、加上 mksh**。

---

## 七、建议的落地顺序

1. **先改生成器模板，做 mksh 兼容**（改动最小、收益最大、直击 Android）
   - `declare -a X` → `X=`（或按 shell 探测分派）
   - `for ((;;))` → `while` + 手动递增
   - 档 2 的 `<(…)` → 临时文件（一处改动覆盖 4 个点）
   - `builtin type -t` → 加 mksh 分支
2. **验证：产物在 mksh 下跑通第一个块** ← 新的止损点
3. **再评估 dash**（成本高，但服务器场景有价值）

> **止损点更新**：原定"dash-only PoC"改为 **"mksh-only PoC"**。
> 判断标准：**生成一个产物，在 mksh 下跑通第一个块**。

---

## 八、对 `GENERALIZATION_FEASIBILITY.md` 的修正

原文把 dash 当作首要目标（"档位 2：dash-only 子集 PoC"）。**该定位有误**，应修正为：

- **首选目标：mksh**（Android 系统 shell，成本最低）
- **次选目标：dash**（Debian 系 `/bin/sh`，成本最高）
- **不做：zsh**（脚本运行环境份额≈0）

同时原文第 2 层的构造清单（`[[ ]]` / `<<<` / `${var//}` / 真数组）是**针对 dash 的**；**对 mksh 而言这些全都不需要改**，mksh 的实际清单只有 4 项（见第五节表格）。
