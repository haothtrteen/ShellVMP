# 外部同类项目调研（Prior Art Review）

> 目的：评估社区已有的跨 shell 兼容 / 翻译工具，能否为 ShellVMP 的通用化路线（见 `GENERALIZATION_FEASIBILITY.md`）提供直接可用的东西。
>
> 结论先行：**没有一个项目能直接拿来用。** 但有两个项目在「思路」和「副产品」上对我们有真实价值，另有三个项目是**反面教材**——它们正好演示了我们不能走的路。
>
> 调研时间：2026-09-13。文中所有实测数据均为本机复现，非引用。

---

## 一、先明确我们到底需要什么

这是整份调研的判据。方向搞错，后面所有评价都是废话。

ShellVMP 的产品（V6 生成的混淆脚本 / V7 产物）是 **bash 语法 + bash 语义**。要让它跑在别的 shell 上，缺的是两样东西：

| 需求 | 内容 | 对应报告中的层 |
|---|---|---|
| **A. 语法翻译** | 把产物里的 `declare -a` / `[[ ]]` / `<<<` / `${var//}` / `_c[$_p]` 变成目标 shell 认识的写法 | **Layer 2** |
| **B. 语义模拟** | 让目标 shell 的 `$RANDOM`、`$-`、`$BASH_VERSINFO` 表现得像 bash | **Layer 3** |

**B 我们自己已经解决了**——`tools/interp_compat/` 里那个 dash patch，7 个种子逐位对齐 bash。所以外部项目对我们唯一还有意义的价值区间是 **A（Layer 2 语法）**。

判据就一句话：**能不能帮我们把 bash 语法搬到 POSIX sh / dash 上，而且是朝着「产物能在目标 shell 里无交互地跑完」这个目标，不是朝着「让人在 fish 里手打 bash 命令更顺手」。**

---

## 二、逐个评估

### 2.1 Babelfish —— 真实存在，但与我们的方向正交

| 项 | 内容 |
|---|---|
| 仓库 | `bouk/babelfish` |
| 语言 / 许可 | Go / MIT |
| 星标 | ~245 |
| 最近发布 | v1.2.0（2023-06） |
| 做的事 | bash 脚本 → **fish** 脚本翻译 |
| 实现 | 基于 `mvdan.cc/sh` 的 bash 解析器，走 AST 转换 |

**真实，也还活着，但用不上。** 三个原因：

1. **目标 shell 错了。** 它输出 fish，我们要 dash/POSIX sh。fish 是个语法完全另起炉灶的 shell，Babelfish 的价值恰恰在于处理 bash↔fish 这种巨大鸿沟；我们只需要把 bash 的少量扩展语法降到 POSIX，问题规模小一到两个数量级。
2. **它自己承认有覆盖盲区。** 明确不翻译 `$BASH_SOURCE`、也不处理全部算术表达式。而 `$BASH_SOURCE` 恰好是我们 V6 产物的入口守卫依赖（见下条）——它漏的正好是我们要的。
3. **交互场景 vs 无头执行。** Babelfish 面向「让用户能在 fish 里 source 一个 bash 脚本」，容忍部分模糊；我们的产物是自我解密后一口气跑完，任何一处语法不认就是硬崩。

**有没有能借的**：`mvdan.cc/sh` 这个库本身值得记一笔——它是目前最完整的纯 Go bash 语法树实现，如果哪天要做产物语法静态检查（比如给 `v6_lint.py` 加一条「产物是否只用了 POSIX 子集」的检查），它比手写正则靠谱。但那是工具链的辅助，不是通用化本身。

---

### 2.2 Rosetta-shell —— 唯一方向对上的，但成熟度是硬伤

| 项 | 内容 |
|---|---|
| 获取 | npm `@flashesofbrilliance/rosetta-shell` |
| 许可 | MIT |
| 版本 | **v0.1.0（draft）** |
| 宣称 | 同一份脚本在 bash 3.2.57 / bash 5.3 / zsh 5.9 / dash / ksh93 上**逐字节一致**地跑 |
| 组件 | `crossrun`（准入闸门）、`lint`（非可移植构造检查）、`doctor`、`selftest` |
| 构成 | 纯 shell + coreutils |

**这是我们列表里唯一一个「方向完全对上」的项目**，而且是唯一一个把 `dash` 明确写进目标清单的。它想解决的就是我们要解决的问题。

但必须泼冷水：

- **v0.1.0 draft**。这不是「版本号谦虚」，0.1.0 意味着接口和实现都还在大改，拿来做地基风险极高。
- **宣称的强度与证据不匹配。** 「五个 shell 逐字节一致」是个极强的断言，而它没有给出可复现的测试装置细节。
- **来源存疑。** 该包挂在「ARCS / flashesofbrilliance」这个名号下，README 里有「private priors」「animating spark stays private」这类表述。这不是正常的开源工程语言，读起来更像营销或某种概念宣传。**我无法验证它的实现是否真实存在。** 这种情况下不能把它的宣称当成事实。

**有没有能借的**：**思路，而非代码。** 它的两个设计动作值得我们照搬到自己的产物校验里：

1. **`lint` 只做「指出问题」不做「自动修」** —— 我们是混淆器不是转译器，这个定位一样。一个「扫描产物、列出所有非 POSIX 构造及行号」的检查器，成本极低、收益直接，正好补上 `v6_lint.py` 现在缺的那块。
2. **`crossrun` 准入闸门** —— 「产物必须先在 N 个 shell 上跑通才算发布」。这个 CI 思路我们可以直接抄：把产物丢给 bash / dash / busybox ash 各跑一遍比对输出。**这件事我们该做但还没做。**

---

### 2.3 Polysh —— 你看到的那条描述是错的

先说结论：**你贴的这条对不上任何一个真实项目。**

- `dantecatalfamo/polysh` —— **404，不存在**。
- `ffgenius/polysh` —— 真实存在，但 v0.0.1、6 天前发布、61 次下载、3.7K SLoC。做的是 **Unix ↔ PowerShell ↔ CMD** 翻译。**跨的是操作系统命令语义，不是 shell 语法。** 而且以它的年龄和体量，不具备任何参考价值。
- `innogames/polysh` —— 同名的另一个东西，是个**远程 shell 多路复用器**（前身 Group Shell/gsh），Python 写的。**和翻译毫无关系。**

**评价：不需要跟进。** 但这里有个更值得注意的事——你手上那份搜索结果里混进了一条**不存在的项目**（`dantecatalfamo/polysh`），并给 Polysh 配了一段与实际内容不符的描述。这说明那份列表是搜索摘要拼凑的，**不是逐条核实过的**。后面几条我也按这个标准全部重验了。

---

### 2.4 Reef —— 真实、工程质量高，但目标 shell 错了

| 项 | 内容 |
|---|---|
| 仓库 | `ZStud/reef` |
| 语言 / 许可 | Rust / MIT |
| 版本 | v0.3.0 |
| 做的事 | **给 fish 加 bash 兼容层** |
| 架构 | 三档：关键字包装（<0.1ms）→ AST 翻译（~0.4ms，用 conch-parser）→ bash 直通（~1.6ms） |
| 测试 | 498 单测，251/251 bash 构造覆盖 |
| 分发 | AUR / crates.io(`reef-shell`) / Homebrew / Nix / Fedora，约 1.2MB |

**这是列表里工程质量最高的一个**，值得学的地方不少：

- **它是唯一明确声明「只用 fish 的公开 API，不改 fish 内部」的。** 这件事的立场跟我们 `tools/interp_compat/` 的思路高度一致——我们那个 dash patch 也刻意做成了「单个 `.h` + 一处 `lookupvar` 挂载点」，而不是散弹式改 `var.c`。方向上互相印证。
- **三档分级策略**（快路径/翻译路径/直通兜底）是个好范式。它承认「不可能全翻译」，于是给退化路径留了口子。我们的功能剥离表本质上是同一个思路的静态版本。
- **251/251 构造覆盖 + 498 单测** 这个测试规模，是我们该对标的。

**但用不上，理由和 Babelfish 一样：目标是 fish，不是 POSIX sh。** 而且它是个交互式兼容层（让 fish 用户能打 bash 命令），不是「让一个脚本在别的 shell 里跑完」。

---

### 2.5 zsh 的 `emulate` 机制 —— 实测证明这条路走不通

这个必须实测，因为它是最容易让人误以为「现成可用」的东西。

**实测结果（本机 zsh 5.9）：**

```
$ zsh -c 'emulate bash -c "emulate"'      →  sh      ← 注意！
$ zsh -c 'emulate sh   -c "emulate"'      →  sh
$ zsh -c 'emulate ksh  -c "emulate"'      →  ksh
```

**`emulate bash` 不存在。** 传 `bash` 进去，zsh 按「首字母是 b 时当 Bourne sh 处理」的规则，静默落到 `sh` 模式，**并且 rc=0，不报任何错**。

zsh 真正的 emulate 模式只有四个：`zsh` / `sh` / `ksh` / `csh`。官方手册原文：*"If the argument is not one of the shells listed above, zsh will be used as a default"*。

再说更关键的——**emulate 改的是 options，不是解析器**：

```
$ zsh -c 'emulate sh -c "a=(1 2 3); echo \${a[0]}"'
1                    ← 跑通了，但那是因为 zsh 自己的语法

$ dash -c 'a=(1 2 3); echo ${a[0]}'
dash: 1: Syntax error: "(" unexpected     ← dash 直接语法错
```

zsh 在 `sh` 模式下**仍然用 zsh 的语法解析**，`a=(1 2 3)` 能过是因为 zsh 认数组字面量，跟 sh 模式无关。手册把这点写得很直白：*"emulate changes options, not parser syntax"*、*"To run an actual sh script, invoke sh as a separate process."*

**顺带一个实测副产品**（对 Layer 3 有意义）：

```
zsh  6424 8744 6566       ← zsh 原生
zsh(sh)  10914 24205 14919    ← sh 模式，$RANDOM 仍在，值不同
zsh(ksh) 23591 11792 24701
bash     25554 17240 30906    ← 参照
```

**emulate 模式完全不改变 `$RANDOM` 的取值序列。** 也就是说 zsh 下 `$RANDOM` 有三个不同的失真值，一个都不是 bash 的。这反过来印证了我们 `INTERP_COMPAT_LAYER.md` 里的判断：**语义层不能靠宿主 shell 的开关调出来，只能自己 hook 进去。**

> **这是本次调研最有价值的一条负面结论**：任何「用宿主 shell 的兼容开关来获得 bash 语义」的方案，都是在错的层面上使劲。这条路堵死，可以不再重复讨论。

---

### 2.5b libdash —— 名字对得上，能力对不上

> **勘误：「社区有个 libdash 补丁，所以 dash 应该不成问题了」——这个理解是错的。**

| 项 | 内容 |
|---|---|
| 仓库 | `binpash/libdash` |
| 许可 / 语言 | MIT（继承 dash 的 BSD 系）/ C |
| 星标 | ~48 |
| 最近更新 | 2026-04（在修 wheel 打包失败） |
| 做的事 | **把 dash fork 成可链接库**，暴露扩展接口 |
| 主要用途 | **解析** shell 脚本 → Python / OCaml 绑定 + `shell_to_json` / `json_to_shell` |
| 基于 | dash 0.5.12（`configure.ac` 有 "Merge v0.5.12 from upstream"） |

**它是"让程序能读 shell 脚本"，不是"让程序能跑 bash 语法"。** 两者差别是根本性的：

- libdash 提供的是 `parsecmd_safe`（`parser.c`）这类**解析**接口，配套 `nodes.h` 里的 AST 定义。
- 它**不含任何运行时能力增强**。用 libdash 去跑我们的产物，`declare: not found` 照样报 —— 因为它就是 dash，只是被编译成了 `.so`。
- README 自己写得很清楚：*"The primary use of libdash is to parse shell scripts, but it could be used for more."* —— "could be used for more" 是可能性措辞，不是既有能力。

**对我们唯一可能的用处**：如果哪天要给 `v6_lint.py` 加一条"产物是否只用 POSIX 子集"的静态检查，libdash 的解析器比正则靠谱（和 2.1 节提到的 `mvdan.cc/sh` 是同类工具，一个面向 POSIX sh 一个面向 bash）。

**但它解决不了通用化问题。** 而且这个坑值得单独记一笔：**名字里有 dash、功能是"shell 作为库"，看起来正好是我们要的，实际方向是"读"不是"跑"。** 调研中最容易踩的就是这种"名字对得上、能力对不上"的项目。

### 2.6 zsh 上游 C 补丁（`Src/subst.c`）—— 不存在，纯属虚构

**没有这个东西。** zsh 上游没有维护任何「bash 兼容补丁集」，`Src/subst.c` 是 zsh 自己的参数替换实现，和 bash 兼容无关。搜索里出现的只是讲 zsh 内部实现的材料，被拼成了「上游补丁」这个说法。

即使真有人做这种事，也撞在我们报告里已经写明的墙上：**bash 的东西在 `execute_cmd.c` / `subst.c` 里，zsh 的在 `Src/*.c` 里，是两套完全不同的实现。** 你没法只补一个文件就让 zsh 获得 bash 语义——这需要把 bash 的整条执行链搬过去。这正是我们选择「提取 bash 单个语义点做 hook」而不是「给别的 shell 打 bash 补丁」的原因。

---

### 2.7 Zshrs —— 宣称最强，可信度最低

| 项 | 内容 |
|---|---|
| 仓库 | `MenkeTechnologies/zshrs`（crates.io 上同时以 `zsh` 名字发布） |
| 语言 / 许可 | Rust / MIT |
| 创建时间 | **2026-04-25**（约 4.6 个月前） |
| 版本数 | **110 个版本**，全部落在 0.12.x |
| 发布频率 | 平均 **0.78 个版本/天**，出现过单日连发 9 个版本 |
| 总下载 | 8,264 次 |
| 代码量声明 | 从 190k 行 → 398K SLoC → 842k 行 → 915k 行，**同一项目在同一时间窗口内数字自相矛盾** |
| 与我们的相关宣称 | 8 种 Bourne 方言 drop-in，包含 `--dash` 和 `--bash` |

它宣称的东西**正好是我们最想要的**：一个能 `--dash` / `--bash` 跑的 shell。如果属实，我们的 Layer 2 就归零了。

**但我认为不能信，理由如下：**

1. **增长曲线物理上不可能。** 4.6 个月从 0 到 915k 行 Rust，且期间持续以每天近一个版本的速度发版。这个体量相当于把 zsh 整个用 Rust 重写一遍还有余（zsh 本体约 15 万行 C）。人类团队做不到，AI 生成代码也做不到「915k 行且经过 parity 验证」。
2. **数字自相矛盾。** 同一批文档里代码量在 190k / 398K / 842k / 915k 之间跳，`src/extensions/` 的文件数在 README 和 commit 记录里对不上。真实工程不会这样。
3. **宣称的验证强度与实现方式不匹配。** 它说 8 种方言「each verified against its real reference shell by the parity matrix」，但**差分模糊测试明确只覆盖 zsh 模式**（原文："zsh mode **is additionally** cross-checked"）。也就是说 bash/dash 模式**没有**做模糊测试。而恰恰是 bash/dash 模式对我们才有意义。
4. **README 里没有任何一句声称「可无修改运行 bash / POSIX sh 脚本」。** 注意它很谨慎地把 `drop-in` 这个词**只用在 zsh 上**（"A drop-in zsh replacement"）。真能跑 bash 脚本的话，这是最大的卖点，不可能不提。
5. 自我宣传语言（`[THE MENKE-TECH REVOLUTIONARY FLYWHEEL]`、`[PATENT PENDING]`、`The most powerful shell ever created`）超出正常工程文档的边界。

**评价：不跟进。** 它是本次调研里**风险最高、最可能浪费我们时间**的选项。一个 4.6 个月、每天发版、代码量数字自相矛盾、对目标能力刻意不做出明确承诺的项目，不能作为通用化路线的基础。

---

### 2.8 Bash-To-ZSH-Initialization —— 无关

`MushuDG/Bash-To-ZSH-Initialization`。真实存在，MIT。但它是**一个环境安装脚本**：装 zsh、Oh My Zsh、Powerlevel10k、一堆插件（fzf / bat / lsd / thefuck / zsh-autosuggestions…），然后把模板 `.zshrc` 拷到用户家目录。

**和 shell 兼容没有任何关系。** 它只是「帮你把开发机换成 zsh」的装机脚本。**评价：无关，不需要看。**

---

### 2.9 bash2zsh-complete —— 已废弃，且作者说明了为什么

`curusarn/bash2zsh-complete`。Go，**2 颗星**，最后更新 **2018-05**，作者自己标注 DEPRECATED，理由：*"I have found out that it's nearly impossible to support all bash completion helper functions."*

**这正好是我们该记住的一条教训。** 它做的是 bash 补全 → zsh 补全的翻译，失败原因是「bash 补全的辅助函数太多，无法穷尽支持」。

对我们有直接映射：**Layer 2 语法翻译同样面临「构造太多、无法穷尽」的风险。** 这里的启示不是「所以别做了」，而是「所以要做成**可枚举 + 可检测**的：先穷举出产物实际用到的那个**有限子集**（`declare -a` / `[[ ]]` / `<<<` / `${var//}` / 数组下标），再为这个闭集做翻译，而不是做通用 bash→sh 转译器。」

这恰好支撑我们功能剥离表的思路：**我们不翻译 bash，我们只降级我们自己产物里出现的那些构造。**

---

### 2.10 promptconv —— 无关

`promptconv`，crates.io，MIT，284 SLoC，v0.1.3，下载量 1,690。功能：把 bash 的 `PS1` 转成 zsh 的 `PROMPT`（`\u`→`%n`、`\h`→`%m`……）。

**纯提示符字符串替换，284 行。** 和我们的需求完全无关。**评价：无关。**

---

## 三、总表

| 项目 | 真实？ | 与我们的方向 | 可用性 | 处置 |
|---|---|---|---|---|
| **Rosetta-shell** | 是，但 v0.1.0 draft、来源存疑 | **完全对上**（含 dash 目标） | 代码不可信，**思路可借** | **借两个设计动作**（见下） |
| **Reef** | 是，工程质量高 | 同向但目标是 fish | 代码不可用，**方法论可借** | **对标其测试规模与「不改宿主内核」立场** |
| **Babelfish** | 是 | 同向但目标是 fish | 不可用 | 记录 `mvdan.cc/sh` 备查 |
| **zsh `emulate`** | 是（机制真实） | 看似可用 | **实测证伪** | **堵死这条路，不再讨论** |
| **libdash** | 是 | 名字对得上、能力对不上（解析≠运行） | **解决不了通用化** | 或可用于 lint，不能用于跑 |
| **Zshrs** | 是但**不可信** | 宣称完全对上 | 高风险 | **不跟进** |
| **zsh 上游 C 补丁** | **否，不存在** | — | — | 无需处置 |
| **Polysh** | **描述错误**（链接 404） | — | — | 无需处置 |
| **Bash-To-ZSH-Init** | 是 | 无关 | 无关 | 无需处置 |
| **bash2zsh-complete** | 是，已废弃 | 同类失败案例 | 反面教材 | **吸取教训**（见 2.9） |
| **promptconv** | 是 | 无关 | 无关 | 无需处置 |

---

## 四、结论：能拿走的只有三件事

**没有一行代码可以拿来直接用。** 但有三个东西值得吸收：

### 1. 一个反面教训（最重要）

`emulate` / 上游补丁这条路，我们在**实测层面**确认了它不通。过去讨论里可能还存在「是不是给 zsh 打个补丁就行」的幻想，现在有数据了：

> **宿主 shell 的兼容开关只在 options 层起作用，永远碰不到语义层。** `emulate bash` 不存在还会静默退化成 sh；`emulate sh` 不改变 `$RANDOM`；zsh 在 sh 模式下照样用 zsh 语法解析。

这跟我们在 `INTERP_COMPAT_LAYER.md` 里实测出的结论是同一条：语义只能靠**自己 hook 进目标 shell 的实现**拿到（我们那个 dash patch 就是正确做法的样板）。

### 2. 两个应该照搬的设计动作

**`crossrun` 式准入闸门** —— 把「产物必须在多 shell 上跑通」变成硬性流程。现在我们的产物只在 bash 上验证过；应该加一个脚本，把产物丢给 bash / dash / busybox ash 各跑一遍并对输出。这件事成本极低，能立刻告诉我们「当前产物在 dash 上到底挂在哪一行」。

**`lint` 式静态检查** —— 扫描产物、列出所有非 POSIX 构造及行号，只报告不自动修。这正好补齐 `v6_lint.py` 缺的那块，并且和 2.9 的教训合起来形成正确路线：**不做通用转译器，先穷举出产物实际用到的那个有限构造集。**

### 3. 一个方向性确认

Reef 明确声明「只用 fish 的公开 API，不改 fish 内部」，我们的 dash patch 也是「一个头文件 + 一个挂载点」。**两个独立项目得出同一个工程立场，说明我们 `tools/interp_compat/` 的做法是对的**，可以放心沿着这条路继续扩（`$SRANDOM` / `$EPOCHREALTIME` / `$BASH_VERSINFO`）。

---

## 五、对通用化路线的影响

**没有变化，但信心更强了。** `GENERALIZATION_FEASIBILITY.md` 里的判断不变：

- Layer 3（语义）—— 已解决，`tools/interp_compat/` 实证。
- Layer 2（语法）—— 仍是唯一的真障碍，且**外部没有现成方案可用**，这条路必须我们自己走完。

这份调研的增量价值在于：**排除了四条歧路。** 如果哪天又开始讨论「是不是可以用 zsh/wshrs/emulate 省掉 Layer 2 的工作」，请回来看第 2.5 和 2.7 节——答案是有实测和数据支撑的「不行」。

下一步该做的，是第 4.2 节那两个动作：**先写一个产物跨 shell 跑通检查器**。它不需要等 Layer 2 完成，而且能立刻给出「当前产物在 dash 上具体挂在哪」的精确位置，让 Layer 2 的工作量从估计变成可测量。
