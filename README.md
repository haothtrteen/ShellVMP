# ShellVMP

**把 shell 脚本变成自保护产物。** 两层独立可用的保护：

- **V6** — 纯 shell 实现的脚本混淆器：分块加密 + 执行状态绑链 + 跳跃密钥链 + 批级自修改。零外部依赖（`aes` 模式需 openssl，`builtin` 模式纯 shell/awk）。
- **V7** — ELF 封装层：反调试 + 反内存读取 + 流式解密直喂解释器，磁盘上永不存在完整明文。
- **V7-ISA** — 解释器魔改层（PoC）：把命令名/关键字/变量名令牌化，让产物在磁盘上只是一串随机令牌。

> 目标不是"藏得更深"，而是**改变攻击面**：让磁盘上不存在明文，让运行期的明文窗口尽可能短且有界，让关键逻辑变成攻击者无法静态分析的虚拟指令。

---

## 目录

- [它是怎么工作的](#它是怎么工作的)
- [三分钟上手](#三分钟上手)
- [为什么 shell 是最难保护的语言](#为什么-shell-是最难保护的语言)
- [诚实的安全边界](#诚实的安全边界)
- [项目结构](#项目结构)
- [版本演进与心路历程](docs/JOURNEY.md)
- [文档索引](#文档索引)
- [状态与路线图](#状态与路线图)

---

## 它是怎么工作的

```
┌─────────────────────────────────────────────────────────────┐
│  你的脚本 (app.sh)  ── 明文，谁都看得懂                      │
└────────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   V6  混淆器         │  纯 shell 实现
              │  ─────────────────   │
              │  分块 → 加密 → 绑链   │  · 每块密文独立
              │  + 诱饵 + 垃圾块     │  · 执行状态($?/$_/路径)掺入密钥链
              └──────────┬──────────┘  · 跳跃引用第 N-7 块 → 必须从头跑
                         │                · 批级自修改（解密后重加密）
                         ▼
                  骨架 (加密的 shell 脚本)
                         │
              ┌──────────▼──────────┐
              │   V7  ELF 封装       │  C 实现
              │  ─────────────────   │
              │  scrypt-like KDF     │  · 载荷追加在 ELF 尾部
              │  Encrypt-then-MAC    │  · 父进程分块解密 → pipe → 子进程
              │  pipe 流式执行        │  · 明文即写即抹，不进磁盘
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │   V7-ISA 令牌化      │  魔改解释器
              │  ─────────────────   │
              │  命令名/关键字/变量   │  · L1 builtin / L2 external
              │  → 随机别名          │  · L3 关键字 / L4 变量+路径
              └──────────┬──────────┘  · L6 字符串字面量（密文驻留）
                         ▼
                    最终产物 (ELF)
              strings 出来的只有随机令牌
```

## 三分钟上手

### 最小用法：V6 混淆

```bash
git clone https://github.com/<you>/ShellVMP.git
cd ShellVMP

# 混淆一个脚本
ANDROID_GATE=0 bash v6/shell_script_obfuscator_v6.sh examples/demo_app.sh demo.protected.sh

# 跑它
bash demo.protected.sh
```

`ANDROID_GATE=0` 用于在非安卓环境测试；默认开启安卓环境门控（非安卓直接静默拒绝）。

### 常用开关

```bash
# 强混淆：加垃圾块 + 诱饵
JUNK_LEVEL=3 DECOY_LEVEL=2 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# 密钥分离：产物需要口令才能跑，主密钥不写入产物
PASSKEY_MODE=1 PASSKEY_COUNT=3 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# 零 openssl 依赖（极简环境）
CRYPTO_MODE=builtin \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh
```

### 混淆前体检（推荐）

```bash
python3 tools/v6_lint.py your_script.sh          # 静态检查兼容性
python3 tools/v6_lint.py your_script.sh --strict # 有问题即 exit 1（可挂 CI）
```

> **为什么必须先体检**：宿主的 `errexit`、`set -x`、改 `PS4`、重定义 builtin 都会**命中产物的反调试指纹** → 主密钥污染 → **静默 exit、零提示**。`v6_lint.py` 会在混淆前把这些揪出来。

### 署名 / 个人化

三种方式，**安全性递增**：

```bash
# ① 命名空间前缀（推荐）：产物里是 yourname_k9x2
#    每次构建后缀都不同 → 攻击者无法写固定规则
V6_NS=yourname ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# ② 抗 AI 声明（嵌入明文头部，正常用户不可见）
AI_GUARD=1 AI_GUARD_OWNER="Your Name" ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh
```

> **为什么不建议把标识做成完全固定的变量名**：随机变量名存在的**唯一理由**就是"不固定"。
> 固定 = 给攻击者一个**永久锚点**——一条 `grep` 就能定位密钥链的每一环，并可用**跨样本比对**反推结构。
> `V6_NS` 的"前缀 + per-build 随机后缀"是**署名感与安全性的两全方案**。

### 运行期排障

```bash
bash tools/v6_pm_diag.sh    # 逐条列出 6 项会触发密钥污染的条件
```

---

## 选哪条线？用哪个 shell 打包？

**你的脚本可以用 bash 或 mksh 的魔改解释器打包保护。** 按下面三步走：
**① 读这张表选线 → ② 进对应目录 → ③ 自己构建。**

### 三条产物线

| 线 | 命令入口 | 产物 | 令牌化 | 宿主依赖 | 状态 |
|---|---|---|---|---|---|
| **纯脚本线**（最快上手） | `v6/shell_script_obfuscator_v6.sh` | 混淆后的 `.sh` | ❌ | 宿主有 bash **或** mksh 即可 | ✅ 稳定 |
| **bash 线**（最强） | `v7/v7_build.sh` | 改过的 bash 二进制 | ✅ L1-L6 | 自带解释器，不依赖宿主 | ✅ 生产可用 |
| **mksh 线** | `v7/v7_build.sh`（`V7_MODE=mksh`） | 改过的 mksh 二进制 | ✅ L1-L6 | 自带解释器，不依赖宿主 | ⚠️ **已可打包**（C1/C2/C3 已通）；内层口令档待修 |

### 怎么选

| 你的情况 | 选 |
|---|---|
| 只想快速挡一下源码泄漏 | **纯脚本线**（零构建，一条命令） |
| 要最强保护、能接受自带几 MB 解释器 | **bash 线** |
| 目标是 Android 真机 / 想省掉内嵌 bash 的体积 | **mksh 线** —— 约 3 万行源码（bash 约 150 万行），产物小得多 |
| 不确定 | 先用纯脚本线跑通，再上 bash 线 |

**mksh 线一条命令**（不需要预先构建 mksh，会从源码现场构建改版解释器）：

```bash
V7_MODE=mksh V7_MKSH_SRC=./mksh-src V7_OUTER_PASS='外层口令' \
  bash v7/v7_build.sh your_script.sh app.mksh

# 运行 —— ★ 必须带一个 argv 文件参数（惯例 /dev/null），见下方提示
V7_SELF=1 V7_PASS='外层口令' V7_ISA_TABLE=app.mksh.isa.bin ./app.mksh /dev/null
```

> **★ 运行契约**：产物必须带一个 argv 文件参数。不带时 mksh 进 stdin 模式
> （FSTDIN），解密分支根本不会被走到 —— 无内层口令档表现为**静默 rc=0、零输出**，
> 这是契约不是缺陷。同理，产物是 ELF，要 `./app.mksh` **直接执行**，
> **不要**写成 `mksh app.mksh`（那样 `/proc/self/exe` 指向解释器而非产物）。
> 详见 [`docs/BUILD_MKSH.md`](docs/BUILD_MKSH.md) §六.3。
>
> **⚠️ 暂不要传 `V7_PASS`（内层口令）**：那会走到 V6 骨架的 `read -rs -p 'Key: '`，
> 而 `-p` 在 mksh 里是"从 coprocess 读" ⇒ 产物 rc=1 失败。
> **外层口令 `V7_OUTER_PASS` / 离线分发模式不受影响**，正常可用。
>
> **尚未做的**：内层口令档修复、跨架构（aarch64）实测、`V7_WRAP` 接入（属 C4）。

### 自己构建各 shell 的 C 层补丁

| 线 | 构建指南 |
|---|---|
| **bash 线**（环境要求 / 三步构建 / 验证 / 排障） | [`docs/BUILD.md`](docs/BUILD.md) |
| **mksh 线**（源码获取 / 锚点插桩 / 编译 / 验证 / 自包含性检查） | [`docs/BUILD_MKSH.md`](docs/BUILD_MKSH.md) |
| 各解释器插桩点怎么挂、两条线的能力对照 | [`docs/BUILD_PER_SHELL.md`](docs/BUILD_PER_SHELL.md) |

> **验收标准**：每个 shell 的构建目录必须能**独立**走通"下载 → 构建 → 得到产物"。
> 自包含性审计结论见 [`docs/BUILD_MKSH.md`](docs/BUILD_MKSH.md) §八。

---

## 为什么 shell 是最难保护的语言

| 难点 | 说明 |
|---|---|
| **输入即源码** | 解释器必须能读懂代码 → 攻击者也能。没有 AOT 这道天然屏障 |
| **无编译期** | 不能像 C 那样"编译时算好"，所有密钥派生都发生在运行期 |
| **进程即边界** | 每一次 `$( )` / `\|` 都可能是密钥或明文泄漏点（`/proc/pid/cmdline`） |
| **字符串即一切** | 变量、函数、命令都是字符串，没有类型系统帮你"固化"语义 |
| **内建被特权** | 攻击者重定义 `eval` / `type` 就能劫持你的整个执行链 |

**反过来看，这也带来了独特优势**：shell 没有二进制，所以**每一行都可以是密文**——粒度优势是编译型语言不具备的。

## 诚实的安全边界

> **这一节是本项目最重要的部分。任何声称"无法破解"的脚本保护都是骗局。**

### 挡得住什么

- ✅ **随手看源码**、`cat` 一下就知道逻辑
- ✅ **静态批量扒取**（爬虫/批量去混淆）
- ✅ **明文落盘分析**（磁盘上不存在完整明文）
- ✅ **非 root 的内存读取**（`PR_SET_DUMPABLE=0` + seccomp-BPF，唯一确定性手段）
- ✅ **调试器/注入**（TracerPid / frida 痕迹扫描 / `LD_PRELOAD`）

### 挡不住什么

| 攻击者能力 | 现实 |
|---|---|
| **root 权限** | 能读 `/proc/pid/mem`（`PROT_NONE` 拦不住它——走 `get_user_pages`，不检查页表权限）。**实测打脸过** |
| **足够长的运行期观察** | 解释器最终要吃明文。唯一能做的是**缩短窗口 + 稀释信噪比** |
| **耐心的人工逆向** | 任何混淆都是"提高成本"，不是"消除可能"。目标是"让逆向成本高于收益" |
| **有 AI 辅助** | 抗 AI 声明（`AI_GUARD=1`）能挡住一部分，但**不构成技术防线** |

### 一句话

> **整体强度 ≈ 最弱组件，且所有组件共享信任根（dump 一次全暴露）。**
> 我们不承诺"无法破解"，只承诺"**逆向成本 > 你的脚本价值**"。

详见 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)。

---

## 项目结构

```
ShellVMP/
├── v6/
│   └── shell_script_obfuscator_v6.sh   # V6 混淆器（纯 shell，~2900 行）
├── v7/
│   ├── elfrun.c                        # ELF 封装加载器
│   ├── crypto_core.h                   # 密码学核心（SHA-256/HMAC/流密码/scrypt-like）
│   ├── v7_wipe.h                       # 内存擦除
│   ├── v7_build.sh                     # V7 统一构建入口（V7_MODE=bash|mksh|elf）
│   ├── v7_wrap.sh                      # V7 一键封装
│   ├── blobgen.c                       # 载荷生成
│   ├── bash_poc/                       # bash 线 + 两线共享工具
│   │   ├── isa_hook.c / .py            # 四层令牌化表：C 端翻译 + Python 端插桩
│   │   ├── anchors.py                  # ★ 锚点表（bash-5.2 / mksh-R59c）
│   │   ├── v7_builtin_takeover.c       # builtin 接管（L6 出口）
│   │   ├── zread.c.v7poc               # bash 线骨架注入（读取层劫持）
│   │   ├── v7_embed.py                 # 加密嵌入（载荷无关，两线共用）
│   │   ├── crypto_isa.h                # ISA 层密码学
│   │   ├── xtrace_kill.py              # 调试通道剥离
│   │   ├── elf_anti_disasm.py          # 抗反汇编后处理
│   │   └── ...
│   └── mksh_poc/                       # mksh 线（与 bash_poc/ 平级）
│       ├── v7mksh_build.sh             # mksh 线一键构建（先建解释器 → 再改写脚本）
│       ├── v7_builtin_takeover_mksh.c  # builtin 接管（L6 出口）
│       ├── v7_shf_inject_mksh.c        # shf_open() 骨架注入（打开层劫持）
│       └── v7core_mksh.c               # v7c_* 包装层（8 个非 static 符号）
├── tools/
│   ├── v6_lint.py                      # V6 混淆前兼容性检查（含 41 项自测）
│   ├── v6_pm_diag.sh                   # 运行期指纹诊断
│   ├── v7_isa.py                       # 四层表生成器 + 校验器
│   ├── isa_itest.py                    # ISA 端到端集成测试
│   ├── vmp_apply.py                    # VMPacker 自动化对接（逐函数验证闭环）
│   ├── vmp_targets.py                  # 无符号表产物里定位保护函数
│   └── argv_leak_scan.py               # 参数泄漏扫描
├── examples/                           # 示例脚本
├── tests/                              # 回归测试
└── docs/                               # 文档
    ├── JOURNEY.md                      # ★ v1→v6 心路历程
    ├── ARCHITECTURE.md                 # 架构与设计原理
    ├── THREAT_MODEL.md                 # 威胁模型与能力承诺
    └── ...
```

## 文档索引

| 想了解 | 读 |
|---|---|
| **这套东西是怎么一路试错做出来的** | **[`docs/JOURNEY.md`](docs/JOURNEY.md)** |
| 两层架构怎么协作、密码学怎么设计 | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| 到底防得住谁、防不住谁 | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| V6 的分块/绑链/跳跃密钥链算法 | [`docs/V6_DESIGN.md`](docs/V6_DESIGN.md) |
| V7 的流式解密与反调试 | [`docs/V7_DESIGN.md`](docs/V7_DESIGN.md) |
| 令牌化（V7-ISA）四层表 | [`docs/TOKENIZATION.md`](docs/TOKENIZATION.md) |
| 构建、测试、排障（bash 线） | [`docs/BUILD.md`](docs/BUILD.md) |
| **构建 mksh 线（魔改解释器）** | **[`docs/BUILD_MKSH.md`](docs/BUILD_MKSH.md)** |
| C 层补丁怎么挂到不同解释器 | [`docs/BUILD_PER_SHELL.md`](docs/BUILD_PER_SHELL.md) |
| **踩过的坑（按症状索引）** | **[`docs/PITFALLS.md`](docs/PITFALLS.md)** |
| VMP 对接与收益边界 | [`docs/VMP_NOTES.md`](docs/VMP_NOTES.md) |
| 哪些开源、哪些保留、为什么 | [`docs/OPEN_SOURCE_SCOPE.md`](docs/OPEN_SOURCE_SCOPE.md) |
| 路线图与已知限制 | [`docs/ROADMAP.md`](docs/ROADMAP.md) |

### 最值得读的三篇

如果你只有十分钟，按这个顺序：

1. **[`docs/JOURNEY.md`](docs/JOURNEY.md)** —— v0 到 v6 的完整试错过程。每一节都是"我以为这样就行了 → 实测被打脸 → 改成这样"。**失败的方式比成功的方式更有信息量。**
2. **[`docs/PITFALLS.md`](docs/PITFALLS.md)** —— 按症状索引的踩坑清单，含"我以为但实测打脸"的六条。
3. **[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)** —— 诚实的能力边界。**任何声称"无法破解"的脚本保护都是骗局。**

## 状态与路线图

| 层 | 状态 | 说明 |
|---|---|---|
| **V6 混淆器** | ✅ 稳定 | 双架构（x86_64 / aarch64）验证；32 项集成测试 |
| **V7 ELF 封装** | ✅ 稳定 | 反调试 / 流式解密 / 内存擦除；退出码分类 |
| **V7-ISA 令牌化** | ✅ 可用 | **bash 线 L1-L4 + L6 生产可用**；**mksh 线 L1-L4 + L6 已通，且已可一条命令打包**（C1/C2/C3，提交 `babf886`）。未做：跨架构实测、`V7_WRAP` 接入（C4）。见 [`BUILD_MKSH.md`](docs/BUILD_MKSH.md) |
| **VMP 对接** | 🧪 工具就绪 | `vmp_apply.py` 逐函数验证闭环；受限于 NEON 约束，**收益有限**（见文档） |
| **Python / Lua 移植** | 📋 方法论已备 | 机制可移植性分析完成，待实现 |

### 已知限制

- **V7-ISA 绑定具体解释器版本**（解释器魔改层的插桩点依赖具体源码结构）。bash-5.2 与 mksh-R59c 两组锚点已实装；任一 shell 主版本升级时需重新校准插桩点——这层是"可移植性最弱、但价值最高"的部分（换版本会**响亮失败**，不静默错位）。
- **VMP 保护收益有限**：本架构最终把脚本交给 `eval`，VMP 只能保护"壳"。详见 [`docs/VMP_NOTES.md`](docs/VMP_NOTES.md)。
- **真机产物**未随仓库分发（体积 + 隐私）。
- **产物运行期不再锁定 bash（mksh 已完成）**。历史认知"跨 shell 做不到"的前提是**密钥链把解释器语义烧进了密文**。实测证明：把产物里所有非 POSIX 构造**无条件改写成 POSIX 等价物**就能同时覆盖 bash 与 mksh —— **产物在 mksh 下与 bash 输出逐字节一致**（8 轮独立生成 8/8 通过）。
  - **为什么是 mksh**：Android 4.0+ 的 `/system/bin/sh` 就是 **mksh**（不是 dash）。这才是真靶子。
  - **验收门禁**：`sh tools/sh_compat_check.sh <产物.sh> [原始脚本.sh]`
  - 改动清单与"计划外四大真凶"（`$RANDOM` / `$-` / `$_` / `read -a`）见 [`docs/SHELL_TARGETS.md`](docs/SHELL_TARGETS.md) 第九节。
- **dash 解释器路线冻结**：V6 产物跑 dash 需要标量仿真层（dash 完全没有数组）。但注意定位：这只影响"产物必须由 dash 解释"的场景——dash 来源的脚本本身是 POSIX 子集，直接进 bash 链即可；V7 线产物自带解释器，不受影响。
- **zsh 解释器不做；zsh 来源脚本走收敛审计**：zsh 作为解释器不适配（交互 shell，生产脚本环境份额 ≈0，决策见 [`docs/BACKLOG.md`](docs/BACKLOG.md)）。但 zsh 来源的脚本可以通过**语义审计降级**进 bash 链保护——重点审计项：**数组 1-based（bash 0-based）**、`$arr` 展开语义、默认无 word splitting。跨方言收敛审计器（bash/mksh/dash/zsh → bash 子集，**审计报告 + 受限降级，拒绝静默自动翻译**）是当前计划中的工具。
- **解释器兼容层（已被取代，保留作历史）**：`tools/interp_compat/` 原方案是给 dash 打 C 补丁装 bash 兼容 `$RANDOM`。现已被**纯算术内联 PRNG**（`_rn()`，三 shell 逐位一致、零依赖）取代 —— 无需改任何 shell 源码。详见 [`docs/INTERP_COMPAT_LAYER.md`](docs/INTERP_COMPAT_LAYER.md) 顶部的状态更新。
- **跨 shell 的外部方案已核查完毕**：社区同类工具（Babelfish / Reef / Rosetta-shell / Zshrs / zsh `emulate` / `libdash` 等）**均无法直接复用**，其中五条常见思路已被实测或事实排除。详见 [`docs/PRIOR_ART_REVIEW.md`](docs/PRIOR_ART_REVIEW.md)。

### 兼容性怎么读（先分清三个不同的问题）

"支持哪些 shell"不是一个问题，是**三个独立的问题**。混在一起说，就会得出错误的预期：

| 问题 | 现状 |
|---|---|
| ① **源脚本是什么方言**（你拿什么进来保护） | bash ✅ 原生；POSIX / dash ✅ 子集直接收；mksh ⚠️ 接近（4 个构造 + 4 处语义分叉，清单见 [`docs/SHELL_TARGETS.md`](docs/SHELL_TARGETS.md)）；zsh ⚠️ 需语义审计降级（**数组 1-based**、word splitting 等，审计器制作中） |
| ② **产物由谁执行**（目标环境靠哪个解释器跑） | **V7 线：产物自带内嵌静态 bash（`V7_SELF=1`）→ 不依赖目标环境装了什么 shell**，任何能跑 ELF 的 Linux / Android 都行。V6 线：靠环境的 shell，见下方实测矩阵 |
| ③ **要不要 C 层插桩**（V7-ISA 魔改解释器） | 补丁已随本仓库分发、构建脚本齐全，**对使用者透明**。bash-5.2 生产链 ✅（[`BUILD.md`](docs/BUILD.md)）；**mksh-R59c 四层插桩 + 三件套 + L6 全通，已可打包**（[`BUILD_MKSH.md`](docs/BUILD_MKSH.md)）；其余冻结（自动发现工具链抽为子仓库 `sh-hook/`） |

> **一句话**：如果你接受默认形态——产物**内嵌解释器分发**——那么 bash / POSIX / dash / mksh / zsh 来源的脚本（经收敛审计）都能保护，产物跑在**任何** Linux / Android 上，**目标环境装什么 shell 与你无关**。
> 只有当你要求产物必须用目标环境的系统 shell 执行（例如 Android `/system/bin/mksh`，省去内嵌解释器的几 MB 体积）时，才需要关心下面这张矩阵。

### V6 产物 × 环境 shell（实测矩阵）

| shell | V6 产物 | 说明 |
|---|---|---|
| **bash** | ✅ 完整 | 原生目标，输出与明文逐字节一致 |
| **mksh** | ✅ 完整 | 与 bash 输出逐字节一致（8 轮独立生成 8/8 通过），**零 C 补丁**——纯生成器侧改写 |
| dash | ❌ | V6 产物用数组下标，dash 直接报错；需标量仿真层（冻结，见已知限制） |
| zsh | ❌ | `assignment to invalid subscript range`；解释器路线不做 |

> **"天然原生兼容 bash / mksh" 这句话，只对纯脚本线成立。**
> VMP bash 线额外要求宿主能带自控 bash 二进制；ELF 线不依赖 C 层但**放弃 VMP 令牌化**。
> 三条线的能力/代价对照见 [`docs/SHELL_TARGETS.md`](docs/SHELL_TARGETS.md)。

### 自己编译各 shell 的 C 层补丁

V7-ISA 的 C 层补丁（bash 生产链已通；**mksh 线四层插桩 + 三件套 + L6 全部实装并验证，
已可通过 `v7/v7_build.sh` 一条命令打包** —— 完整状态与构建流程见
[`docs/BUILD_MKSH.md`](docs/BUILD_MKSH.md)），
逐条注入步骤、两条线的三处有意差异、三个 Android libc 线的取舍、以及踩过的坑全部整理在
**[`docs/BUILD_PER_SHELL.md`](docs/BUILD_PER_SHELL.md)** §十。

### 想再加一个解释器？先看两条路线的对比

「把 ISA/v7core C 层移植进新 shell 树」与「把插桩做成通用补丁」是**两个不同的工作方向**，
投入产出比不同。两条路线各自要解决什么问题、哪个该先做、止损点在哪，
见 **[`docs/C_LAYER_ROUTE_COMPARE.md`](docs/C_LAYER_ROUTE_COMPARE.md)**（结论：先做通用补丁，
拿 mksh 当第二个实例逼出抽象，止损点设在 mksh 的定长 `ident` 缓冲区）。

### 「一次写、到处插」能做到什么程度

不同 shell 的同类逻辑**在结构上高度同构**，可以靠"语义锚点 + 自动发现"自动适配，
不必逐个手写。可行性、三条自动识别规则、以及自动化**做不到**的边界，
见 **[`docs/GENERIC_HOOK_DESIGN.md`](docs/GENERIC_HOOK_DESIGN.md)**。

> 规则 1（保留字表自动发现）**已实现并验证** —— 已抽出为子仓库
> `../sh-hook/`（「sh 通用 hook 点 —— 便捷快速移植不同 sh 解释器的特性」），
> 其 `discover_tables.py` 能自动找出
> bash 的 `word_token_alist`、mksh 的 `tokentab`、dash 的 `parsekwd`。
>
> **定位说明（2026-09）**：主产品路线是**脚本侧收敛**（审计 + 降级到 bash 子集 +
> 内嵌解释器分发），解释器插桩线降级为 P3 优化——只在"产物必须用目标系统 shell
> 执行以省体积"的场景才有必要。探索/重启该线时，sh-hook 的 G1-G3（表发现 →
> 引用图谱 → 主路径探针）就是现成的地基。

---

## License

- **本项目自有代码**（V6 混淆器、V7 ELF 封装、ISA 工具链、文档）：[MIT](LICENSE)。
- **V7-ISA 涉及的 bash 部分**（`v7/bash_poc/` 的补丁，以及产物内嵌的魔改 bash）：bash 是 **GPLv3+** 软件，**魔改并分发其二进制时，必须向接收方提供对应完整源码**（含补丁与构建脚本）。本仓库已包含全部所需内容——随产物附上仓库链接或源码包即满足义务；下游再分发同样承担此义务。
- **V7-ISA 涉及的 mksh 部分**（`v7/mksh_poc/` 的补丁，以及产物内嵌的魔改 mksh）：mksh 采用 **MirOS 许可证**（源码头部原文：*"Provided that these terms and disclaimer and all copyright notices are retained or reproduced in an accompanying document, permission is granted to deal in this work without restriction…"*）。**再分发门槛比 GPL 低**：保留版权与许可声明即可，不要求提供完整源码。补丁与构建脚本同样随本仓库提供。
- **如实披露建议**：产物内嵌的是魔改 bash——这解释了产物体积，也是逆向者的已知起点（解释器可被识别，攻击面见 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)）。向产物接收方说明这一点，与项目的"诚实边界"原则一致。

**免责声明**：本项目是**防御性安全研究**。使用者应只在**自己拥有或被授权**的代码上使用。作者不对任何滥用行为负责。
