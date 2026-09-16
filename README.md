# ShellVMP

> **English**: [README.en.md](README.en.md) — the English overview. Full documentation is in Chinese (see [文档索引](#文档索引)).

**把 shell 脚本变成自保护产物。** 两层独立可用的保护：

- **V6** — 纯 shell 实现的脚本混淆器：分块加密 + 执行状态绑链 + 跳跃密钥链 + 批级自修改。零外部依赖（`aes` 模式需 openssl，`builtin` 模式纯 shell/awk）。
- **V7** — ELF 封装层：反调试 + 反内存读取 + 流式解密直喂解释器，磁盘上永不存在完整明文。
- **V7-ISA** — 解释器魔改层（PoC）：把命令名/关键字/变量名令牌化，让产物在磁盘上只是一串随机令牌。

> **平台**：**不绑定平台**。产物是 ELF 或纯脚本，**任何能跑 Linux / ELF 的环境都能运行**
> ——Android、桌面 Linux、服务器、容器、嵌入式皆可。
> **脚本来源**：bash 原生支持；dash / POSIX / zsh 等经**转译收敛**进 bash 线；
> mksh 有独立的第二打包路线。**不需要魔改所有解释器**——详见
> [`docs/SHELL_TARGETS.md`](docs/SHELL_TARGETS.md) 第零节。

> 目标不是"藏得更深"，而是**改变攻击面**：让磁盘上不存在明文，让运行期的明文窗口尽可能短且有界，让关键逻辑变成攻击者无法静态分析的虚拟指令。

---

## 目录

- [它是怎么工作的](#它是怎么工作的)
- [三分钟上手](#三分钟上手)
- [选哪条线？用哪个 shell 打包？](#选哪条线用哪个-shell-打包)
- [为什么 shell 是最难保护的语言](#为什么-shell-是最难保护的语言)
- [诚实的安全边界](#诚实的安全边界)
- [项目结构](#项目结构)
- [使用指南（构建 / 开关 / 注意事项）](docs/USAGE.md)
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
git clone https://github.com/haothtrteen/ShellVMP.git
cd ShellVMP

# 混淆一个脚本
ANDROID_GATE=0 bash v6/shell_script_obfuscator_v6.sh examples/demo_app.sh demo.protected.sh

# 跑它
bash demo.protected.sh
```

`ANDROID_GATE=0` 用于在非安卓环境测试；默认开启安卓环境门控（非安卓直接静默拒绝）。

> ⚠️ **门控是"可选的反分析开关"，不是"平台限制"。** 它的作用是让产物在
> **不该运行的环境**里静默拒绝（提高沙箱分析成本），**不代表项目只能在 Android 用**。
> 在桌面 / 服务器 / 容器里跑，加 `ANDROID_GATE=0` 即可——这是**所有平台通用**的做法。

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
| 要最强保护、能接受自带几 MB 解释器 | **bash 线**（**主力线**，吃下所有来源的脚本） |
| 想省掉内嵌 bash 的体积（约 150 万行 vs mksh 约 3 万行）/ 目标是 Android 真机 | **mksh 线**（**第二打包路线**） |
| 不确定 | 先用纯脚本线跑通，再上 bash 线 |

> **平台说明**：项目**不绑定平台**。产物是 ELF 或纯脚本，**任何能跑 Linux / ELF 的环境都能运行**
> ——Android、桌面 Linux、服务器、容器、嵌入式均可。Android 只是**验证成本最低的靶场**
> （设备易得、环境熵检测好写），不是能力边界。

**最小的开始 —— 不需要任何口令**（连解释器都不用预先准备）：

```bash
# bash 线
V7_MODE=bash V7_BASH_BIN=/path/to/改版bash ANDROID_GATE=0 \
  bash v7/v7_build.sh your_script.sh app.bash
V7_SELF=1 ./app.bash /dev/null

# mksh 线（从源码现场构建改版解释器）
V7_MODE=mksh V7_MKSH_SRC=./mksh-src ANDROID_GATE=0 \
  bash v7/v7_build.sh your_script.sh app.mksh
V7_SELF=1 ./app.mksh /dev/null
```

**要设口令**就加 `V7_OUTER_PASS='至少8位'`（不给 = **离线分发模式**，运行免口令）。

> **两条最容易踩的坑**（详见 [`docs/USAGE.md`](docs/USAGE.md) §四）：
>
> 1. **运行必须带 `V7_SELF=1` + 一个 argv 文件参数**（惯例 `/dev/null`），缺任一个都
>    **静默零输出** —— 症状与"解密失败"完全同形，极易误诊。
>    产物是 ELF，要 `./app.bash` **直接执行**，不要写成 `bash app.bash`。
> 2. **慢机器 + 外层口令默认参数会 `rc=113`**（反调试时间窗被 KDF 耗时误伤）。
>    桌面调试加 `V7_SCRYPT_N=16384` 即解；或直接走离线分发模式。
>
> **完整开关表、实测矩阵、按场景配方** → **[`docs/USAGE.md`](docs/USAGE.md)**

### 自己构建各 shell 的 C 层补丁

| 线 | 构建指南 |
|---|---|
| **★ 使用指南（先读这个）** | **[`docs/USAGE.md`](docs/USAGE.md)** —— 敲哪条命令 / 能开哪些功能 / 注意什么 |
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
├── sh-hook/                            # ★ 子项目：sh 通用 hook 点（subtree 并入，见其 README）
│   ├── discover_tables.py              # G1 保留字表自动发现
│   ├── discover_callers.py             # G2 查表函数/调用点引用图谱
│   ├── probe_path.py                   # G3 主路径探针裁决
│   ├── hook_engine.py                  # 表驱动插桩引擎（定位→回滚→幂等→插入）
│   └── docs/DESIGN.md                  # 设计浓缩版
├── examples/                           # 示例脚本
├── tests/                              # 回归测试
└── docs/                               # 文档
    ├── USAGE.md                        # ★ 使用指南（构建/开关/注意事项）
    ├── JOURNEY.md                      # ★ v1→v6 心路历程
    ├── ARCHITECTURE.md                 # 架构与设计原理
    ├── THREAT_MODEL.md                 # 威胁模型与能力承诺
    ├── HISTORY/                        # 历版源码与实验归档（史料，不参与构建）
    └── ...
```

## 文档索引

| 想了解 | 读 |
|---|---|
| **★ 怎么用：构建、开关、注意事项** | **[`docs/USAGE.md`](docs/USAGE.md)** |
| **这套东西是怎么一路试错做出来的** | **[`docs/JOURNEY.md`](docs/JOURNEY.md)** |
| 两层架构怎么协作、密码学怎么设计 | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| 到底防得住谁、防不住谁 | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| V6 的分块/绑链/跳跃密钥链算法 | [`docs/V6_DESIGN.md`](docs/V6_DESIGN.md) |
| V7 的流式解密与反调试 | [`docs/V7_DESIGN.md`](docs/V7_DESIGN.md) |
| 令牌化（V7-ISA）四层表 | [`docs/TOKENIZATION.md`](docs/TOKENIZATION.md) |
| 构建、测试、排障（bash 线） | [`docs/BUILD.md`](docs/BUILD.md) |
| **构建 mksh 线（魔改解释器）** | **[`docs/BUILD_MKSH.md`](docs/BUILD_MKSH.md)** |
| C 层补丁怎么挂到不同解释器 | [`docs/BUILD_PER_SHELL.md`](docs/BUILD_PER_SHELL.md) |
| **sh 通用 hook 点（子项目：表发现 → 引用图谱 → 主路径探针）** | **[`sh-hook/README.md`](sh-hook/README.md)** |
| **踩过的坑（按症状索引）** | **[`docs/PITFALLS.md`](docs/PITFALLS.md)** |
| VMP 对接与收益边界 | [`docs/VMP_NOTES.md`](docs/VMP_NOTES.md) |
| 哪些开源、哪些保留、为什么 | [`docs/OPEN_SOURCE_SCOPE.md`](docs/OPEN_SOURCE_SCOPE.md) |
| **历版源码与实验归档（史料）** | **[`docs/HISTORY/`](docs/HISTORY/README.md)** |
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
  - **为什么做 mksh 线**：它是**第二条打包路线**（内嵌 mksh 体积远小于 bash），同时验证"同一套 ISA 机制能否移植到别的解释器"。Android 4.0+ 的 `/system/bin/sh` 就是 mksh，所以它也是 Android 场景下的最优选择。
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
| ③ **要不要 C 层插桩**（V7-ISA 魔改解释器） | 补丁已随本仓库分发、构建脚本齐全，**对使用者透明**。bash-5.2 生产链 ✅（[`BUILD.md`](docs/BUILD.md)）；**mksh-R59c 四层插桩 + 三件套 + L6 全通，已可打包**（[`BUILD_MKSH.md`](docs/BUILD_MKSH.md)）；其余冻结（自动发现工具链见子项目 [`sh-hook/`](sh-hook/README.md)） |

> **关键：为什么只魔改 bash 和 mksh，就够了？**
>
> 早期曾以为"不把每种解释器都魔改完，项目就应用不起来"。**这个前提不成立。**
>
> 正确路径是：**先把各种来源的脚本转成 bash，再交给 bash 线打包**。
> 社区已有 dash / POSIX / busybox → bash 的转译工具，配合我们的收敛审计
> （[`docs/DASH_SYNTAX_AUDIT.md`](docs/DASH_SYNTAX_AUDIT.md)），
> **任何来源的脚本都收敛到同一条 bash 线**——业务逻辑不变，改的只是写法。
>
> 魔改解释器是整个链路里**成本最高**的一环。所以策略是：
> **bash 当主力吃下所有来源，mksh 做第二打包路线**，其余一律不新增线。
> 详见 [`docs/SHELL_TARGETS.md`](docs/SHELL_TARGETS.md) 第零节与第五节。

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

> 规则 1（保留字表自动发现）**已实现并验证** —— 见子项目
> **[`sh-hook/`](sh-hook/README.md)**（「sh 通用 hook 点 —— 便捷快速移植不同 sh
> 解释器的特性」），其 `discover_tables.py` 能自动找出
> bash 的 `word_token_alist`、mksh 的 `tokentab`、dash 的 `parsekwd`。
>
> **定位说明（2026-09）**：主产品路线是**脚本侧收敛**（审计 + 降级到 bash 子集 +
> 内嵌解释器分发），解释器插桩线降级为 P3 优化——只在"产物必须用目标系统 shell
> 执行以省体积"的场景才有必要。探索/重启该线时，sh-hook 的 G1-G3（表发现 →
> 引用图谱 → 主路径探针）就是现成的地基。

---

## License

**双重许可（dual licensing）——二选一，不必同时遵守两套。**

| 路径 | 许可证 | 适用 | 代价 |
|---|---|---|---|
| **开源** | **[AGPLv3](LICENSE)** | 个人 / 内部使用 / 开源项目 / 学术 | **免费**，但分发或提供网络服务时须公开修改版全部源码 |
| **商业** | **[LICENSE.COMMERCIAL](LICENSE.COMMERCIAL)** | 想**闭源商用**、想运营 SaaS 而不开源 | 需向版权人取得书面授权 |

> **一句话**：只要你愿意**把修改版开源**，商用也是免费的；**不想开源又想商用**，才需要买授权。

**版权人**：皓thirteen（GitHub: [@haothtrteen](https://github.com/haothtrteen)）· `2557976190@qq.com`
商业授权洽谈请走邮件，标题以 `[ShellVMP 商业授权]` 开头。详见 **[`LICENSE.COMMERCIAL`](LICENSE.COMMERCIAL)**。

### 无论走哪条路，你都必须保留署名

**这是硬性要求**：任何形式的分发（开源或闭源、改过或没改过、源码或二进制），
代码与产物中都必须保留**原始版权声明与许可证声明**。详见 `LICENSE` 第 4、5 条。

### 第三方组件不受本许可约束（上游强制继承，版权人无权更改）

| 目录 | 许可证 | 义务 |
|---|---|---|
| `v7/bash_poc/` | **GPLv3+** | 派生自 GNU bash。分发内嵌魔改 bash 的产物 → **必须向接收方提供对应完整源码**（含补丁与构建脚本）。**商业许可也无法豁免这一条**——那是 bash 的权利，不是我们的。 |
| `v7/mksh_poc/` | **MirOS** | 派生自 mksh。义务较轻：保留版权与许可声明即可，**不要求提供完整源码**。 |
| `sh-hook/` | AGPLv3 | 本项目子项目，与本仓库一致。 |

> **想完全闭源分发产物？** 走 **mksh 线**（MirOS，无需开源）而非 bash 线。
> 逐项算账见 **[`docs/OPEN_SOURCE_SCOPE.md`](docs/OPEN_SOURCE_SCOPE.md)**。

- **如实披露建议**：产物内嵌的是魔改 bash——这解释了产物体积，也是逆向者的已知起点（解释器可被识别，攻击面见 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)）。向产物接收方说明这一点，与项目的"诚实边界"原则一致。

**免责声明**：本项目是**防御性安全研究**。使用者应只在**自己拥有或被授权**的代码上使用。作者不对任何滥用行为负责。
